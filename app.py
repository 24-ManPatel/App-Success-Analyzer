# Main Flask application file — handles routes, auth, MFA, and security logic.
from flask import Flask, render_template, request, redirect, session, make_response, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import config
import jwt
import datetime
import re
import random
import os
import hashlib
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ── Secure session cookie settings ─────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ── MongoDB ─────────────────────────────────────────────────────────────────────
client    = MongoClient(config.MONGO_URI)
db        = client[config.DB_NAME]
users         = db.users
security_logs = db.security_logs
otp_logs      = db.otp_logs          # New collection for MFA OTPs

# Indexes
users.create_index("email", unique=True)
otp_logs.create_index("expires_at", expireAfterSeconds=0)  # TTL index auto-cleans expired OTPs


# ── Email helper ────────────────────────────────────────────────────────────────
def send_otp_email(to_email: str, otp: str) -> bool:
    """Send a 6-digit OTP via SendGrid — works with ANY email provider.

    Reads SENDGRID_API_KEY and EMAIL_FROM from environment variables.
    Returns True on success, False on any failure.
    """
    api_key:    str | None = os.environ.get("SENDGRID_API_KEY")
    from_email: str | None = os.environ.get("EMAIL_FROM")

    if not api_key or not from_email:
        app.logger.error(
            "SENDGRID_API_KEY / EMAIL_FROM environment variables are not set."
        )
        return False

    subject = "Your App Success Analyzer Login OTP"
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px
                ;border-radius:8px;border:1px solid #e2e8f0;background:#ffffff">
        <h2 style="color:#1e293b;margin-bottom:8px">App Success Analyzer</h2>
        <p style="color:#475569">Your one-time login code:</p>
        <div style="font-size:36px;font-weight:700;letter-spacing:8px
                    ;color:#6366f1;padding:16px 0">{otp}</div>
        <p style="color:#64748b;font-size:13px">
            This code expires in <strong>2 minutes</strong>.
            Do not share it with anyone.
        </p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
        <p style="color:#94a3b8;font-size:12px">
            If you did not request this code, you can safely ignore this email.
        </p>
    </div>
    """

    try:
        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            html_content=html_body,
        )
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        app.logger.info(
            "OTP email sent to %s — SendGrid status %s", to_email, response.status_code
        )
        return response.status_code in (200, 201, 202)
    except Exception as exc:
        app.logger.error("Failed to send OTP email via SendGrid: %s", exc)
        return False


# ── OTP helper ──────────────────────────────────────────────────────────────────
def generate_otp() -> str:
    """Return a cryptographically-random 6-digit OTP string."""
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def hash_otp(otp: str) -> str:
    """SHA-256 hash an OTP so we never store plaintext codes."""
    return hashlib.sha256(otp.encode()).hexdigest()


def store_otp(email: str, otp: str) -> None:
    """Replace any existing OTP for this email and store a fresh hashed one."""
    now    = datetime.datetime.utcnow()
    expiry = now + datetime.timedelta(minutes=2)

    otp_logs.delete_many({"email": email})          # Invalidate previous OTPs
    otp_logs.insert_one({
        "email":      email,
        "otp_hash":   hash_otp(otp),
        "attempts":   0,                            # Track brute-force attempts
        "created_at": now,
        "expires_at": expiry,                       # TTL index respects this field
    })


# ── JWT decorator ───────────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("jwt_token")
        if not token:
            return redirect("/login")
        try:
            jwt.decode(token, app.secret_key, algorithms=["HS256"])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ── Routes ──────────────────────────────────────────────────────────────────────

@app.route("/")
@token_required
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate inputs
        if not name or not email or not password:
            return render_template("register.html", error="All fields are required.")

        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, email):
            return render_template("register.html", error="Please enter a valid email address.")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$"
        if not re.match(password_pattern, password):
            return render_template("register.html", error="Password does not meet the complexity requirements.")

        if users.find_one({"email": email}):
            return render_template("register.html", error="An account with this email already exists.")

        now = datetime.datetime.utcnow()
        users.insert_one({
            "name":       name,
            "email":      email,
            "password":   generate_password_hash(password),
            "role":       "user",
            "created_at": now,
            "last_login": None,
        })
        return redirect("/login")

    return render_template("register.html")


# ── Step 1 of MFA: validate credentials, send OTP ──────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        ip_addr  = request.remote_addr

        if not email or not password:
            return render_template("login.html", error="Email and password are required.")

        # Brute-force guard on password attempts (IP-based, 15 min window)
        fifteen_mins_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        recent_failures  = security_logs.count_documents({
            "ip":        ip_addr,
            "event":     "login_failed",
            "timestamp": {"$gt": fifteen_mins_ago},
        })
        if recent_failures >= 5:
            return render_template("login.html", error="Too many failed attempts. Please try again later.")

        user = users.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            # ── Credentials OK → generate & send OTP ─────────────────────────
            otp = generate_otp()
            store_otp(email, otp)           # Hashed OTP saved to otp_logs

            email_sent = send_otp_email(email, otp)

            # Temporarily store email in server-side session for the OTP step.
            # We do NOT store the OTP itself in the session.
            session["mfa_email"]    = email
            session["mfa_verified"] = False

            if not email_sent:
                # Still redirect — user might see dev mode note
                app.logger.warning("OTP email delivery failed; proceeding to OTP page.")

            return redirect(url_for("verify_otp"))
        else:
            # Log the failed password attempt
            security_logs.insert_one({
                "ip":        ip_addr,
                "email":     email,
                "event":     "login_failed",
                "timestamp": datetime.datetime.utcnow(),
            })
            return render_template("login.html", error="Invalid email or password. Please try again.")

    return render_template("login.html")


# ── Step 2 of MFA: verify OTP, issue JWT ───────────────────────────────────────
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    # User must have passed credential check first
    email = session.get("mfa_email")
    if not email or session.get("mfa_verified"):
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        ip_addr     = request.remote_addr

        # Fetch the OTP record
        record = otp_logs.find_one({"email": email})

        # ── Guard: no record / expired ────────────────────────────────────────
        if not record:
            return render_template("otp.html", error="OTP expired or not found. Please log in again.", email=email)

        # ── Guard: too many OTP attempts (per-record) ─────────────────────────
        if record.get("attempts", 0) >= 3:
            otp_logs.delete_one({"email": email})           # Invalidate
            security_logs.insert_one({
                "ip":        ip_addr,
                "email":     email,
                "event":     "otp_lockout",
                "timestamp": datetime.datetime.utcnow(),
            })
            session.clear()
            return render_template("login.html", error="Too many incorrect OTP attempts. Please log in again.")

        # ── Guard: OTP expired (belt-and-suspenders check) ──────────────────
        if datetime.datetime.utcnow() > record["expires_at"]:
            otp_logs.delete_one({"email": email})
            return render_template("otp.html", error="Your OTP has expired. Please log in again.", email=email)

        # ── Verify hashed OTP ─────────────────────────────────────────────────
        if hash_otp(entered_otp) == record["otp_hash"]:
            # OTP correct → single-use: delete it immediately
            otp_logs.delete_one({"email": email})

            # Update last_login
            now  = datetime.datetime.utcnow()
            user = users.find_one({"email": email})
            users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now}})

            security_logs.insert_one({
                "ip":        ip_addr,
                "email":     email,
                "event":     "login_success",
                "timestamp": now,
            })

            # Issue JWT
            payload = {
                "user_id": str(user["_id"]),
                "email":   user["email"],
                "exp":     now + datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, app.secret_key, algorithm="HS256")

            session.clear()                         # Remove MFA session keys

            resp = make_response(redirect("/"))
            resp.set_cookie("jwt_token", token, httponly=True, secure=True, samesite="Lax")
            return resp

        else:
            # Wrong OTP → increment attempt counter
            otp_logs.update_one({"email": email}, {"$inc": {"attempts": 1}})
            attempts_left = 2 - record.get("attempts", 0)  # 3 max, already incremented

            security_logs.insert_one({
                "ip":        ip_addr,
                "email":     email,
                "event":     "otp_failed",
                "timestamp": datetime.datetime.utcnow(),
            })
            return render_template(
                "otp.html",
                error=f"Incorrect OTP. {max(attempts_left, 0)} attempt(s) remaining.",
                email=email,
            )

    return render_template("otp.html", email=email)


# ── Resend OTP ──────────────────────────────────────────────────────────────────
@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("mfa_email")
    if not email:
        return redirect(url_for("login"))

    otp = generate_otp()
    store_otp(email, otp)
    send_otp_email(email, otp)

    return render_template("otp.html", success="A new OTP has been sent to your email.", email=email)


# ── Dashboard ───────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@token_required
def dashboard():
    return render_template("dashboard.html")


# ── Logout ──────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/login"))
    resp.set_cookie("jwt_token", "", expires=0)
    return resp


if __name__ == "__main__":
    app.run(debug=True)