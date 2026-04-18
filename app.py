from flask import Flask, render_template, request, redirect, session, make_response, jsonify, url_for, flash, g
from pymongo import MongoClient, DESCENDING
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import config
import jwt
import datetime
import re
import random
import os
import hashlib
from functools import wraps
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import predictor
from openai import OpenAI

load_dotenv()

nvidia_client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=config.NVIDIA_API_KEY,
)

_ADVISOR_SYSTEM = (
    "You are an expert Google Play Store app analyst. "
    "Given an app's metrics and its ML-predicted success class, produce a concise structured improvement report. "
    "Be specific and data-driven. "
    "Respond with EXACTLY these three sections, each starting with the header on its own line:\n"
    "### Quick Wins\n"
    "### Strategic Improvements\n"
    "### Risk Factors\n"
    "Use 2-3 bullet points (starting with -) under each section. No extra prose outside these sections."
)


app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Secure cookies setup (though using JWT, keeping for best practice if session is used)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# MongoDB connection
client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]
users         = db.users
security_logs = db.security_logs
otp_logs      = db.otp_logs          # MFA: stores hashed OTPs
user_history  = db.user_history      # per-user activity history

users.create_index("email", unique=True)
otp_logs.create_index("expires_at", expireAfterSeconds=0)  # TTL — auto-deletes expired OTPs
user_history.create_index("user_id")


# ── MFA helpers ─────────────────────────────────────────────────────────────────

def send_otp_email(to_email: str, otp: str) -> bool:
    """Send a 6-digit OTP via SendGrid. Returns True on success."""
    api_key    = os.environ.get("SENDGRID_API_KEY")
    from_email = os.environ.get("EMAIL_FROM")
    if not api_key or not from_email:
        app.logger.error("SENDGRID_API_KEY / EMAIL_FROM not set in environment.")
        return False
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px;
                border-radius:8px;border:1px solid #e2e8f0;background:#ffffff">
        <h2 style="color:#1e293b;margin-bottom:8px">App Success Analyzer</h2>
        <p style="color:#475569">Your one-time login code:</p>
        <div style="font-size:36px;font-weight:700;letter-spacing:8px;
                    color:#6366f1;padding:16px 0">{otp}</div>
        <p style="color:#64748b;font-size:13px">
            This code expires in <strong>2 minutes</strong>. Do not share it with anyone.
        </p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
        <p style="color:#94a3b8;font-size:12px">
            If you did not request this code, you can safely ignore this email.
        </p>
    </div>
    """
    try:
        sg  = SendGridAPIClient(api_key)
        msg = Mail(from_email=from_email, to_emails=to_email,
                   subject="Your App Success Analyzer Login OTP", html_content=html_body)
        resp = sg.send(msg)
        return resp.status_code in (200, 201, 202)
    except Exception as exc:
        app.logger.error("SendGrid error: %s", exc)
        return False


def generate_otp() -> str:
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode()).hexdigest()


def store_otp(email: str, otp: str) -> None:
    now    = datetime.datetime.utcnow()
    expiry = now + datetime.timedelta(minutes=2)
    otp_logs.delete_many({"email": email})
    otp_logs.insert_one({
        "email":      email,
        "otp_hash":   hash_otp(otp),
        "attempts":   0,
        "created_at": now,
        "expires_at": expiry,
    })

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("jwt_token")
        if not token:
            return redirect("/login")
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            g.current_user = {
                "user_id": data["user_id"],
                "email":   data["email"],
                "name":    data.get("name", data["email"].split("@")[0]),
            }
        except jwt.ExpiredSignatureError:
            return redirect("/login")
        except jwt.InvalidTokenError:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_current_user():
    return {"current_user": getattr(g, "current_user", None)}


def log_activity(tool: str, tool_label: str, summary: str = "") -> None:
    """Record a user tool usage in user_history collection."""
    user = getattr(g, "current_user", None)
    if not user:
        return
    user_history.insert_one({
        "user_id":    ObjectId(user["user_id"]),
        "tool":       tool,
        "tool_label": tool_label,
        "summary":    summary[:200],
        "timestamp":  datetime.datetime.utcnow(),
    })


@app.route("/")
@token_required
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # 1. Validate empty inputs
        if not name or not email or not password:
            return render_template("register.html", error="All fields are required.")
            
        # 2. Validate email format
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, email):
            return render_template("register.html", error="Please enter a valid email address.")
            
        # 3. Validate password strength
        # Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$"
        if not re.match(password_pattern, password):
            return render_template("register.html", error="Password does not meet the complexity requirements.")

        # Check if user already exists
        if users.find_one({"email": email}):
            return render_template("register.html", error="An account with this email already exists.")

        hashed_password = generate_password_hash(password)
        now = datetime.datetime.utcnow()

        # Insert secure user entry
        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": "user",
            "created_at": now,
            "last_login": None
        })

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("login.html", error="Email and password are required.")

        ip_addr = request.remote_addr

        # Brute-force protection: check failed attempts in last 15 mins
        fifteen_mins_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        recent_failures = security_logs.count_documents({
            "ip":        ip_addr,
            "timestamp": {"$gt": fifteen_mins_ago},
            "event":     "login_fail",
        })

        if recent_failures >= 5:
            return render_template("login.html", error="Too many failed login attempts. Please try again later.")

        user = users.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            # Credentials correct — start MFA flow
            otp = generate_otp()
            store_otp(email, otp)

            sent = send_otp_email(email, otp)
            if not sent:
                return render_template("login.html", error="Could not send verification email. Please try again.")

            # Store email in server-side session for the OTP step
            session["mfa_email"] = email
            security_logs.insert_one({
                "ip": ip_addr, "email": email,
                "timestamp": datetime.datetime.utcnow(), "event": "otp_sent",
            })
            return redirect(url_for("verify_otp"))
        else:
            # Log failed login attempt
            security_logs.insert_one({
                "ip": ip_addr, "email": email,
                "timestamp": datetime.datetime.utcnow(), "event": "login_fail",
            })
            return render_template("login.html", error="Invalid email or password. Please try again.")

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("mfa_email")
    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":
        entered = "".join([
            request.form.get(f"otp{i}", "").strip() for i in range(1, 7)
        ])

        record = otp_logs.find_one({"email": email})

        # No OTP on record (expired or never issued)
        if not record:
            return render_template("otp.html", email=email, error="OTP expired. Please request a new one.")

        # Too many wrong attempts
        if record.get("attempts", 0) >= 3:
            otp_logs.delete_many({"email": email})
            session.pop("mfa_email", None)
            return render_template("login.html", error="Too many incorrect OTP attempts. Please log in again.")

        if record["otp_hash"] == hash_otp(entered):
            # Correct OTP — consume it and issue JWT
            otp_logs.delete_many({"email": email})
            session.pop("mfa_email", None)

            user = users.find_one({"email": email})
            now  = datetime.datetime.utcnow()
            users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now}})
            security_logs.insert_one({
                "ip": request.remote_addr, "email": email,
                "timestamp": now, "event": "login_success",
            })

            payload = {
                "user_id": str(user["_id"]),
                "email":   user["email"],
                "name":    user.get("name", user["email"].split("@")[0]),
                "exp":     now + datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, app.secret_key, algorithm="HS256")
            resp  = make_response(redirect("/"))
            resp.set_cookie("jwt_token", token, httponly=True, secure=True, samesite="Lax")
            return resp
        else:
            # Increment attempt counter
            otp_logs.update_one({"email": email}, {"$inc": {"attempts": 1}})
            remaining = 3 - (record.get("attempts", 0) + 1)
            return render_template("otp.html", email=email,
                                   error=f"Incorrect code. {remaining} attempt(s) remaining.")

    return render_template("otp.html", email=email)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("mfa_email")
    if not email:
        return redirect(url_for("login"))

    otp  = generate_otp()
    store_otp(email, otp)
    sent = send_otp_email(email, otp)

    if sent:
        return render_template("otp.html", email=email, success="A new code has been sent to your email.")
    return render_template("otp.html", email=email, error="Failed to resend. Please try again.")


@app.route("/dashboard")
@token_required
def dashboard():
    log_activity("dashboard", "Dashboard")
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    # Clear the JWT token securely
    resp.set_cookie("jwt_token", "", expires=0) 
    session.clear() # Clear session just in case
    return resp



@app.route("/blueprint")
@token_required
def blueprint():
    return render_template("blueprint.html")


@app.route("/api/blueprint", methods=["POST"])
@token_required
def api_blueprint():
    import json as _json
    try:
        data = request.get_json(force=True)
        idea = (data.get("idea") or "").strip()
        if len(idea) < 10:
            return jsonify({"error": "Please describe your app idea in more detail."}), 400

        categories_list    = sorted(predictor.category_map.keys())
        content_ratings_list = sorted(predictor.content_rating_map.keys())

        # ── Step 1: extract structured profile from natural language ──
        extract_prompt = (
            f'App idea: "{idea}"\n\n'
            f'Return ONLY a valid JSON object — no explanation, no markdown fences:\n'
            f'{{\n'
            f'  "app_name": "short catchy name",\n'
            f'  "tagline": "one sentence value proposition",\n'
            f'  "category": "one of: {", ".join(categories_list)}",\n'
            f'  "content_rating": "one of: {", ".join(content_ratings_list)}",\n'
            f'  "is_free": true or false,\n'
            f'  "estimated_installs": integer — estimate for a successfully launched, growing app; choose from (100000,500000,1000000,5000000,10000000) — do NOT go below 100000,\n'
            f'  "estimated_size_mb": number 1-500,\n'
            f'  "estimated_price": number (0 if free),\n'
            f'  "estimated_reviews": integer,\n'
            f'  "days_since_update": integer 1-365,\n'
            f'  "min_android_ver": number 4.0-10.0,\n'
            f'  "market_segment": "2-3 word segment",\n'
            f'  "target_audience": "brief audience description"\n'
            f'}}'
        )

        ext_resp = nvidia_client.chat.completions.create(
            model="meta/llama-3.1-70b-instruct",
            messages=[
                {"role": "system", "content": "You are a mobile app analyst. Extract structured data from app descriptions. Return only valid JSON."},
                {"role": "user",   "content": extract_prompt},
            ],
            temperature=0.2,
            max_tokens=450,
        )

        raw = ext_resp.choices[0].message.content.strip()
        # strip markdown fences if model wraps in ```json ... ```
        if "```" in raw:
            for part in raw.split("```"):
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    raw = part
                    break
        extracted = _json.loads(raw)

        # Sanitise against known maps
        if extracted.get("category") not in predictor.category_map:
            extracted["category"] = categories_list[0]
        if extracted.get("content_rating") not in predictor.content_rating_map:
            extracted["content_rating"] = content_ratings_list[0]

        # ── Step 2: run all 3 ML models ──
        form_data = {
            "category":          extracted["category"],
            "content_rating":    extracted["content_rating"],
            "is_free":           "1" if extracted.get("is_free", True) else "0",
            "reviews":           str(max(0,      int(extracted.get("estimated_reviews",  50000)))),
            "installs":          str(max(100000, int(extracted.get("estimated_installs", 500000)))),
            "size_mb":           str(max(1.0,  float(extracted.get("estimated_size_mb", 25)))),
            "price":             str(float(extracted.get("estimated_price", 0))),
            "days_since_update": str(max(1,   int(extracted.get("days_since_update",  90)))),
            "min_android_ver":   f"{float(extracted.get('min_android_ver', 5.0)):.1f}",
        }
        predictions = predictor.predict_all(form_data)

        # ── Step 3: market analysis ──
        main = predictions["xgb"]
        analysis_prompt = (
            f'App: {extracted.get("app_name","Unnamed")}\n'
            f'Concept: {idea}\n'
            f'Category: {extracted["category"]} | Audience: {extracted.get("target_audience","")}\n'
            f'ML Prediction: {main["label"]} ({main["confidence"]:.1f}% confidence)\n'
            f'Probabilities — Good {main["probabilities"]["Good"]*100:.1f}%, '
            f'Average {main["probabilities"]["Average"]*100:.1f}%, '
            f'Poor {main["probabilities"]["Poor"]*100:.1f}%\n\n'
            f'Write a structured analysis with EXACTLY these five sections. Each section: 2-3 bullet points starting with -.\n'
            f'For Development Timeline: 5-6 phases totalling 16–32 weeks. Each bullet format: "Phase N — Name: X–Y weeks — brief description". Keep total timeline realistic for a small indie team.\n'
            f'For Cost Estimate: assume a small indie team or freelancers in India/Southeast Asia with a very tight budget. Use LOW realistic ranges. Each bullet format: "Category: $X – $Y". Include a final bullet "Total estimate: $X – $Y". Typical total MUST stay between $500–$4,000 USD. Do not exceed $4,000 total under any circumstances.\n\n'
            f'### Market Opportunity\n### Competitive Landscape\n### Launch Strategy\n### Development Timeline\n### Cost Estimate'
        )

        ana_resp = nvidia_client.chat.completions.create(
            model="meta/llama-3.1-70b-instruct",
            messages=[
                {"role": "system", "content": "You are a senior mobile app market strategist and project estimator. Be specific, data-driven, and actionable."},
                {"role": "user",   "content": analysis_prompt},
            ],
            temperature=0.65,
            max_tokens=1100,
        )

        log_activity("blueprint", "App Genesis", idea[:150])
        return jsonify({
            "extracted":   extracted,
            "predictions": predictions,
            "analysis":    ana_resp.choices[0].message.content,
        })

    except _json.JSONDecodeError:
        return jsonify({"error": "Could not parse the app profile — try describing your idea with more specific details."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/predict", methods=["POST"])
@token_required
def api_predict():
    try:
        data = request.get_json(force=True)
        return jsonify(predictor.predict(data))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/predict-all", methods=["POST"])
@token_required
def api_predict_all():
    try:
        data = request.get_json(force=True)
        return jsonify(predictor.predict_all(data))
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/arena")
@token_required
def arena():
    log_activity("arena", "Model Arena")
    categories      = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())
    return render_template(
        "arena.html",
        categories=categories,
        content_ratings=content_ratings,
        model_meta=predictor.MODEL_META,
    )


@app.route("/advisor", methods=["GET", "POST"])
@token_required
def advisor():
    categories      = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())

    if request.method == "POST":
        form_data = {
            "category":          request.form.get("category", ""),
            "reviews":           request.form.get("reviews", 0),
            "installs":          request.form.get("installs", 0),
            "size_mb":           request.form.get("size_mb", 0.0),
            "is_free":           request.form.get("is_free", 1),
            "price":             request.form.get("price", "") or "0",
            "content_rating":    request.form.get("content_rating", ""),
            "days_since_update": request.form.get("days_since_update", 0),
            "min_android_ver":   request.form.get("min_android_ver", 1.0),
        }
        prediction = predictor.predict(form_data)
        if "error" in prediction:
            return render_template("advisor.html", categories=categories, content_ratings=content_ratings,
                                   prediction=None, ai_report=None, form_data=form_data,
                                   error=prediction["error"])

        top_features = predictor.get_feature_importances()[:3]

        user_prompt = (
            f"App Metrics:\n"
            f"- Category: {form_data['category']}\n"
            f"- Installs: {form_data['installs']}\n"
            f"- Reviews: {form_data['reviews']}\n"
            f"- Size (MB): {form_data['size_mb']}\n"
            f"- Free: {'Yes' if str(form_data['is_free']) == '1' else 'No'}\n"
            f"- Price (USD): {form_data['price']}\n"
            f"- Content Rating: {form_data['content_rating']}\n"
            f"- Days Since Last Update: {form_data['days_since_update']}\n"
            f"- Min Android Version: {form_data['min_android_ver']}\n\n"
            f"ML Prediction: {prediction['label']} (confidence {prediction['confidence']:.1f}%)\n"
            f"Probabilities — Poor: {prediction['probabilities']['Poor']*100:.1f}%, "
            f"Average: {prediction['probabilities']['Average']*100:.1f}%, "
            f"Good: {prediction['probabilities']['Good']*100:.1f}%\n\n"
            f"Top 3 predictive features (by importance):\n"
            + "\n".join(f"- {f['label']}: {f['importance_pct']:.1f}%" for f in top_features)
            + "\n\nGenerate the improvement report."
        )

        try:
            completion = nvidia_client.chat.completions.create(
                model="meta/llama-3.1-70b-instruct",
                messages=[
                    {"role": "system", "content": _ADVISOR_SYSTEM},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.6,
                max_tokens=800,
            )
            ai_report = completion.choices[0].message.content
        except Exception as e:
            return render_template("advisor.html", categories=categories, content_ratings=content_ratings,
                                   prediction=None, ai_report=None, form_data=form_data,
                                   error=f"AI service error: {str(e)}")

        log_activity(
            "advisor", "AI Advisor",
            f"Category: {form_data['category']} | Prediction: {prediction['label']} ({prediction['confidence']:.1f}%)"
        )
        return render_template(
            "advisor.html",
            categories=categories,
            content_ratings=content_ratings,
            prediction=prediction,
            ai_report=ai_report,
            form_data=form_data,
        )

    return render_template(
        "advisor.html",
        categories=categories,
        content_ratings=content_ratings,
        prediction=None,
        ai_report=None,
        form_data={},
    )


@app.route("/model-report")
@token_required
def model_report():
    log_activity("model_report", "Model Report")
    all_fi         = predictor.get_all_feature_importances()
    category_count = len(predictor.category_map)
    genre_count    = len(predictor.primary_genre_map)
    rating_count   = len(predictor.content_rating_map)
    return render_template(
        "model_report.html",
        feature_importances=all_fi["xgb"],
        all_fi=all_fi,
        model_meta=predictor.MODEL_META,
        category_count=category_count,
        genre_count=genre_count,
        rating_count=rating_count,
    )


@app.route("/history")
@token_required
def history():
    user_id = ObjectId(g.current_user["user_id"])
    records = list(
        user_history.find({"user_id": user_id})
        .sort("timestamp", DESCENDING)
        .limit(200)
    )
    for r in records:
        r["_id"]     = str(r["_id"])
        r["user_id"] = str(r["user_id"])
    return render_template("history.html", records=records)


if __name__ == "__main__":
    app.run(debug=True)