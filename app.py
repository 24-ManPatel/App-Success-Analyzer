# Main Flask application file - Define routes, views, and application logic here
# This file initializes the Flask app and handles all HTTP requests/responses
from flask import Flask, render_template, request, redirect, session, flash, make_response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import config
import jwt
import datetime
import re
from functools import wraps

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
users = db.users
security_logs = db.security_logs

# Ensure unique email index
users.create_index("email", unique=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("jwt_token")
        if not token:
            return redirect("/login")
        try:
            # Decode JWT
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            # Optionally attach user info to request here if needed
            # e.g., request.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return redirect("/login")
        except jwt.InvalidTokenError:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


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
            "ip": ip_addr,
            "timestamp": {"$gt": fifteen_mins_ago},
            "success": False
        })
        
        if recent_failures >= 5:
            return render_template("login.html", error="Too many failed login attempts. Please try again later.")

        user = users.find_one({"email": email})

        # Securely verify password
        if user and check_password_hash(user["password"], password):
            # Update last login
            now = datetime.datetime.utcnow()
            users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now}})
            
            # Log successful login
            security_logs.insert_one({"ip": ip_addr, "email": email, "timestamp": now, "success": True})
            
            # Generate JWT Token (valid for 1 hour)
            payload = {
                "user_id": str(user["_id"]),
                "email": user["email"],
                "exp": now + datetime.timedelta(hours=1)
            }
            token = jwt.encode(payload, app.secret_key, algorithm="HS256")
            
            # Create response and set HTTPOnly Cookie
            resp = make_response(redirect("/"))
            resp.set_cookie("jwt_token", token, httponly=True, secure=True, samesite="Lax")
            return resp
        else:
            # Log failed login
            security_logs.insert_one({"ip": ip_addr, "email": email, "timestamp": datetime.datetime.utcnow(), "success": False})
            # Safe generic error message (no information leakage)
            return render_template("login.html", error="Invalid email or password. Please try again.")

    return render_template("login.html")


@app.route("/dashboard")
@token_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    # Clear the JWT token securely
    resp.set_cookie("jwt_token", "", expires=0) 
    session.clear() # Clear session just in case
    return resp


if __name__ == "__main__":
    app.run(debug=True)