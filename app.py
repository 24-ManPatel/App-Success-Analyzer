# Main Flask application file - Define routes, views, and application logic here
# This file initializes the Flask app and handles all HTTP requests/responses
from flask import Flask, render_template, request, redirect, session, flash, make_response, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import config
import jwt
import datetime
import re
from functools import wraps
import predictor
from openai import OpenAI

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


@app.route("/predictor", methods=["GET", "POST"])
@token_required
def predictor_page():
    categories = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())
    primary_genres = sorted(predictor.primary_genre_map.keys())

    if request.method == "POST":
        form_data = {
            "category": request.form.get("category", ""),
            "reviews": request.form.get("reviews", 0),
            "installs": request.form.get("installs", 0),
            "size_mb": request.form.get("size_mb", 0.0),
            "is_free": request.form.get("is_free", 1),
            "price": request.form.get("price", 0.0),
            "content_rating": request.form.get("content_rating", ""),
            "primary_genre": request.form.get("primary_genre", ""),
            "days_since_update": request.form.get("days_since_update", 0),
            "min_android_ver": request.form.get("min_android_ver", 1.0),
        }
        result = predictor.predict(form_data)
        if "error" in result:
            flash(result["error"])
            return redirect("/predictor")
        return render_template(
            "predictor.html",
            categories=categories,
            content_ratings=content_ratings,
            primary_genres=primary_genres,
            result=result,
            form_data=form_data,
        )

    return render_template(
        "predictor.html",
        categories=categories,
        content_ratings=content_ratings,
        primary_genres=primary_genres,
        result=None,
        form_data={},
    )



@app.route("/compare")
@token_required
def compare():
    categories = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())
    primary_genres = sorted(predictor.primary_genre_map.keys())
    return render_template(
        "compare.html",
        categories=categories,
        content_ratings=content_ratings,
        primary_genres=primary_genres,
    )


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
    categories      = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())
    primary_genres  = sorted(predictor.primary_genre_map.keys())
    return render_template(
        "arena.html",
        categories=categories,
        content_ratings=content_ratings,
        primary_genres=primary_genres,
        model_meta=predictor.MODEL_META,
    )


@app.route("/advisor", methods=["GET", "POST"])
@token_required
def advisor():
    categories      = sorted(predictor.category_map.keys())
    content_ratings = sorted(predictor.content_rating_map.keys())
    primary_genres  = sorted(predictor.primary_genre_map.keys())

    if request.method == "POST":
        form_data = {
            "category":          request.form.get("category", ""),
            "reviews":           request.form.get("reviews", 0),
            "installs":          request.form.get("installs", 0),
            "size_mb":           request.form.get("size_mb", 0.0),
            "is_free":           request.form.get("is_free", 1),
            "price":             request.form.get("price", "") or "0",
            "content_rating":    request.form.get("content_rating", ""),
            "primary_genre":     request.form.get("primary_genre", ""),
            "days_since_update": request.form.get("days_since_update", 0),
            "min_android_ver":   request.form.get("min_android_ver", 1.0),
        }
        prediction = predictor.predict(form_data)
        if "error" in prediction:
            flash(prediction["error"])
            return redirect("/advisor")

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
            f"- Primary Genre: {form_data['primary_genre']}\n"
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
            flash(f"AI service error: {str(e)}")
            return redirect("/advisor")

        return render_template(
            "advisor.html",
            categories=categories,
            content_ratings=content_ratings,
            primary_genres=primary_genres,
            prediction=prediction,
            ai_report=ai_report,
            form_data=form_data,
        )

    return render_template(
        "advisor.html",
        categories=categories,
        content_ratings=content_ratings,
        primary_genres=primary_genres,
        prediction=None,
        ai_report=None,
        form_data={},
    )


@app.route("/model-report")
@token_required
def model_report():
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


if __name__ == "__main__":
    app.run(debug=True)