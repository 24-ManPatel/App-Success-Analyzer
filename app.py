# Main Flask application file - Define routes, views, and application logic here
# This file initializes the Flask app and handles all HTTP requests/responses
from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# MongoDB connection
client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]
users = db.users


@app.route("/")
def home():
    if "user" in session:
        return render_template("home.html")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Check if user already exists
        if users.find_one({"email": email}):
            return render_template("register.html", error="User with this email already exists. Please try logging in instead.")

        hashed_password = generate_password_hash(password)

        users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password
        })

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = users.find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            session["user"] = user["name"]
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid email or password. Please try again.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html")
    return redirect("/login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)