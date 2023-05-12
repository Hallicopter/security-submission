import hashlib
import requests
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "secret_key"

DATABASE = "database.db"


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    with app.open_resource("schema.sql", mode="r") as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.route("/")
def index():
    if "username" in session:
        return render_template("index.html", username=session["username"])
    else:
        return redirect(url_for("login"))


def is_password_common(password):
    """
    Checks if a password is common based on the Have I Been Pwned API.
    Returns True if the password is common, False otherwise.
    """
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    hash_prefix = sha1_password[:5]
    hash_suffixes = requests.get(f"https://api.pwnedpasswords.com/range/{hash_prefix}").text.splitlines()
    for suffix in hash_suffixes:
        if sha1_password[5:] in suffix:
            return True
    return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        error = None

        if not username:
            error = "Username is required"
        elif not password:
            error = "Password is required"
        elif password != confirm_password:
            error = "Passwords do not match"
        elif is_password_common(password):
            error = "This password has been compromised in a data breach. Please choose a different password."
        elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone() is not None:
            error = "Username already exists"

        if error is None:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, generate_password_hash(password)))
            db.commit()
            db.close()
            return redirect(url_for("login"))

        db.close()
        return render_template("register.html", error=error)
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        username = request.form["username"]
        password = request.form["password"]
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        error = None

        if user is None:
            error = "Invalid username or password"
        elif not check_password_hash(user["password"], password):
            error = "Invalid username or password"
        elif is_password_common(password):
            error = "This password has been compromised in a data breach. Please choose a different password."

        if error is None:
            session["username"] = user["username"]
            return redirect(url_for("index"))

        return render_template("login.html", error=error)
    else:
        return render_template("login.html")


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         db = get_db()
#         username = request.form["username"]
#         password = request.form["password"]
#         user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
#         db.close()
#
#         if user is None:
#             error = "Invalid username or password"
#         elif not check_password_hash(user["password"], password):
#             error = "Invalid username or password"
#         else:
#             session["username"] = user["username"]
#             return redirect(url_for("index"))
#
#         return render_template("login.html", error=error)
#     else:
#         return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


# @app.route("/register", methods=["GET", "POST"])
# def register():
#     if request.method == "POST":
#         db = get_db()
#         username = request.form["username"]
#         password = request.form["password"]
#         confirm_password = request.form["confirm_password"]
#
#         error = None
#
#         if not username:
#             error = "Username is required"
#         elif not password:
#             error = "Password is required"
#         elif password != confirm_password:
#             error = "Passwords do not match"
#         elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone() is not None:
#             error = "Username already exists"
#
#         if error is None:
#             db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
#                        (username, generate_password_hash(password)))
#             db.commit()
#             db.close()
#             return redirect(url_for("login"))
#
#         db.close()
#         return render_template("register.html", error=error)
#     else:
#         return render_template("register.html")


if __name__ == '__main__':
    init_db()
    app.run()
