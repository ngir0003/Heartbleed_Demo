import os
import secrets
from flask import Flask, request, redirect, url_for, render_template, make_response

app = Flask(__name__)

ACCOUNTS = {
    "alice": {"password": "password123", "balance": "$14,320.50", "account": "ACC-0042"},
    "bob":   {"password": "securepass",  "balance": "$7,891.00",  "account": "ACC-0187"},
}

# Server-side session store — token lives in HTTP headers on every request,
# so it passes through OpenSSL's heap and can be leaked via Heartbleed.
SESSIONS = {}


def get_session():
    token = request.cookies.get("session")
    if token and token in SESSIONS:
        return SESSIONS[token], token
    return None, None


@app.route("/")
def home():
    data, _ = get_session()
    if data:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = ACCOUNTS.get(username)
        if user and user["password"] == password:
            token = secrets.token_hex(16)
            SESSIONS[token] = {"username": username, "account": user["account"]}
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("session", token, httponly=True)
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    data, _ = get_session()
    if not data:
        return redirect(url_for("login"))
    user = ACCOUNTS[data["username"]]
    return render_template("dashboard.html", username=data["username"],
                           account=user["account"], balance=user["balance"])


@app.route("/logout")
def logout():
    _, token = get_session()
    if token and token in SESSIONS:
        del SESSIONS[token]
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
