"""VULNERABLE SHOP -- A DELIBERATELY INSECURE DEMO APPLICATION. NOT REAL. DO NOT DEPLOY.

Every flaw in this file is intentional. It exists only so SecureAgent's `demo` command has
realistic weaknesses to find. Each flaw is annotated with what SecureAgent should report.
"""

import hashlib
import logging
import pickle
import sqlite3
import subprocess

import jwt
import requests
from flask import Flask, redirect, request
from flask_cors import CORS
from models import Order

app = Flask(__name__)
app.config["DEBUG"] = True  # misconfig: debug mode enabled
app.config["WTF_CSRF_ENABLED"] = False  # misconfig: CSRF protection disabled
CORS(app, origins=["*"], supports_credentials=True)  # misconfig: wildcard origin + credentials

db = sqlite3.connect("shop.db")


# --- Injection (untrusted request input reaches a dangerous sink) -------------------------


@app.route("/search")
def search():
    term = request.args.get("q")
    cur = db.cursor()
    cur.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")  # SQL injection
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text  # SSRF: server fetches an attacker-chosen URL


@app.route("/download")
def download():
    name = request.args.get("file")
    return open("/srv/files/" + name).read()  # path traversal


def current_theme():
    return request.cookies.get("theme")  # helper returns attacker-influenced data


@app.route("/theme")
def theme():
    return eval("themes." + current_theme())  # code injection via a helper's return value


# --- Broken access control -----------------------------------------------------------------


@app.route("/orders/<order_id>")
def get_order(order_id):
    return str(Order.query.get_or_404(order_id))  # IDOR: no check the order belongs to the caller


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():  # endpoint with no visible authorization
    return "deleted"


# --- Business logic: the server trusting the client -----------------------------------------


@app.route("/register", methods=["POST"])
def register():
    return str(User(**request.json))  # mass assignment: client can set any model field


@app.route("/profile", methods=["POST"])
def update_profile():
    user.is_admin = request.json["is_admin"]  # privilege flag taken from the client


@app.route("/checkout", methods=["POST"])
def checkout():
    return charge(amount=request.json["amount"])  # price decided by the client


# --- Cryptography, deserialization, TLS ---------------------------------------------------


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # weak password hash


@app.route("/import", methods=["POST"])
def import_cart():
    return pickle.loads(request.data)  # insecure deserialization of untrusted bytes


def sync_with_partner():
    return requests.get("https://partner.example/api", verify=False)  # TLS verification disabled


def read_token(token):
    return jwt.decode(token, options={"verify_signature": False})  # JWT signature not verified


# --- Logging and monitoring ----------------------------------------------------------------


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    logging.info("login attempt %s / %s", username, password)  # secret written to the log
    try:
        authenticate(username, hash_password(password))
    except Exception:
        pass  # failure silently swallowed: never logged or monitored
    return "ok"
