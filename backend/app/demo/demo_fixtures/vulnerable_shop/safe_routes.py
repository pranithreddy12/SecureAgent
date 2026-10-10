"""The SAFE counterparts of the flaws in app.py.

SecureAgent should report NOTHING in this file. It demonstrates that the scanner tells
vulnerable code from correct code instead of flagging every database call or subprocess.
"""

import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, request
from models import Order

app = Flask(__name__)
db = sqlite3.connect("shop.db")


@app.route("/safe/search")
def safe_search():
    term = request.args.get("q")
    cur = db.cursor()
    # Parameterised query: the SQL text is constant, user input is passed as data.
    cur.execute("SELECT * FROM products WHERE name LIKE ?", ["%" + term + "%"])
    return str(cur.fetchall())


@app.route("/safe/ping")
def safe_ping():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host])  # argument list, no shell


@app.route("/safe/orders/<order_id>")
@login_required
def safe_get_order(order_id):
    # Ownership enforced: the lookup is scoped to the signed-in user.
    return str(Order.query.filter_by(id=order_id, user_id=current_user.id).first())


def checksum(data):
    return hashlib.sha256(data).hexdigest()  # strong hash


def load_settings(text):
    return yaml.safe_load(text)  # safe loader


@app.route("/safe/checkout", methods=["POST"])
@login_required
def safe_checkout():
    # The price comes from the server-side catalogue; the client only names the product.
    return charge(amount=CATALOG[request.json["product_id"]].price)
