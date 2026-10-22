from flask import Flask, request
import sqlite3

app = Flask(__name__)
app.config["DEBUG"] = True


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchone())
