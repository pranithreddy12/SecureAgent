"""Benchmark corpus: injection-class cases (Flask).

Every line carrying `VULN:<type>` is a real flaw the scanner SHOULD report on that line.
Any finding elsewhere in the corpus is counted as a false positive. Cases marked KNOWN-MISS are
real flaws the engine is not expected to see yet; they are kept so recall is honest.
"""

import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)
db = sqlite3.connect("shop.db")
ALLOWED_HOSTS = {"example.com"}


# ----------------------------------------------------------------------------- vulnerable


@app.route("/v/sql_concat")
def v_sql_concat():
    name = request.args.get("name")
    return str(db.execute("SELECT * FROM t WHERE n = '" + name + "'").fetchall())  # VULN:sql_injection


@app.route("/v/sql_fstring")
def v_sql_fstring():
    name = request.args.get("name")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM t WHERE n = '{name}'")  # VULN:sql_injection
    return "ok"


@app.route("/v/sql_format")
def v_sql_format():
    name = request.args.get("name")
    cur = db.cursor()
    cur.execute("SELECT * FROM t WHERE n = '%s'" % name)  # VULN:sql_injection
    return "ok"


@app.route("/v/cmd_shell")
def v_cmd_shell():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # VULN:command_injection


@app.route("/v/cmd_system")
def v_cmd_system():
    host = request.args.get("host")
    os.system("nslookup " + host)  # VULN:command_injection
    return "ok"


@app.route("/v/eval")
def v_eval():
    expr = request.args.get("expr")
    return str(eval(expr))  # VULN:code_injection


@app.route("/v/ssrf")
def v_ssrf():
    url = request.args.get("url")
    return requests.get(url).text  # VULN:ssrf


@app.route("/v/path")
def v_path():
    name = request.args.get("file")
    return open("/srv/files/" + name).read()  # VULN:path_traversal


@app.route("/v/redirect")
def v_redirect():
    nxt = request.args.get("next")
    return redirect(nxt)  # VULN:open_redirect


@app.route("/v/pickle", methods=["POST"])
@login_required
def v_pickle():
    return pickle.loads(request.data)  # VULN:insecure_deserialization


@app.route("/v/yaml", methods=["POST"])
@login_required
def v_yaml():
    return yaml.load(request.data)  # VULN:insecure_deserialization


def _theme():
    return request.cookies.get("theme")


@app.route("/v/helper_return")
def v_helper_return():
    return eval("themes." + _theme())  # VULN:code_injection


@app.route("/v/second_order")
def v_second_order():
    # KNOWN-MISS: value is stored then re-read later; static taint does not model persistence.
    stored = db.execute("SELECT note FROM notes LIMIT 1").fetchone()[0]
    db.execute("SELECT * FROM t WHERE n = '" + stored + "'")  # VULN:sql_injection
    return "ok"


# ----------------------------------------------------------------------------- safe


@app.route("/s/sql_param")
def s_sql_param():
    name = request.args.get("name")
    cur = db.cursor()
    cur.execute("SELECT * FROM t WHERE n = ?", (name,))
    return str(cur.fetchall())


@app.route("/s/cmd_list")
def s_cmd_list():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/s/constant_eval")
def s_constant_eval():
    return str(eval("1 + 1"))


@app.route("/s/ssrf_constant")
def s_ssrf_constant():
    return requests.get("https://api.example.com/status").text


@app.route("/s/path_const")
def s_path_const():
    return open("/srv/files/readme.txt").read()


@app.route("/s/redirect_const")
def s_redirect_const():
    return redirect("/home")


@app.route("/s/yaml_safe", methods=["POST"])
@login_required
def s_yaml_safe():
    return yaml.safe_load(request.data)


@app.route("/s/static_sql")
def s_static_sql():
    cur = db.cursor()
    cur.execute("SELECT count(*) FROM t")
    return str(cur.fetchall())


@app.route("/s/allowlisted_host")
def s_allowlisted_host():
    # Allow-list check: a human sees this is safe. Sanitizer modelling is not implemented, so the
    # scanner may flag it -- a known false positive tracked by the benchmark.
    host = request.args.get("host")
    if host not in ALLOWED_HOSTS:
        return "denied", 403
    return requests.get("https://" + host).text
