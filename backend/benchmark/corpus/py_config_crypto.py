"""Benchmark corpus: misconfiguration, crypto, TLS, logging and secret cases.

`VULN:<type>` marks a flaw expected on that line; findings elsewhere are false positives.
"""

import hashlib
import logging

import jwt
import requests
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------- vulnerable

app.config["DEBUG"] = True  # VULN:debug_enabled
app.config["WTF_CSRF_ENABLED"] = False  # VULN:csrf_disabled
CORS(app, origins=["*"], supports_credentials=True)  # VULN:permissive_cors

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLQ"  # VULN:hardcoded_secret
DB_PASSWORD = "Tr0ub4dor&3xK9vQ2mZ"  # VULN:hardcoded_secret


def v_weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # VULN:weak_hash


def v_tls_off():
    return requests.get("https://partner.example/api", verify=False)  # VULN:disabled_tls_verification


def v_jwt_off(token):
    return jwt.decode(token, options={"verify_signature": False})  # VULN:jwt_verification_disabled


def v_log_secret(password):
    logger.info("login with %s", password)  # VULN:sensitive_data_in_log


def v_swallow():
    try:
        risky()
    except Exception:  # VULN:swallowed_exception
        pass


# ----------------------------------------------------------------------------- safe

SECRET_KEY = "load-me-from-the-environment"
API_URL = "https://api.example.com"
PLACEHOLDER_TOKEN = "{TOKEN}"


def s_strong_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def s_tls_on():
    return requests.get("https://partner.example/api", timeout=5)


def s_jwt_on(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


def s_log_safe(user_id):
    logger.info("login for user %s", user_id)


def s_handled():
    try:
        risky()
    except Exception:
        logger.exception("risky failed")
        raise
