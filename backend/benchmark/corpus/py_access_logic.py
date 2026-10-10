"""Benchmark corpus: access control and business-logic cases (Flask).

`VULN:<type>` marks a flaw expected on that line; findings anywhere else count as false
positives. See py_injection.py for conventions.
"""

from flask import Flask, request

app = Flask(__name__)


# ----------------------------------------------------------------------------- vulnerable


@app.route("/v/orders/<order_id>")
def v_get_order(order_id):
    return str(Order.query.get_or_404(order_id))  # VULN:idor


@app.route("/v/invoices/<invoice_id>")
def v_get_invoice(invoice_id):
    return str(Invoice.query.filter_by(id=invoice_id).first())  # VULN:idor


@app.route("/v/admin/purge", methods=["POST"])
def v_admin_purge():  # VULN:missing_function_level_authorization
    return "purged"


@app.route("/v/users", methods=["POST"])
@login_required
def v_create_user():
    return str(User(**request.json))  # VULN:mass_assignment


@app.route("/v/promote", methods=["POST"])
@login_required
def v_promote():
    user.is_admin = request.json["is_admin"]  # VULN:client_trusted_privilege


@app.route("/v/pay", methods=["POST"])
@login_required
def v_pay():
    return charge(amount=request.json["amount"])  # VULN:client_trusted_value


@app.route("/v/profile", methods=["POST"])
@login_required
def v_profile():
    for key, value in request.json.items():
        setattr(user, key, value)  # VULN:mass_assignment
    return "ok"


@app.route("/v/ticket/<ticket_id>/close", methods=["POST"])
@login_required
def v_close_ticket(ticket_id):
    # KNOWN-MISS: authorization is a business rule (only the assignee may close) not visible as a
    # by-id lookup; needs the intent spec.
    ticket = tickets[ticket_id]  # VULN:idor
    ticket.closed = True
    return "closed"


# ----------------------------------------------------------------------------- safe


@app.route("/s/orders/<order_id>")
@login_required
def s_get_order(order_id):
    return str(Order.query.filter_by(id=order_id, user_id=current_user.id).first())


@app.route("/s/admin/purge", methods=["POST"])
@admin_required
def s_admin_purge():
    return "purged"


@app.route("/s/users", methods=["POST"])
@login_required
def s_create_user():
    data = request.json
    return str(User(name=data["name"], email=data["email"]))


@app.route("/s/pay", methods=["POST"])
@login_required
def s_pay():
    # Known false positive: a catalogue lookup by id is not user-owned data, but the by-id IDOR
    # heuristic cannot tell shared reference data from private records.
    product = Product.query.get(request.json["product_id"])
    return charge(amount=product.price)


@app.route("/s/health")
def s_health():
    return "ok"


@app.route("/s/me")
@login_required
def s_me():
    return str(current_user.profile)
