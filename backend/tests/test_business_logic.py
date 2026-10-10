"""Business-logic detectors and the developer intent spec (ADR-010)."""

import json
import textwrap

import pytest

from app.analysis.business_logic import analyze_business_logic
from app.analysis.intent import IntentError, load_intent
from app.analysis.scanner import scan_repo


def _find(src: str, **kw):
    return analyze_business_logic("app.py", textwrap.dedent(src), **kw)


def _cats(findings):
    return {(f.category, f.field) for f in findings}


def test_mass_assignment_from_request_body():
    f = _find(
        """
        @app.route("/users", methods=["POST"])
        def create():
            user = User(**request.json)
            return "ok"
        """
    )
    assert ("mass_assignment", "**") in _cats(f)


def test_mass_assignment_via_intermediate_variable():
    f = _find(
        """
        @app.post("/profile")
        def update():
            data = request.get_json()
            current.update(**data)
        """
    )
    assert ("mass_assignment", "**") in _cats(f)


def test_setattr_loop_over_request_items():
    f = _find(
        """
        @app.post("/p")
        def update():
            for k, v in request.json.items():
                setattr(user, k, v)
        """
    )
    assert any(x.category == "mass_assignment" for x in f)


def test_privilege_field_assigned_from_request():
    f = _find(
        """
        @app.post("/signup")
        def signup():
            user.is_admin = request.json["is_admin"]
        """
    )
    assert ("client_trusted_privilege", "is_admin") in _cats(f)


def test_client_trusted_price_keyword():
    f = _find(
        """
        @app.post("/checkout")
        def checkout():
            charge(amount=request.json["amount"])
        """
    )
    assert ("client_trusted_value", "amount") in _cats(f)


def test_server_side_values_are_not_flagged():
    f = _find(
        """
        @app.post("/checkout")
        def checkout():
            product = Product.query.get(request.json["id"])
            charge(amount=product.price)
            order = Order(user_id=current_user.id, total=product.price * 2)
        """
    )
    assert f == []


def test_lookup_keyed_by_client_value_is_server_data():
    f = _find(
        """
        @app.post("/checkout")
        def checkout():
            price = CATALOG[request.json["sku"]]
            charge(amount=price)
        """
    )
    assert f == []


def test_path_params_and_non_handlers_are_not_treated_as_client_bodies():
    f = _find(
        """
        @app.get("/items/<price>")
        def show(price):
            return Item(price=price)

        def helper():
            return User(**request.json)
        """
    )
    assert f == []


def test_extra_fields_from_intent_extend_vocabulary():
    src = """
    @app.post("/x")
    def x():
        obj.tenant_id = request.json["tenant_id"]
    """
    assert _find(src) == []
    assert ("client_trusted_privilege", "tenant_id") in _cats(
        _find(src, extra_fields=frozenset({"tenant_id"}))
    )


# --------------------------------------------------------------------- intent spec


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def test_intent_require_auth_and_owner_scoped(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/admin/purge", methods=["POST"])
        def purge():
            return "ok"

        @app.route("/orders/<order_id>")
        def order(order_id):
            return str(Order.query.get_or_404(order_id))
        """,
    )
    _write(
        tmp_path,
        "secureagent-intent.json",
        json.dumps(
            {
                "rules": [
                    {"id": "admin-auth", "type": "require_auth", "paths": ["/admin/*"]},
                    {"id": "orders-private", "type": "owner_scoped", "paths": ["/orders/*"]},
                ]
            }
        ),
    )
    r = scan_repo(str(tmp_path), check_osv=False)
    assert r.intent_rules == 2
    rules = {f.field for f in r.logic_findings if f.category == "intent_violation"}
    assert rules == {"admin-auth", "orders-private"}
    assert all(f.category == "intent_violation" for f in r.logic_findings)


def test_intent_satisfied_means_no_violation(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        @app.route("/admin/purge", methods=["POST"])
        @login_required
        def purge():
            return "ok"
        """,
    )
    spec = _write(
        tmp_path,
        "rules.json",
        json.dumps({"rules": [{"type": "require_auth", "paths": ["/admin/*"]}]}),
    )
    r = scan_repo(str(tmp_path), check_osv=False, intent=str(spec))
    assert r.intent_rules == 1
    assert r.logic_findings == []


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        json.dumps([1]),
        json.dumps({"rules": [{"type": "bogus"}]}),
        json.dumps({"rules": [{"type": "require_auth"}]}),
        json.dumps({"rules": [{"type": "never_from_client", "fields": "role"}]}),
    ],
)
def test_malformed_spec_fails_loudly(tmp_path, doc):
    p = _write(tmp_path, "bad.json", doc)
    with pytest.raises(IntentError):
        load_intent(str(p))


def test_missing_explicit_spec_is_an_error(tmp_path):
    with pytest.raises(IntentError):
        scan_repo(str(tmp_path), check_osv=False, intent=str(tmp_path / "nope.json"))
