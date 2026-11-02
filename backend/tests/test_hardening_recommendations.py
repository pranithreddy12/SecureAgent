"""Context-aware hardening recommendations (ADR-045).

Named ``test_hardening_recommendations`` because ``test_hardening.py`` already covers login
throttling. Snippet-based: each case writes a tiny project and scans it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.analysis.hardening import RULES, recommend
from app.analysis.intent import IntentError, Profile, load_intent, load_profile
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.cli import main
from app.demo import sample_app_path
from app.schemas.report import HardeningSummary, Recommendation

FLASK = "from flask import Flask, request\napp = Flask(__name__)\n"
LOGIN = FLASK + '@app.route("/login", methods=["POST"])\ndef login():\n    return "ok"\n'
ADMIN = FLASK + '@app.route("/admin/users", methods=["POST"])\ndef users():\n    return "ok"\n'
UPLOAD = FLASK + (
    '@app.route("/profile", methods=["POST"])\ndef profile():\n'
    '    f = request.files["avatar"]\n    return "ok"\n'
)
URL = (
    "import requests\n"
    + FLASK
    + (
        '@app.route("/fetch")\ndef fetch():\n    u = request.args.get("url")\n'
        "    return requests.get(u).text\n"
    )
)
URL_NO_CLIENT = FLASK + ('@app.route("/fetch")\ndef fetch():\n    return request.args.get("url")\n')
PASSWORD = FLASK + ('@app.route("/x")\ndef x():\n    return request.form["password"]\n')
CARD = FLASK + '@app.route("/pay")\ndef pay():\n    return request.json["card_number"]\n'
NPM = '{"name": "x", "version": "1.0.0"}'
NPM_LOCK = '{"name": "x", "lockfileVersion": 3, "packages": {}}'


def scan(root: Path, files: dict[str, str], profile: dict | None = None):
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    if profile is not None:
        (root / "secureagent-intent.json").write_text(
            json.dumps({"profile": profile}), encoding="utf-8"
        )
    return scan_repo(str(root), check_osv=False)


def sub(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir()
    return path


def ids(result) -> set[str]:
    return {r.id for r in result.hardening.recommendations}


def by_id(result, rid: str) -> Recommendation:
    return next(r for r in result.hardening.recommendations if r.id == rid)


# --------------------------------------------------------------------------- 1. profile parsing


def _intent(tmp_path: Path, data) -> str:
    p = tmp_path / "secureagent-intent.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_valid_profile_is_parsed(tmp_path: Path) -> None:
    path = _intent(
        tmp_path,
        {
            "profile": {
                "purpose": "ecommerce",
                "expected_users": "10k-100k",
                "data_categories": ["payment", "pii"],
                "regions": ["IN", "EU"],
                "exposure": "internet",
                "description": "shop",
            },
            "rules": [],
        },
    )
    p = load_profile(path)
    assert p == Profile(
        "ecommerce", "10k-100k", ("payment", "pii"), ("EU", "IN"), "internet", "shop"
    )
    assert load_intent(path) == []


def test_profile_only_file_has_no_rules_and_no_profile_means_none(tmp_path: Path) -> None:
    path = _intent(tmp_path, {"profile": {"purpose": "saas"}})
    assert load_intent(path) == []
    assert load_profile(path).purpose == "saas"
    rules_only = _intent(tmp_path, {"rules": []})
    assert load_profile(rules_only) is None


@pytest.mark.parametrize(
    ("profile", "needle"),
    [
        ({"colour": "red"}, "colour"),
        ({"purpose": "gaming"}, "purpose"),
        ({"expected_users": "lots"}, "expected_users"),
        ({"data_categories": ["secrets"]}, "data_categories"),
        ({"regions": ["India"]}, "regions"),
        ({"exposure": "dmz"}, "exposure"),
        ({"description": "x" * 501}, "500"),
    ],
)
def test_invalid_profile_is_rejected_naming_the_field(tmp_path: Path, profile, needle) -> None:
    with pytest.raises(IntentError, match=needle):
        load_profile(_intent(tmp_path, {"profile": profile}))


def test_file_with_neither_key_keeps_the_existing_error(tmp_path: Path) -> None:
    path = _intent(tmp_path, {"something": 1})
    with pytest.raises(IntentError, match="expected an object with a 'rules' list"):
        load_intent(path)
    with pytest.raises(IntentError, match="expected an object with a 'rules' list"):
        load_profile(path)


# --------------------------------------------------------------------------- 2. every rule

BIG = {"exposure": "internet", "expected_users": "100k-1m"}

# rule id -> (positive files, positive profile, negative files, negative profile)
CASES = {
    "HR-RATELIMIT-LOGIN": (LOGIN, None, LOGIN + "import slowapi\n", None),
    "HR-RATELIMIT-API": (FLASK, BIG, FLASK, {**BIG, "exposure": "internal"}),
    "HR-MFA": (LOGIN + ADMIN.split("\n", 2)[2], None, LOGIN + "import pyotp\n", None),
    "HR-PASSWORD-HASH": (PASSWORD, None, PASSWORD + "import bcrypt\n", None),
    "HR-PII-ENCRYPT": (FLASK, {"data_categories": ["pii"]}, FLASK, {"purpose": "saas"}),
    "HR-PII-MINIMISE": (FLASK, {"data_categories": ["pii"]}, FLASK, {"purpose": "saas"}),
    "HR-PAYMENT-SCOPE": (CARD, None, FLASK, None),
    "HR-PAYMENT-SERVER-PRICE": (FLASK, {"purpose": "ecommerce"}, FLASK, {"purpose": "content"}),
    "HR-UPLOAD": (UPLOAD, None, FLASK, None),
    "HR-HEADERS": (LOGIN, None, LOGIN + "import flask_talisman\n", None),
    "HR-SSRF-EGRESS": (URL, None, URL_NO_CLIENT, None),
    "HR-AUDIT-LOG": (ADMIN, None, FLASK, None),
    "HR-MONITORING": (
        FLASK,
        {"expected_users": "10k-100k"},
        FLASK + "import sentry_sdk\n",
        {"expected_users": "10k-100k"},
    ),  # fmt: skip
    "HR-DEPENDENCY-PIPELINE": (
        {"package.json": NPM},
        None,
        {"package.json": NPM, "package-lock.json": NPM_LOCK},
        None,
    ),  # fmt: skip
    "HR-AUTHZ-REVIEW": (
        FLASK + '@app.route("/o", methods=["POST"])\ndef o():\n    return "x"\n',
        {"expected_users": "1k-10k"},
        FLASK,
        {"expected_users": "1k-10k"},
    ),  # fmt: skip
    "HR-COMPLIANCE-NOTE": (PASSWORD, {"regions": ["EU"]}, PASSWORD, {"regions": []}),
}


def test_cases_cover_exactly_the_sixteen_rules() -> None:
    assert len(RULES) == 16
    assert {name.upper().replace("_", "-") for name in (r.__name__ for r in RULES)} == set(CASES)


def _files(value) -> dict[str, str]:
    return value if isinstance(value, dict) else {"app.py": value}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_when_its_trigger_is_present(tmp_path: Path, rule_id: str) -> None:
    files, profile, _, _ = CASES[rule_id]
    assert rule_id in ids(scan(tmp_path, _files(files), profile))


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet_without_its_trigger(tmp_path: Path, rule_id: str) -> None:
    _, _, files, profile = CASES[rule_id]
    assert rule_id not in ids(scan(tmp_path, _files(files), profile))


def test_mfa_rule_can_fire_from_the_declared_purpose(tmp_path: Path) -> None:
    result = scan(tmp_path, {"app.py": LOGIN}, {"purpose": "fintech"})
    assert by_id(result, "HR-MFA").basis == "code+profile"
    other = scan(sub(tmp_path, "b"), {"app.py": LOGIN}, {"purpose": "saas"})
    assert "HR-MFA" not in ids(other)


# ----------------------------------------------------------- 3-5. profile, scale, pan


def test_needs_profile_lists_the_fields_that_would_unlock_a_rule(tmp_path: Path) -> None:
    result = scan(tmp_path, {"app.py": FLASK})
    need = next(n for n in result.hardening.needs_profile if n["id"] == "HR-RATELIMIT-API")
    assert need["missing"] == ["expected_users", "exposure"]
    assert "HR-RATELIMIT-API" not in ids(result)
    assert result.hardening.profile_declared == {}


def test_scale_escalates_exactly_three_rules(tmp_path: Path) -> None:
    files = {"app.py": ADMIN}
    small = scan(sub(tmp_path, "a"), files, {"expected_users": "10k-100k"})
    big = scan(sub(tmp_path, "b"), files, {"expected_users": "100k-1m"})
    lo = {r.id: r.priority for r in small.hardening.recommendations}
    hi = {r.id: r.priority for r in big.hardening.recommendations}
    changed = {i for i in lo if lo[i] != hi[i]}
    assert changed == {"HR-HEADERS", "HR-AUDIT-LOG", "HR-MONITORING"}
    assert all(lo[i] == "consider" and hi[i] == "recommended" for i in changed)
    assert "Raised to recommended" in next(
        r.rationale for r in big.hardening.recommendations if r.id == "HR-MONITORING"
    )


def test_pan_counts_as_payment_only_with_payment_context(tmp_path: Path) -> None:
    ambiguous = FLASK + '@app.route("/k")\ndef k():\n    return request.form["pan"]\n'
    alone = scan(tmp_path, {"app.py": ambiguous})
    assert "payment" not in alone.hardening.data_categories_detected
    with_ctx = scan(sub(tmp_path, "b"), {"app.py": "import stripe\n" + ambiguous})
    assert "payment" in with_ctx.hardening.data_categories_detected
    gov = scan(sub(tmp_path, "c"), {"app.py": ambiguous.replace('"pan"', '"pan_number"')})
    assert "government_id" in gov.hardening.data_categories_detected
    assert "payment" not in gov.hardening.data_categories_detected


def test_token_expiry_is_not_card_data_without_payment_context(tmp_path: Path) -> None:
    token = FLASK + '@app.route("/t")\ndef t():\n    return request.json["token_expiry"]\n'
    alone = scan(tmp_path, {"app.py": token})
    assert "payment" not in alone.hardening.data_categories_detected
    assert not ids(alone) & {"HR-PAYMENT-SCOPE", "HR-COMPLIANCE-NOTE"}
    with_ctx = scan(sub(tmp_path, "b"), {"app.py": "import stripe\n" + token})
    assert "payment" in with_ctx.hardening.data_categories_detected
    card = scan(sub(tmp_path, "c"), {"app.py": token.replace("token_expiry", "card_expiry")})
    assert "payment" in card.hardening.data_categories_detected


def test_pin_code_is_a_postal_code_not_a_credential(tmp_path: Path) -> None:
    postal = FLASK + '@app.route("/a")\ndef a():\n    return request.json["pin_code"]\n'
    result = scan(tmp_path, {"app.py": postal})
    assert "credentials" not in result.hardening.data_categories_detected
    assert "HR-PASSWORD-HASH" not in ids(result)
    pin = scan(sub(tmp_path, "b"), {"app.py": postal.replace("pin_code", "atm_pin")})
    assert "credentials" in pin.hardening.data_categories_detected


def test_test_and_fixture_files_do_not_drive_data_categories(tmp_path: Path) -> None:
    model = (
        "from pydantic import BaseModel\nclass U(BaseModel):\n    email: str\n    aadhaar: str\n"
    )
    result = scan(tmp_path, {"tests/test_users.py": model, "fixtures/users.py": model})
    assert result.hardening.data_categories_detected == []
    assert not ids(result) & {"HR-PII-ENCRYPT", "HR-PII-MINIMISE"}
    real = scan(sub(tmp_path, "b"), {"models.py": model})
    assert {"pii", "government_id"} <= set(real.hardening.data_categories_detected)


def test_detected_and_declared_categories_stay_separate(tmp_path: Path) -> None:
    result = scan(tmp_path, {"app.py": PASSWORD}, {"data_categories": ["health"]})
    h = result.hardening
    assert h.data_categories_detected == ["credentials"]
    assert h.profile_declared["data_categories"] == ["health"]


# --------------------------------------------------------------------------- 6. honesty invariants


def _demo_summary() -> HardeningSummary:
    return scan_repo(str(sample_app_path()), check_osv=False).hardening


def test_every_recommendation_states_what_cannot_be_verified() -> None:
    recs = _demo_summary().recommendations
    assert recs
    assert all(r.cannot_verify.strip() for r in recs)
    assert len({r.cannot_verify for r in recs}) == len(recs)  # specific, not one sentence copied
    assert all(r.evidence for r in recs if r.basis in ("code", "code+profile"))
    assert all(len(r.evidence) <= 5 and 2 <= len(r.actions) <= 4 for r in recs)


def test_a_recommendation_has_no_severity() -> None:
    assert "severity" not in Recommendation.model_fields
    assert "severity" not in HardeningSummary.model_fields
    assert not any(hasattr(r, "severity") for r in _demo_summary().recommendations)


def test_references_come_only_from_the_allowed_list() -> None:
    allowed = re.compile(
        r"^(OWASP Top 10 \(2021\) A(0[1-9]|10)\b.*|OWASP API Security Top 10 \(2023\) API(10|[1-9])"
        r"|OWASP ASVS 4\.0 V(1[0-4]|[1-9]) [A-Za-z ]+|OWASP [A-Za-z -]+ Cheat Sheet"
        r"|PCI DSS|GDPR|HIPAA|COPPA|Digital Personal Data Protection Act, 2023)$"
    )
    refs = {ref for r in _demo_summary().recommendations for ref in r.references}
    assert refs and all(allowed.match(ref) for ref in refs), refs


def test_output_is_deterministic_and_sorted(tmp_path: Path) -> None:
    first = scan(tmp_path, {"app.py": LOGIN + ADMIN.split("\n", 2)[2]}, BIG)
    second = scan_repo(str(tmp_path), check_osv=False)
    assert first.hardening.model_dump_json() == second.hardening.model_dump_json()
    recs = first.hardening.recommendations
    assert recs == sorted(recs, key=lambda r: (r.priority != "recommended", r.category, r.id))


# --------------------------------------------------------------------------- 8-9. isolation


def _cli_json(capsys, path: Path, *extra: str) -> dict:
    main(["scan", str(path), "--no-osv", "--format", "json", "--exit-zero", *extra])
    return json.loads(capsys.readouterr().out)


def test_a_profile_changes_no_finding_sarif_or_gate(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(LOGIN + "DEBUG = True\n", encoding="utf-8")
    before = _cli_json(capsys, tmp_path)
    main(["scan", str(tmp_path), "--no-osv", "--format", "sarif", "--exit-zero"])
    sarif_before = capsys.readouterr().out
    (tmp_path / "secureagent-intent.json").write_text(
        json.dumps({"profile": {"purpose": "fintech", "expected_users": ">1m"}}), encoding="utf-8"
    )
    after = _cli_json(capsys, tmp_path)
    main(["scan", str(tmp_path), "--no-osv", "--format", "sarif", "--exit-zero"])
    sarif_after = capsys.readouterr().out

    assert after["hardening"] != before["hardening"]  # the profile did change the guidance...
    for key in ("findings", "summary", "dependency_findings", "misconfig_findings"):
        assert after[key] == before[key]  # ...and nothing else
    assert sarif_after == sarif_before and "HR-" not in sarif_after
    assert main(["scan", str(tmp_path), "--no-osv", "--fail-on", "critical"]) == 0


def test_new_recommendation_alone_does_not_fail_the_baseline_gate(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    base = tmp_path / "base.json"
    assert main(["scan", str(tmp_path), "--no-osv", "--write-baseline", str(base)]) == 0
    capsys.readouterr()
    (tmp_path / "secureagent-intent.json").write_text(
        json.dumps({"profile": {"data_categories": ["pii"], "regions": ["EU"]}}), encoding="utf-8"
    )
    assert "HR-COMPLIANCE-NOTE" in ids(scan_repo(str(tmp_path), check_osv=False))  # new guidance
    assert (
        main(["scan", str(tmp_path), "--no-osv", "--baseline", str(base), "--fail-on", "low"]) == 0
    )


def test_inline_ignored_findings_do_not_count_in_related_findings(tmp_path: Path) -> None:
    post = 'methods=["POST"])'
    # route findings are reported at the handler's def line, so the ignore goes there
    routes = FLASK + (
        f'@app.route("/a", {post}\ndef a():  # secureagent: ignore\n    return "x"\n'
        f'@app.route("/b", {post}\ndef b():\n    return "x"\n'
    )
    result = scan(tmp_path, {"app.py": routes}, {"expected_users": "1k-10k"})
    assert result.inline_ignored == 1
    assert by_id(result, "HR-AUTHZ-REVIEW").related_findings == {
        "missing_function_level_authorization": 1
    }


def test_suppressed_findings_do_not_count_in_related_findings(tmp_path: Path) -> None:
    route = FLASK + '@app.route("/b", methods=["POST"])\ndef b():\n    return "x"\n'
    result = scan(tmp_path, {"app.py": route}, {"expected_users": "1k-10k"})
    rec = by_id(result, "HR-AUTHZ-REVIEW")
    where = rec.evidence[0].location
    dropped = {("missing_function_level_authorization", where)}
    assert "HR-AUTHZ-REVIEW" not in {
        r.id for r in recommend(result, result.profile, dropped).recommendations
    }


# --------------------------------------------------------------------------- 10-11. wording


def test_no_secret_value_appears_in_any_recommendation() -> None:
    text = _demo_summary().model_dump_json()
    for secret in (
        "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5",
        "Hk3Ts9Pw2Lm7Qd5Xv8Bn4Rc1Fj6Gz0",
        "AKIAIOSFODNN7",
    ):
        assert secret not in text


def test_compliance_is_a_note_never_a_verdict(tmp_path: Path) -> None:
    declared = ["health", "children", "payment"]
    result = scan(
        tmp_path, {"app.py": PASSWORD}, {"regions": ["IN", "EU", "US"], "data_categories": declared}
    )
    note = by_id(result, "HR-COMPLIANCE-NOTE")
    for regime in (
        "Digital Personal Data Protection Act, 2023",
        "GDPR",
        "HIPAA",
        "COPPA",
        "PCI DSS",
    ):
        assert regime in note.rationale
    assert note.rationale.count("may apply") == 5
    assert "review with whoever owns compliance" in note.rationale
    for text in (result.hardening.model_dump_json(), _demo_summary().model_dump_json()):
        assert "compliant" not in text.lower() and "%" not in text


def test_absence_is_worded_as_absence_of_evidence() -> None:
    for r in _demo_summary().recommendations:
        assert not re.search(r"\b(has|have) no (rate limiting|mfa|headers)\b", r.rationale, re.I)


# --------------------------------------------------------------------------- 12. CLI


def test_cli_recommend_flag_prints_a_block_and_json_always_has_the_key(
    capsys, tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text(LOGIN, encoding="utf-8")
    main(["scan", str(tmp_path), "--no-osv", "--no-color", "--exit-zero"])
    assert "Hardening recommendations" not in capsys.readouterr().out
    main(["scan", str(tmp_path), "--no-osv", "--no-color", "--exit-zero", "--recommend"])
    out = capsys.readouterr().out
    assert "Hardening recommendations" in out and "HR-RATELIMIT-LOGIN" in out
    assert "could not verify" in out
    assert "hardening" in _cli_json(capsys, tmp_path)


def test_summary_model_is_a_plain_pydantic_object() -> None:
    assert HardeningSummary().model_dump(mode="json")["recommendations"] == []


# --------------------------------------------------------------------------- 14-15. MCP and demo


def _mcp(args):
    from tests.test_mcp_server import call

    return call("hardening_recommendations", args)


def test_mcp_tool_happy_path_and_bad_path(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(LOGIN, encoding="utf-8")
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    ok = json.loads(_mcp({"path": str(tmp_path)})["result"]["content"][0]["text"])
    assert any(r["id"] == "HR-RATELIMIT-LOGIN" for r in ok["recommendations"])
    for bad in ({"path": str(tmp_path / "missing")}, {"path": str(tmp_path.parent)}, {}):
        assert _mcp(bad)["result"]["isError"] is True


def test_demo_shows_at_least_five_recommendations(capsys) -> None:
    assert len(_demo_summary().recommendations) >= 5
    main(["demo", "--no-color"])
    assert "Hardening recommendations" in capsys.readouterr().out


def test_report_has_section_20_and_the_executive_line(tmp_path: Path) -> None:
    from app.reports.renderer import render_html

    html = render_html(scan_to_report_context(scan_repo(str(sample_app_path()), check_osv=False)))
    assert 'id="s20"' in html and "20. Hardening Recommendations" in html
    assert "hardening recommendation(s) (see section 20)" in html
    assert "Could not verify" in html
    no_profile = tmp_path / "p"
    no_profile.mkdir()
    (no_profile / "app.py").write_text(LOGIN, encoding="utf-8")
    html2 = render_html(scan_to_report_context(scan_repo(str(no_profile), check_osv=False)))
    assert "No application profile declared" in html2
