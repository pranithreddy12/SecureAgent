"""Regressions from the first independent evaluation (eight real projects, 111 sampled findings).

Each case is a pattern the scanner reported that a reader judged not to be a vulnerability, plus the
nearest *real* variant that must keep being reported.
"""

from __future__ import annotations

import textwrap

from app.analysis.access_control import analyze_access_control
from app.analysis.logging_checks import scan_logging
from app.analysis.routes import extract_routes, route_findings
from app.analysis.secrets import key_looks_secret, scan_text
from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint


def src(text: str) -> str:
    return textwrap.dedent(text)


def sqli(text: str) -> list:
    return [f for f in analyze_taint("app.py", src(text)) if f.vuln_type == "sql_injection"]


def idor(text: str) -> list:
    return analyze_access_control("app.py", src(text))


# ------------------------------------------------------------------ SQL: statement objects

LIST_ROUTE = """
    from sqlalchemy import select
    @router.get("/items")
    def list_items(db, org, company_id=None, page=1, page_size=50):
        stmt = select(Item).where(Item.organization_id == org.id)
        if company_id:
            stmt = stmt.where(Item.company_id == company_id)
        ordered = stmt.order_by(Item.created_at)
        rows = db.execute(ordered.offset((page - 1) * page_size).limit(page_size))
        return rows
"""


def test_sqlalchemy_statement_variable_is_not_sql_injection():
    assert sqli(LIST_ROUTE) == []


def test_raw_text_in_a_statement_variable_is_still_sql_injection():
    raw = LIST_ROUTE.replace(
        "stmt = stmt.where(Item.company_id == company_id)",
        'stmt = stmt.where(text(f"company_id = {company_id}"))',
    )
    assert sqli(raw)
    string_query = """
        @router.get("/items")
        def list_items(db, name):
            q = "SELECT * FROM items WHERE name = '" + name + "'"
            return db.execute(q)
    """
    assert sqli(string_query)


# ------------------------------------------------------------------ IDOR: ownership forms

OWNED = """
    @router.get("/{cid}")
    def get_campaign(cid: int, db, org=Depends(current_org)):
        row = db.get(Campaign, cid)
        if not row or row.organization_id != org.id:
            raise NotFound()
        return row
"""


def test_ownership_comparison_on_organization_id_is_recognised():
    assert idor(OWNED) == []
    unchecked = OWNED.replace(
        "        if not row or row.organization_id != org.id:\n            raise NotFound()\n", ""
    )
    assert idor(unchecked)


def test_repository_scoped_at_construction_is_not_idor():
    scoped = """
        @router.get("/{eid}")
        def get_event(eid: int, db, user=Depends(get_current_user)):
            repo = EventRepository(db, user.tenant_id)
            return repo.get(eid)
    """
    assert idor(scoped) == []
    unscoped = scoped.replace("EventRepository(db, user.tenant_id)", "EventRepository(db)")
    assert idor(unscoped)


def test_in_memory_store_lookup_is_not_an_orm_by_id_lookup():
    text = """
        @app.get("/{code}")
        def redirect(code: str):
            return url_store.get(code)
    """
    assert idor(text) == []


# ------------------------------------------------------------------ routes / guards


def _unguarded(relpath: str, text: str) -> list:
    return route_findings(extract_routes(relpath, src(text)))


def test_current_user_style_dependencies_are_guards_but_optional_ones_are_not():
    guarded = """
        @router.post("/orgs/items")
        def create(payload, org: Organization = Depends(current_org)):
            ...
        @router.post("/logout")
        async def out(user: User = Depends(get_current_active_user)):
            ...
    """
    assert _unguarded("r.py", guarded) == []
    optional = """
        @router.post("/orgs/items")
        def create(payload, tenant = Depends(get_current_user_optional)):
            ...
    """
    assert _unguarded("r.py", optional)


def test_nest_controller_guard_above_the_controller_decorator():
    nest = """
        @ApiTags('admin')
        @UseGuards(RolesGuard)
        @Controller('admin')
        export class AdminController {
          @Post('hospitals')
          createHospital(@Body() dto: Dto) { return 1; }
        }
    """
    assert _unguarded("admin.controller.ts", nest) == []
    open_ctl = nest.replace("@UseGuards(RolesGuard)\n", "")
    assert _unguarded("admin.controller.ts", open_ctl)


def test_client_api_calls_are_not_routes_but_server_routes_are():
    client = "const save = useMutation({ mutationFn: (b) => api.put('/settings', b) });\n"
    assert extract_routes("page.tsx", client) == []
    assert extract_routes("lib/client.ts", client) == []
    server = (
        "const express = require('express');\n"
        "const api = express.Router();\n"
        "api.put('/settings', h);\n"
    )
    assert [r.path for r in extract_routes("routes.js", server)] == ["/settings"]


def test_capability_url_and_sign_in_routes_are_public_by_design():
    public = """
        @router.get("/p/{token}")
        def page(token: str): ...
        @router.post("/register")
        def register(body): ...
        @router.post("/webhooks/stripe")
        def hook(request): ...
    """
    assert _unguarded("r.py", public) == []
    assert _unguarded("r.py", '@router.post("/admin/reset")\ndef reset(): ...\n')


# ------------------------------------------------------------------ secrets: values and keys


def test_identifier_values_and_descriptive_keys_are_not_credentials():
    cases = [
        'ACCESS_KEY = "aibos.access_token"\n',  # storage key name
        'TOKEN_TRANSFER = "token_transfer"\n',  # enum member
        'PASS_THROUGH = "pass_through"\n',
        'oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")\n',
        'max_tokens = int(os.environ.get("MAX_TOKENS", "1024"))\n',
        'token_contract = "0x' + "ab" * 20 + '"\n',
        'type AuthStatus = "loading" | "authenticated";\n',
    ]
    for line in cases:
        assert scan_text("app.py", line) == [], line
    assert not key_looks_secret("tokenUrl") and not key_looks_secret("max_tokens")
    assert key_looks_secret("auth_token") and key_looks_secret("JWT_SECRET")


def test_real_looking_credentials_are_still_found_and_docs_are_prose():
    assert scan_text("config.py", 'DB_PASSWORD = "Xk39sLq02mZpV8rT"\n')
    assert scan_text(
        "config.py", 'SECRET_KEY = os.environ.get("SECRET_KEY", "kognos-dev-secret-9x2")\n'
    )
    assert scan_text("README.md", 'export PASSWORD="Xk39sLq02mZpV8rT"\n') == []
    assert scan_text("README.md", "aws AKIAABCDEFGHIJKLMNOP\n")  # provider formats still count


# ------------------------------------------------------------------ misc detectors


def test_swallowed_exception_is_reported_only_when_broad_and_unexplained():
    broad = "try:\n    risky()\nexcept Exception:\n    pass\n"
    assert [f.category for f in scan_logging("a.py", broad)] == ["swallowed_exception"]
    narrow = "try:\n    parse()\nexcept ValueError:\n    pass\n"
    assert scan_logging("a.py", narrow) == []
    explained = (
        "try:\n    risky()\nexcept Exception:  # best effort: the cache is optional\n    pass\n"
    )
    assert scan_logging("a.py", explained) == []
    unexplained_comment = "try:\n    risky()\nexcept Exception:  # TODO\n    pass\n"
    assert scan_logging("a.py", unexplained_comment)


def test_bucketing_and_short_code_hashes_are_not_weak_hash_findings():
    bucket = "import hashlib\nh = int(hashlib.md5(t.encode()).hexdigest(), 16)\n"
    short = "import hashlib\ncode = hashlib.sha1(u.encode()).hexdigest()[:6]\n"
    for text in (bucket, short):
        assert [f for f in scan_sinks("a.py", text) if f.category == "weak_hash"] == []
    password = "import hashlib\nh = hashlib.md5(pw.encode()).hexdigest()\n"
    assert [f for f in scan_sinks("a.py", password) if f.category == "weak_hash"]


def test_inner_html_with_constant_markup_is_not_an_xss_sink():
    constant = "root.innerHTML =\n  '<div>Graph failed to load</div>';\n"
    template = 'panel.innerHTML = `\n  <div id="head"></div>\n`;\n'
    dynamic = "head.innerHTML = '<b>' + n.label + '</b>';\n"
    interpolated = "el.innerHTML = `<b>${n.label}</b>`;\n"
    assert [f for f in scan_sinks("a.ts", constant) if f.category == "xss_sink"] == []
    assert [f for f in scan_sinks("a.ts", template) if f.category == "xss_sink"] == []
    assert [f for f in scan_sinks("a.ts", dynamic) if f.category == "xss_sink"]
    assert [f for f in scan_sinks("a.ts", interpolated) if f.category == "xss_sink"]


def test_path_name_and_character_filter_neutralise_path_traversal():
    safe = """
        @router.get("/download/{name}")
        def download(name: str):
            safe = Path(name).name
            return open(Path(BASE) / safe)
    """
    filtered = """
        @router.get("/graph/{ns}")
        def graph(ns: str):
            clean = "".join(c if c.isalnum() or c in "_-" else "_" for c in ns)
            return open(f"graph_{clean}.json")
    """
    raw = """
        @router.get("/download/{name}")
        def download(name: str):
            return open(Path(BASE) / name)
    """
    for text in (safe, filtered):
        assert [
            f for f in analyze_taint("a.py", src(text)) if f.vuln_type == "path_traversal"
        ] == []
    assert [f for f in analyze_taint("a.py", src(raw)) if f.vuln_type == "path_traversal"]
