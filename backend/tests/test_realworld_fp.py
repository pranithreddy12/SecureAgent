"""Regression tests for false positives reported from a real project scan (2026-10-12).

Each case is a pattern that was reported by the scanner but is not a vulnerability, plus the
nearest *real* variant that must keep being reported.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from app.analysis.authz_matrix import authz_outliers
from app.analysis.gitignore import GitIgnore
from app.analysis.reporting import scan_to_report_context
from app.analysis.routes import Route, extract_routes
from app.analysis.scanner import scan_repo
from app.analysis.secrets import key_looks_secret, scan_text
from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint
from app.core.enums import FindingStatus


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def types(root: Path) -> list:
    return scan_to_report_context(scan_repo(str(root), check_osv=False)).findings


# ------------------------------------------------------------------ secrets


def test_key_names_are_matched_as_words_not_substrings():
    for key in ("author", "author_url", "authorName", "author_fullname", "passport", "tokenizer"):
        assert not key_looks_secret(key), key
    for key in ("password", "DB_PASSWORD", "apiKey", "api_key", "client_secret", "authToken",
                "SECRET_KEY", "private-key", "auth", "authorization"):  # fmt: skip
        assert key_looks_secret(key), key


def test_data_fields_named_author_are_not_credentials():
    text = textwrap.dedent(
        """
        export const row = {
          author: "SomeRedditUser",
          author_fullname: "t2_abc123xyz",
          author_url: "https://www.reddit.com/user/SomeRedditUser",
          author_flair_template_id: "7a8c2f2e-1b3d-4c5e-9f00-112233445566",
          passport: "screen-name",
        };
        """
    )
    assert scan_text("schema.ts", text) == []


def test_fake_and_url_values_are_ignored_but_real_credentials_are_not():
    assert scan_text("a.ts", 'const secret = "whsec_fake";\n') == []
    assert scan_text("a.py", 'redirect_uri = "https://example.org/callback"\n') == []
    assert scan_text("a.py", 'DB_URL_PASSWORD = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"\n')
    # a URL that embeds credentials is still a credential
    assert scan_text("a.py", 'database_secret = "postgres://admin:S3cr3tPass@db.internal/app"\n')


def test_firebase_web_key_in_client_env_is_low_not_high():
    key = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"  # 39 chars, Google API key shape
    client = scan_text(".env", f"VITE_FIREBASE_API_KEY={key}\n")
    assert [f.severity for f in client] == ["low"]
    assert "client-side" in client[0].rule
    server = scan_text("server.py", f'GOOGLE_MAPS_SERVER_KEY = "{key}"\n')
    assert [f.severity for f in server] == ["high"]


def test_gitignored_secret_file_is_informational(tmp_path):
    write(tmp_path, ".gitignore", ".env\nsecrets/\n")
    write(tmp_path, "secrets/admin.json", '{"private_key": "-----BEGIN PRIVATE KEY-----"}\n')
    write(tmp_path, "config.py", 'API_SECRET = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"\n')
    by_file = {f.endpoint.split(":")[0]: f for f in types(tmp_path)}
    assert by_file["secrets/admin.json"].status is FindingStatus.INFORMATIONAL
    assert "ignored by git" in (by_file["secrets/admin.json"].status_reason or "")
    assert by_file["config.py"].status is FindingStatus.LIKELY  # committed code: still a finding


def test_gitignore_matching_semantics():
    gi = GitIgnore("*.log\n/build\nsecrets/\n!keep.log\n# comment\n**/cache/\n")
    assert gi.is_ignored("app/debug.log")
    assert not gi.is_ignored("keep.log")
    assert gi.is_ignored("build/out.js") and not gi.is_ignored("src/build/out.js")
    assert gi.is_ignored("secrets/a/b.json")
    assert gi.is_ignored("x/y/cache/z.txt")
    assert not gi.is_ignored("src/main.py")


# ------------------------------------------------------------------ authorization


def test_router_level_dependencies_guard_every_route_on_it():
    src = textwrap.dedent(
        """
        from fastapi import APIRouter, Depends
        router = APIRouter(prefix="/cats", dependencies=[Depends(verify_cat_owner)])

        @router.post("/{cat_id}/log")
        async def log(cat_id: int):
            return 1

        @router.delete("/{cat_id}")
        async def remove(cat_id: int):
            return 1
        """
    )
    routes = extract_routes("routes/cats.py", src)
    assert len(routes) == 2 and all(r.protected for r in routes)
    assert routes[0].guard == "verify_cat_owner"


def test_route_level_dependency_with_a_non_auth_name_is_still_a_guard():
    src = textwrap.dedent(
        """
        @router.post("/x", dependencies=[Depends(check_membership)])
        async def x():
            return 1

        @router.post("/y", dependencies=[Depends(get_db)])
        async def y():
            return 1
        """
    )
    guarded = {r.path: r.protected for r in extract_routes("a.py", src)}
    assert guarded == {"/x": True, "/y": False}  # get_db is plumbing, not a guard


def test_include_router_dependencies_protect_the_included_module(tmp_path):
    write(
        tmp_path,
        "app/routes/cats.py",
        """
        from fastapi import APIRouter
        router = APIRouter()

        @router.post("/{cat_id}/weight")
        async def weight(cat_id: int):
            return 1
        """,
    )
    write(
        tmp_path,
        "app/main.py",
        """
        from fastapi import Depends, FastAPI
        from app.routes import cats
        app = FastAPI()
        app.include_router(cats.router, dependencies=[Depends(require_user)])
        """,
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    cats = [r for r in result.routes if r.relpath.endswith("cats.py")]
    assert cats and all(r.protected for r in cats)
    assert not any("weight" in f.title for f in result.route_findings)


def test_unrelated_include_router_does_not_hide_an_unguarded_route(tmp_path):
    write(
        tmp_path,
        "app/routes/billing.py",
        """
        from fastapi import APIRouter
        router = APIRouter()

        @router.post("/charge")
        async def charge():
            return 1
        """,
    )
    write(
        tmp_path,
        "app/main.py",
        """
        from fastapi import Depends, FastAPI
        from app.routes import cats
        app = FastAPI()
        app.include_router(cats.router, dependencies=[Depends(require_user)])
        """,
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    billing = [r for r in result.routes if r.relpath.endswith("billing.py")]
    assert billing and not billing[0].protected


def _route(method: str, path: str, protected: bool) -> Route:
    return Route(method, path, "python", "a.py", 1, "h", protected, "g" if protected else None)


def test_public_reads_with_guarded_writes_are_not_outliers():
    routes = [
        _route("POST", "/products", True),
        _route("PUT", "/products/{id}", True),
        _route("DELETE", "/products/{id}", True),
        _route("GET", "/products/barcode/{code}", False),
    ]
    assert authz_outliers(routes) == []


def test_unguarded_read_is_an_outlier_when_other_reads_are_guarded():
    routes = [
        _route("GET", "/orders", True),
        _route("GET", "/orders/{id}", True),
        _route("POST", "/orders", True),
        _route("GET", "/orders/{id}/invoice", False),
    ]
    flagged = authz_outliers(routes)
    assert len(flagged) == 1 and "/orders/{id}/invoice" in flagged[0].rule


# ------------------------------------------------------------------ injection sinks


def test_request_body_is_not_ssrf_but_the_url_is():
    body_only = textwrap.dedent(
        """
        @app.post("/gen")
        def gen(prompt: str):
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate", data=json.dumps({"prompt": prompt}).encode()
            )
            return urllib.request.urlopen(req)

        @app.post("/gen2")
        def gen2(prompt: str):
            return urllib.request.urlopen(
                urllib.request.Request(f"{OLLAMA_URL}/api/generate", data=prompt.encode())
            )
        """
    )
    assert "ssrf" not in {f.vuln_type for f in analyze_taint("a.py", body_only)}
    url_tainted = textwrap.dedent(
        """
        @app.get("/fetch")
        def fetch(url: str):
            return urllib.request.urlopen(urllib.request.Request(url, data=b"x"))
        """
    )
    assert "ssrf" in {f.vuln_type for f in analyze_taint("a.py", url_tainted)}


def test_regexp_exec_is_not_command_injection():
    js = textwrap.dedent(
        """
        const m = /<x-dc[^>]*>/.exec(src);
        const r = pattern.exec(line);
        db.exec("CREATE TABLE t (id)");
        """
    )
    assert [f for f in scan_sinks("app.js", js) if f.category == "command_injection"] == []


def test_child_process_exec_is_still_command_injection():
    js = textwrap.dedent(
        """
        const { exec } = require("child_process");
        exec("ls " + req.query.dir, cb);
        """
    )
    assert any(f.category == "command_injection" for f in scan_sinks("app.js", js))
    qualified = 'const cp = require("child_process");\ncp.exec(cmd);\n'
    assert any(f.category == "command_injection" for f in scan_sinks("a.js", qualified))
    # `exec(` in a file that never touches child_process is something else
    assert not scan_sinks("lib.js", "function exec(x) { return x; }\nexec(1);\n")


def test_stdlib_xml_is_entity_expansion_not_xxe():
    py = "import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)\n"
    out = scan_sinks("a.py", py)
    assert [f.category for f in out] == ["xml_entity_expansion"] and out[0].severity == "low"
    lxml = "from lxml import etree\nroot = etree.fromstring(data)\n"
    assert [f.category for f in scan_sinks("a.py", lxml)] == ["xxe"]


# ------------------------------------------------------------------ ingestion


def test_generated_bundles_and_dev_output_are_skipped(tmp_path):
    bad = "app.get('/x', (req, res) => { new Function(req.query.code)(); });\n"
    write(tmp_path, "dev-dist/workbox-aeb6ecaf.js", bad)
    write(tmp_path, "static/app.min.js", bad)
    write(tmp_path, "static/vendor-1a2b3c4d5e.js", bad)
    write(tmp_path, "src/real.js", "const x = 1;\n")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert result.stats.files_scanned == 1
    assert result.stats.skipped_generated >= 1  # the hashed bundle; .min.js counts as binary
    assert result.total_findings == 0


def test_db_wrapper_passthrough_is_downgraded_but_a_handler_sink_is_not():
    wrapper = textwrap.dedent(
        """
        async def run(query, *args):
            async with pool.acquire() as conn:
                return await conn.execute(query, *args)

        @app.get("/items")
        async def items(q: str):
            return await run(f"SELECT * FROM t WHERE name = '{q}'")
        """
    )
    found = [f for f in analyze_taint("db.py", wrapper) if f.vuln_type == "sql_injection"]
    wrapper_hit = next(f for f in found if f.line == 4)
    assert wrapper_hit.severity == "medium" and wrapper_hit.confidence < 0.5
    assert "arrives from callers" in wrapper_hit.evidence

    direct = textwrap.dedent(
        """
        @app.get("/items")
        async def items(q: str, conn):
            return await conn.execute("SELECT * FROM t WHERE name = '" + q + "'")
        """
    )
    (hit,) = [f for f in analyze_taint("a.py", direct) if f.vuln_type == "sql_injection"]
    assert hit.severity == "high" and hit.confidence >= 0.7


def test_ownership_enforced_inside_the_handler_counts_as_a_guard():
    src = textwrap.dedent(
        """
        @router.put("/visits/{visit_id}")
        async def update_visit(visit_id: int, user=Depends(get_current_user_optional)):
            visit = await load(visit_id)
            if visit.owner_id != user.id:
                raise HTTPException(status_code=404)
            return visit

        @router.post("/cats/{cat_id}/log")
        async def log(cat_id: int):
            cat = await _get_owned_cat(cat_id)
            return cat

        @router.post("/cats/{cat_id}/weight")
        async def weight(cat_id: int, cat=Depends(get_owned_cat)):
            return cat

        @router.delete("/notes/{note_id}")
        async def remove(note_id: int):
            raise HTTPException(status_code=403, detail="no")

        @router.post("/open")
        async def open_route(data: dict):
            return data
        """
    )
    guarded = {r.path: r.protected for r in extract_routes("routes.py", src)}
    assert guarded == {
        "/visits/{visit_id}": True,
        "/cats/{cat_id}/log": True,
        "/cats/{cat_id}/weight": True,
        "/notes/{note_id}": True,
        "/open": False,  # nothing checks anything: still reported
    }


def test_subprocess_check_output_is_not_mistaken_for_an_access_check():
    src = textwrap.dedent(
        """
        @app.get("/ping")
        def ping(h):
            return subprocess.check_output(["ping", h])
        """
    )
    (route,) = extract_routes("app.py", src)
    assert route.protected is False


# --------------------------------------------- config-driven queries (OpenCode run)

CONFIG_DRIVEN = """
    import sqlite3
    from flask import Flask, request, abort, jsonify
    app = Flask(__name__)
    DATASETS = {"funds": {"table": "funds", "cols": ["name", "amount"], "search": ["name"]}}

    def _cfg(name):
        cfg = DATASETS.get(name)
        if cfg is None:
            abort(404)
        return cfg

    def parse_sort(cfg, default="name"):
        col = request.args.get("sort", default)
        if col not in cfg["cols"]:
            col = default
        direction = "DESC" if request.args.get("dir") == "desc" else "ASC"
        return col, direction

    @app.route("/<name>/data")
    def data(name):
        cfg = _cfg(name)
        col, direction = parse_sort(cfg)
        q = request.args.get("q", "")
        sql = f"SELECT * FROM {cfg['table']} WHERE name LIKE ? ORDER BY {col} {direction}"
        return jsonify(sqlite3.connect("x").execute(sql, [q]).fetchall())
"""


def _sqli(source: str) -> list:
    return [
        f
        for f in analyze_taint("app.py", textwrap.dedent(source))
        if f.vuln_type == "sql_injection"
    ]


def test_config_selected_by_request_value_is_not_request_data():
    """A dataset name picks an entry from a constant table; table/column names then come from it,
    the sort column is allow-listed and the direction is one of two literals."""
    assert _sqli(CONFIG_DRIVEN) == []


def test_the_nearest_real_variants_are_still_reported():
    # the column is NOT validated: the allow-list reset assigns request data, not a constant
    unvalidated = CONFIG_DRIVEN.replace("col = default", "col = request.args.get('fallback')")
    assert _sqli(unvalidated)
    # no allow-list at all
    no_check = CONFIG_DRIVEN.replace(
        '        if col not in cfg["cols"]:\n            col = default\n', ""
    )
    assert _sqli(no_check)
    # the "constant" table is mutated from request data, so it is not constant
    mutated = CONFIG_DRIVEN.replace(
        '    @app.route("/<name>/data")',
        '    DATASETS["funds"] = {"table": request.args.get("t"), "cols": [], "search": []}\n\n'
        '    @app.route("/<name>/data")',
    )
    assert _sqli(mutated)
    # a local helper that passes request data through is still tainted
    passthrough = CONFIG_DRIVEN.replace(
        "        return cfg\n", "        return request.args.get('table')\n"
    )
    assert _sqli(passthrough)


# A real report (2026-10-14): CONFIG_DRIVEN never uses the raw `name` parameter itself as the SQL
# table -- only derived values (`cfg['table']`, `col`, `direction`). This project used `name`
# directly after validating it with a separate helper, `_cfg`, that looks it up in a constant dict
# and aborts on a miss -- the scanner's taint tracking missed that cross-function allow-list guard
# and reported 8 false-positive "high" SQL injections.
DATASET_NAME_AS_TABLE = """
    import sqlite3
    from flask import Flask, request, abort, jsonify
    app = Flask(__name__)
    DATASETS = {"brokers": {"cols": ["name"]}, "targets": {"cols": ["name"]}}

    def _cfg(name):
        cfg = DATASETS.get(name)
        if not cfg:
            abort(404)
        return cfg

    @app.route("/<name>/")
    def listing(name):
        cfg = _cfg(name)
        rows = sqlite3.connect("x").execute(f"SELECT * FROM {name}").fetchall()
        return jsonify(rows)
"""


def test_dataset_name_used_directly_after_a_validator_call_is_not_request_data():
    assert _sqli(DATASET_NAME_AS_TABLE) == []


def test_without_the_validator_call_the_same_pattern_is_still_reported():
    unguarded = DATASET_NAME_AS_TABLE.replace("        cfg = _cfg(name)\n", "")
    assert _sqli(unguarded)


def test_a_validator_that_does_not_abort_does_not_guard_anything():
    # `_cfg` returns None silently instead of aborting: a bad `name` reaches the sink unchanged.
    silent = DATASET_NAME_AS_TABLE.replace("        if not cfg:\n            abort(404)\n", "")
    assert _sqli(silent)


# Another real report (2026-10-14): the allow-list reset for an ORDER BY column read its default
# from a validated config object (`cfg["default_sort"][0]`), not a literal -- `_resets_to_default`
# only recognised a literal or a constant-default parameter, so `sort` stayed "tainted" and the
# finding was reported even though every path through `parse_sort` leaves it allow-listed.
SORT_RESET_FROM_CONFIG = """
    import sqlite3
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    def parse_sort(cfg):
        sortable = {"name", "price"}
        sort = request.args.get("sort")
        if sort not in sortable:
            sort = cfg["default_sort"][0]
        return sort

    @app.route("/data")
    def data():
        cfg = {"default_sort": ["name"]}
        sort = parse_sort(cfg)
        rows = sqlite3.connect("x").execute(f"SELECT * FROM t ORDER BY {sort}").fetchall()
        return jsonify(rows)
"""


def test_reset_to_a_value_derived_from_another_parameter_is_not_request_data():
    assert _sqli(SORT_RESET_FROM_CONFIG) == []


def test_reset_to_request_data_itself_is_still_reported():
    tainted_default = SORT_RESET_FROM_CONFIG.replace(
        'sort = cfg["default_sort"][0]', 'sort = request.args.get("fallback")'
    )
    assert _sqli(tainted_default)


# Another real report (2026-10-14): a helper returning `(where, params)` where `params`
# legitimately carries request data for bound `?` placeholders and `where` (the SQL text) is built
# only from safe config -- the whole tuple was treated as tainted because *one* element was,
# flagging the (safe) `where` usage.
TUPLE_RETURN_MIXED_SAFETY = """
    import sqlite3
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    def build_where(cfg, q):
        where = "WHERE col = " + cfg["literal"]
        params = []
        if q:
            params.append(q)
        return where, params

    @app.route("/data")
    def data():
        cfg = {"literal": "1"}
        q = request.args.get("q")
        where, params = build_where(cfg, q)
        rows = sqlite3.connect("x").execute(f"SELECT * FROM t {where}", params).fetchall()
        return jsonify(rows)
"""


def test_a_safe_element_of_a_tuple_return_is_not_tainted_by_its_sibling():
    assert _sqli(TUPLE_RETURN_MIXED_SAFETY) == []


def test_the_actually_tainted_element_of_the_same_tuple_is_still_reported():
    # `where` itself now carries `q` directly: the real injection the mixed-safety case is not.
    leaky = TUPLE_RETURN_MIXED_SAFETY.replace(
        'where = "WHERE col = " + cfg["literal"]', 'where = "WHERE col = " + q'
    )
    assert _sqli(leaky)
