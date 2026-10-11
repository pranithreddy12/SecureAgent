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
