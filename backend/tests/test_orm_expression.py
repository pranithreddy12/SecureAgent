"""Parameterised SQLAlchemy expressions are not SQL injection; raw text() still is."""

from app.analysis.routes import extract_routes
from app.analysis.taint import analyze_taint


def _types(src: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("app.py", src)}


def test_select_with_tainted_value_is_parameterised():
    src = (
        "@app.get('/x')\n"
        "async def x(name, db):\n"
        "    return await db.execute(select(User).where(User.name == name))\n"
    )
    assert "sql_injection" not in _types(src)


def test_text_inside_select_with_tainted_value_is_still_flagged():
    src = (
        "@app.get('/x')\n"
        "async def x(name, db):\n"
        "    return await db.execute(select(User).where(text(f\"n = '{name}'\")))\n"
    )
    assert "sql_injection" in _types(src)


def test_string_built_query_is_still_flagged():
    src = (
        "@app.get('/x')\n"
        "def x(name, db):\n"
        "    return db.execute('SELECT * FROM t WHERE n = ' + name)\n"
    )
    assert "sql_injection" in _types(src)


def test_fastapi_current_user_alias_counts_as_a_guard():
    src = (
        "@router.post('/source')\nasync def create(data: Body, user: CurrentUser):\n    return 1\n"
    )
    (route,) = extract_routes("api.py", src)
    assert route.protected is True
