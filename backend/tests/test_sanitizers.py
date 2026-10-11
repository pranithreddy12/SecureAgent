"""Sanitizer modelling in taint analysis: casts, quoting helpers and allow-list guards."""

from __future__ import annotations

import textwrap

from app.analysis.access_control import analyze_access_control
from app.analysis.taint import analyze_taint


def _types(src: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("app.py", textwrap.dedent(src))}


def test_numeric_cast_neutralises_sql_injection():
    assert "sql_injection" not in _types(
        """
        @app.get("/u")
        def u():
            uid = int(request.args["id"])
            cur.execute("SELECT * FROM t WHERE id = " + str(uid))
        """
    )


def test_cast_inline_in_the_sink_argument():
    assert "sql_injection" not in _types(
        """
        @app.get("/u")
        def u():
            cur.execute("SELECT * FROM t WHERE id = %d" % int(request.args["id"]))
        """
    )


def test_uncast_value_is_still_flagged():
    assert "sql_injection" in _types(
        """
        @app.get("/u")
        def u():
            uid = request.args["id"]
            cur.execute("SELECT * FROM t WHERE id = " + uid)
        """
    )


def test_cast_of_one_value_does_not_clean_another():
    assert "sql_injection" in _types(
        """
        @app.get("/u")
        def u():
            limit = int(request.args["limit"])
            name = request.args["name"]
            cur.execute("SELECT * FROM t WHERE n = '" + name + "' LIMIT " + str(limit))
        """
    )


def test_shell_quote_and_secure_filename():
    assert "command_injection" not in _types(
        """
        @app.get("/p")
        def p():
            host = shlex.quote(request.args["host"])
            os.system("ping " + host)
        """
    )
    assert "path_traversal" not in _types(
        """
        @app.get("/d")
        def d():
            name = secure_filename(request.args["f"])
            return open("/srv/files/" + name).read()
        """
    )


def test_allowlist_early_exit_guard():
    assert "ssrf" not in _types(
        """
        @app.get("/f")
        def f():
            host = request.args["host"]
            if host not in ALLOWED_HOSTS:
                return "denied", 403
            return requests.get("https://" + host).text
        """
    )


def test_guard_on_a_different_variable_does_not_help():
    assert "ssrf" in _types(
        """
        @app.get("/f")
        def f():
            host = request.args["host"]
            other = request.args["other"]
            if other not in ALLOWED_HOSTS:
                return "denied", 403
            return requests.get("https://" + host).text
        """
    )


def test_membership_check_without_exit_is_not_a_guard():
    assert "ssrf" in _types(
        """
        @app.get("/f")
        def f():
            host = request.args["host"]
            if host not in ALLOWED_HOSTS:
                log.warning("unexpected host")
            return requests.get("https://" + host).text
        """
    )


def test_assert_membership_guard():
    assert "ssrf" not in _types(
        """
        @app.get("/f")
        def f():
            host = request.args["host"]
            assert host in ALLOWED_HOSTS
            return requests.get("https://" + host).text
        """
    )


def test_idor_is_not_cleared_by_a_cast():
    # int(order_id) cannot inject, but the *client still chooses which record* -- still an IDOR.
    src = textwrap.dedent(
        """
        @app.route("/orders/<order_id>")
        def get_order(order_id):
            return str(Order.query.get_or_404(int(order_id)))
        """
    )
    assert analyze_access_control("app.py", src)


def test_bare_shell_sink_is_quiet_for_constant_or_quoted_commands():
    from app.analysis.sinks import scan_sinks

    def kinds(src: str) -> set[str]:
        return {f.category for f in scan_sinks("app.py", textwrap.dedent(src))}

    assert "command_injection" not in kinds('os.system("ls -la")\n')
    assert "command_injection" not in kinds('os.system("ping " + shlex.quote(host))\n')
    assert "command_injection" not in kinds('subprocess.run("ls " + "-la", shell=True)\n')
    assert "command_injection" in kinds('os.system("ping " + host)\n')
    assert "command_injection" in kinds("os.system(cmd)\n")
    assert "command_injection" in kinds('subprocess.run(f"ping {host}", shell=True)\n')


def test_quoted_variable_is_scoped_to_its_function():
    from app.analysis.sinks import scan_sinks

    src = textwrap.dedent(
        """
        def safe(raw):
            host = shlex.quote(raw)
            os.system("ping " + host)

        def unsafe(raw):
            host = raw
            os.system("ping " + host)
        """
    )
    lines = sorted(f.line for f in scan_sinks("app.py", src) if f.category == "command_injection")
    assert lines == [8]  # only the function that did not quote
