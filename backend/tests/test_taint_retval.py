"""Tests for return-value taint: a local helper that returns attacker-influenced data."""

from __future__ import annotations

from app.analysis.taint import analyze_taint


def vtypes(src: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("m.py", src)}


READS_REQUEST = """
from flask import request
import os

def get_host():
    return request.args.get("host")      # helper itself reads request input

@app.route("/ping")
def ping():
    host = get_host()                     # no tainted args passed in
    os.system("ping " + host)
"""

DERIVES_FROM_ARG = """
import os
def wrap(x):
    return "ping " + x

@app.route("/ping")
def ping(host):
    cmd = wrap(host)                      # tainted arg flows through the return value
    os.system(cmd)
"""

CONSTANT_RETURN = """
import os
def get_host():
    return "localhost"                    # constant: not attacker controlled

@app.route("/ping")
def ping():
    host = get_host()
    os.system("ping " + host)
"""

TWO_HOPS = """
from flask import request
import os
def inner():
    return request.args.get("c")
def outer():
    return inner()
@app.route("/x")
def h():
    c = outer()
    os.system(c)
"""

NESTED_IN_SINK = """
from flask import request
import os
def get_cmd():
    return request.args.get("c")
@app.route("/x")
def h():
    os.system(get_cmd())                  # call result used directly as sink argument
"""

RECURSIVE = """
import os
def loop(n):
    return loop(n)                        # self-recursion must terminate
@app.route("/x")
def h():
    os.system(loop("a"))
"""


def test_helper_that_reads_request_input() -> None:
    assert "command_injection" in vtypes(READS_REQUEST)


def test_taint_flows_through_return_value() -> None:
    assert "command_injection" in vtypes(DERIVES_FROM_ARG)


def test_constant_return_is_not_tainted() -> None:
    assert "command_injection" not in vtypes(CONSTANT_RETURN)


def test_two_hop_return_chain() -> None:
    assert "command_injection" in vtypes(TWO_HOPS)


def test_call_result_used_directly_in_sink() -> None:
    assert "command_injection" in vtypes(NESTED_IN_SINK)


def test_recursion_terminates_without_finding() -> None:
    assert "command_injection" not in vtypes(RECURSIVE)


def test_reported_at_the_sink_line() -> None:
    findings = [
        f for f in analyze_taint("m.py", READS_REQUEST) if f.vuln_type == "command_injection"
    ]
    assert findings and findings[0].line == 11
