"""Workflow-order detector: terminal state set without checking the current state."""

from __future__ import annotations

import textwrap

from app.analysis.workflow import analyze_workflow


def _find(src: str):
    return analyze_workflow("app.py", textwrap.dedent(src))


def test_terminal_state_without_precondition_is_flagged():
    (f,) = _find(
        """
        @app.post("/orders/<oid>/ship")
        def ship(oid):
            order = Order.query.get(oid)
            order.status = "shipped"
            db.commit()
        """
    )
    assert f.category == "workflow_order"
    assert f.field == "status"
    assert f.confidence == 0.5  # name/path look like a finalizing step
    assert f.line == 5


def test_enum_value_and_boolean_flag_are_terminal():
    assert _find(
        """
        @app.post("/x")
        def x():
            o.status = OrderStatus.PAID
        """
    )
    assert _find(
        """
        @app.post("/x")
        def x():
            o.is_paid = True
        """
    )


def test_state_comparison_in_condition_counts_as_precondition():
    assert not _find(
        """
        @app.post("/orders/<oid>/ship")
        def ship(oid):
            order = Order.query.get(oid)
            if order.status != "paid":
                abort(409)
            order.status = "shipped"
        """
    )


def test_assert_guard_helper_and_conditional_update_are_preconditions():
    assert not _find(
        """
        @app.post("/a")
        def a():
            assert order.status == "paid"
            order.status = "shipped"
        """
    )
    assert not _find(
        """
        @app.post("/b")
        def b():
            ensure_can_ship(order)
            order.status = "shipped"
        """
    )
    assert not _find(
        """
        @app.post("/c")
        def c():
            Order.query.filter_by(id=1, status="paid").update(status="shipped")
        """
    )


def test_non_terminal_values_and_non_handlers_are_ignored():
    assert not _find(
        """
        @app.post("/a")
        def a():
            order.status = "draft"
        """
    )
    assert not _find(
        """
        def helper(order):
            order.status = "shipped"
        """
    )


def test_one_finding_per_handler():
    out = _find(
        """
        @app.post("/a")
        def a():
            o.status = "paid"
            o.shipped = True
        """
    )
    assert len(out) == 1


def test_scan_reports_workflow_order(tmp_path):
    from app.analysis.scanner import scan_repo

    (tmp_path / "app.py").write_text(
        "@app.post('/pay')\n@login_required\ndef pay():\n    order.status = 'paid'\n",
        encoding="utf-8",
    )
    r = scan_repo(str(tmp_path), check_osv=False)
    assert [f.category for f in r.logic_findings] == ["workflow_order"]
