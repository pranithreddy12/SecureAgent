"""Authorization matrix: outliers among sibling routes (ADR-010)."""

from app.analysis.authz_matrix import authz_outliers, build_matrix, resource_of
from app.analysis.routes import Route


def r(method, path, protected, guard=None, handler="h"):
    return Route(method, path, "python", "app.py", 1, handler, protected, guard)


def test_resource_of_skips_params_and_empty_segments():
    assert resource_of("/orders/<id>") == "orders"
    assert resource_of("/{tenant}/Orders") == "orders"
    assert resource_of("/") == "/"


def test_unguarded_sibling_is_flagged():
    routes = [
        r("GET", "/orders", True, "login_required"),
        r("GET", "/orders/<id>", True, "login_required"),
        r("POST", "/orders", True, "login_required"),
        r("DELETE", "/orders/<id>", False),
    ]
    out = authz_outliers(routes)
    assert len(out) == 1
    assert out[0].category == "inconsistent_authorization"
    assert out[0].severity == "high"
    assert "3 of 4" in out[0].rule


def test_all_guarded_or_all_open_is_not_a_pattern():
    guarded = [r("GET", f"/a/{i}", True, "g") for i in range(4)]
    opened = [r("GET", f"/b/{i}", False) for i in range(4)]
    assert authz_outliers(guarded + opened) == []


def test_minority_guarded_is_not_flagged():
    routes = [r("GET", "/x", True, "g")] + [r("GET", f"/x/{i}", False) for i in range(4)]
    assert authz_outliers(routes) == []


def test_small_groups_and_public_resources_are_ignored():
    small = [r("GET", "/pay", True, "g"), r("POST", "/pay", False)]
    public = [
        r("GET", "/login", True, "g"),
        r("GET", "/login/a", True, "g"),
        r("GET", "/login/b", True, "g"),
        r("POST", "/login", False),
    ]
    assert authz_outliers(small + public) == []


def test_matrix_groups_by_resource():
    g = build_matrix([r("GET", "/a", True, "g"), r("GET", "/b", False), r("POST", "/a", True, "g")])
    assert {x.resource: x.guarded for x in g} == {"a": 2, "b": 0}


def test_cli_matrix_flag_prints_grid(tmp_path, capsys):
    from app.cli import main

    (tmp_path / "app.py").write_text(
        "@app.route('/a')\n@login_required\ndef a():\n    return 1\n"
        "@app.route('/b', methods=['POST'])\ndef b():\n    return 1\n",
        encoding="utf-8",
    )
    main(["scan", str(tmp_path), "--no-osv", "--matrix", "--no-color"])
    out = capsys.readouterr().out
    assert "Authorization matrix" in out
    assert "guarded  GET     /a" in out
    assert "OPEN     POST    /b" in out


def test_specific_finding_supersedes_generic_unguarded_route_finding(tmp_path):
    from app.analysis.scanner import scan_repo

    (tmp_path / "app.py").write_text(
        "@app.route('/p')\n@login_required\ndef a():\n    return 1\n"
        "@app.route('/p/1')\n@login_required\ndef b():\n    return 1\n"
        "@app.route('/p', methods=['POST'])\n@login_required\ndef c():\n    return 1\n"
        "@app.route('/p/2', methods=['DELETE'])\ndef d():\n    return 1\n",
        encoding="utf-8",
    )
    r = scan_repo(str(tmp_path), check_osv=False)
    assert [f.category for f in r.logic_findings] == ["inconsistent_authorization"]
    assert r.route_findings == []  # the generic finding on the same route was merged
    assert r.superseded == 1


def test_report_context_carries_the_matrix(tmp_path):
    from app.analysis.reporting import scan_to_report_context
    from app.analysis.scanner import scan_repo
    from app.reports.renderer import render_html

    (tmp_path / "app.py").write_text(
        "@app.route('/a')\n@login_required\ndef a():\n    return 1\n", encoding="utf-8"
    )
    ctx = scan_to_report_context(scan_repo(str(tmp_path), check_osv=False))
    assert ctx.authorization_matrix[0].resource == "a"
    assert "Authorization matrix" in render_html(ctx)


def test_public_collection_listing_is_not_an_outlier_but_object_access_is():
    guarded = [r("POST", "/catalog", True, "g"), r("PUT", "/catalog/<id>", True, "g")]
    public_list = r("GET", "/catalog", False)
    public_item = r("GET", "/catalog/<id>", False)
    assert authz_outliers([*guarded, r("DELETE", "/catalog/<id>", True, "g"), public_list]) == []
    flagged = authz_outliers([*guarded, r("DELETE", "/catalog/<id>", True, "g"), public_item])
    assert len(flagged) == 1 and "/catalog/<id>" in flagged[0].rule
