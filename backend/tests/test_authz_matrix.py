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
