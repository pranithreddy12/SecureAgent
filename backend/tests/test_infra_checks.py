"""Infrastructure and bulk-endpoint checks (gap found in an assistant's review, 2026-10-13)."""

from __future__ import annotations

from app.analysis.guidance import DEFAULT, guidance_for
from app.analysis.misconfig import CATEGORY, scan_misconfig


def cats(relpath: str, text: str) -> list[str]:
    return [f.category for f in scan_misconfig(relpath, text)]


def test_dockerfile_final_stage_root_or_missing_user():
    assert cats("Dockerfile", "FROM python:3.12\nCMD x\n") == ["container_runs_as_root"]
    assert cats("Dockerfile", "FROM a\nUSER root\n") == ["container_runs_as_root"]
    assert cats("Dockerfile", "FROM a\nUSER appuser\n") == []
    assert cats("docker/backend.Dockerfile", "FROM a\nRUN x\nUSER 1000:1000\n") == []
    # only the FINAL stage counts: a root build stage is normal
    multi = "FROM node AS build\nRUN npm ci\nFROM nginx\nUSER nginx\n"
    assert cats("Dockerfile", multi) == []
    assert cats("Dockerfile", "FROM a\nUSER app\nFROM b\nCMD x\n") == ["container_runs_as_root"]


def test_compose_root_and_privileged():
    text = "services:\n  a:\n    user: root\n  b:\n    privileged: true\n  c:\n    user: '1000'\n"
    assert sorted(cats("docker-compose.yml", text)) == [
        "container_runs_as_root",
        "privileged_container",
    ]
    assert cats("compose.yaml", 'services:\n  a:\n    user: "0:0"\n') == ["container_runs_as_root"]
    assert cats("docker-compose.yml", "services:\n  a:\n    user: appuser\n") == []
    assert cats("settings.yml", "user: root\n") == []  # not a compose file


def test_csp_unsafe_inline_only_for_scripts():
    inline = "H = \"default-src 'self'; script-src 'self' 'unsafe-inline'\"\n"
    assert cats("app.py", inline) == ["csp_unsafe_inline"]
    assert cats("server.js", "csp = \"default-src 'unsafe-inline'\"") == ["csp_unsafe_inline"]
    style_only = "H = \"default-src 'self'; style-src 'self' 'unsafe-inline'\"\n"
    assert cats("app.py", style_only) == []


def test_unbounded_bulk_endpoint_flagged_but_bounded_or_ordinary_is_not():
    bulk = (
        "@app.route('/export.csv')\n"
        "def export():\n"
        "    return db.execute('SELECT * FROM t').fetchall()\n"
    )
    assert cats("app.py", bulk) == ["unbounded_query"]
    bounded = bulk.replace("FROM t'", "FROM t LIMIT 1000'")
    assert cats("app.py", bounded) == []
    paged = bulk.replace("fetchall()", "fetchall()[:100]")
    assert cats("app.py", paged) == []
    ordinary = bulk.replace("/export.csv", "/items").replace("def export", "def items")
    assert cats("app.py", ordinary) == []
    not_a_route = bulk.replace("@app.route('/export.csv')\n", "")
    assert cats("app.py", not_a_route) == []


def test_k8s_privileged_root_and_host_namespace():
    manifest = (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      hostNetwork: true\n"
        "      containers:\n"
        "        - securityContext:\n"
        "            privileged: true\n"
        "            runAsUser: 0\n"
        "            allowPrivilegeEscalation: true\n"
    )
    found = sorted(cats("deploy.yaml", manifest))
    assert found == [
        "container_runs_as_root",
        "k8s_host_namespace",
        "privileged_container",
        "privileged_container",
    ]
    # not a k8s manifest (no apiVersion/kind) -- a plain compose-shaped line is ignored here
    assert cats("settings.yaml", "privileged: true\n") == []


def test_terraform_public_bucket_open_ingress_and_credential():
    tf = (
        'resource "aws_s3_bucket" "data" {\n'
        '  acl = "public-read"\n'
        "}\n"
        'resource "aws_security_group" "web" {\n'
        "  ingress {\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "  egress {\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        'provider "aws" {\n'
        '  secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"\n'
        "}\n"
    )
    found = cats("main.tf", tf)
    assert found.count("tf_public_bucket") == 1
    assert found.count("tf_open_ingress") == 1  # not the egress block
    assert found.count("tf_hardcoded_credential") == 1
    # a reference, not a literal, is not a credential finding
    assert cats("main.tf", 'secret_key = "${var.secret_key}"\n') == []


def test_every_misconfig_category_has_guidance():
    for category in CATEGORY:
        assert guidance_for(category) is not DEFAULT, category
