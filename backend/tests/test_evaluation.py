"""The evaluation harness: sampling, redaction and honest scoring."""

from __future__ import annotations

import json
from pathlib import Path

from app.evaluation import main, prepare, render, score

VULN = (
    "import hashlib, subprocess\n"
    "from flask import request\n"
    "KEY = 'AKIAABCDEFGHIJKLMNOP'\n"
    "def a():\n    hashlib.md5(b'1')\n"
    "def b():\n    hashlib.md5(b'2')\n"
    "def c():\n    hashlib.md5(b'3')\n"
    "@app.route('/x')\n"
    "def x():\n    subprocess.run(request.args['c'], shell=True)\n"
)


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "app.py").write_text(VULN, encoding="utf-8")
    return repo


def test_prepare_samples_per_type_redacts_and_leaves_labels_blank(tmp_path):
    repo = make_repo(tmp_path)
    out = tmp_path / "out"
    data = prepare([str(repo)], str(out), per_type=2)
    by_type: dict[str, int] = {}
    for it in data["items"]:
        by_type[it["type"]] = by_type.get(it["type"], 0) + 1
        assert it["label"] is None and it["excerpt"]
    assert by_type["weak_hash"] == 2  # three exist, the cap is two
    assert data["repos"][0]["findings_reviewable"] >= 4
    text = (out / "labels.json").read_text(encoding="utf-8")
    assert "AKIAABCDEFGHIJKLMNOP" not in text  # secrets never reach the sheet


def test_score_counts_only_labelled_items_and_reports_unsure_and_todo(tmp_path):
    repo = make_repo(tmp_path)
    data = prepare([str(repo)], str(tmp_path / "out"), per_type=5)
    items = data["items"]
    items[0]["label"] = "true"
    items[1]["label"] = "false"
    items[2]["label"] = "unsure"
    path = tmp_path / "out" / "labels.json"
    data["labelled_by"] = "reviewer"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = score(str(path))
    t = result["totals"]
    assert (t["true"], t["false"], t["unsure"]) == (1, 1, 1)
    assert t["unlabelled"] == len(items) - 3
    assert result["precision"] == 0.5  # unsure and unlabelled are excluded, not counted as wins
    assert "not a population rate" in render(result)


def test_recall_estimate_from_extras(tmp_path):
    repo = make_repo(tmp_path)
    data = prepare([str(repo)], str(tmp_path / "o"), per_type=1)
    for it in data["items"][:2]:
        it["label"] = "true"
    data["extras"] = [
        {
            "repo": "proj",
            "location": "app.py:1",
            "description": "found by both",
            "found_by_tool": True,
        },
        {
            "repo": "proj",
            "location": "app.py:9",
            "description": "tool missed this",
            "found_by_tool": False,
        },
        {
            "repo": "proj",
            "location": "",
            "description": "",
            "found_by_tool": False,
        },  # blank: ignored
    ]
    path = tmp_path / "o" / "labels.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    r = score(str(path))
    assert r["known_true"] == 4 and len(r["missed"]) == 1
    assert r["recall_estimate"] == 0.75


def test_cli_prepare_and_score_round_trip(tmp_path, capsys):
    repo = make_repo(tmp_path)
    assert main(["prepare", str(repo), "--out", str(tmp_path / "e")]) == 0
    assert main(["score", str(tmp_path / "e" / "labels.json")]) == 0
    assert "ALL (stratified sample)" in capsys.readouterr().out
    assert main(["prepare", str(tmp_path / "missing"), "--out", str(tmp_path / "z")]) == 2


def test_labelling_page_embeds_findings_and_escapes_script_end(tmp_path):
    from app.evaluation import render_labelling_page

    data = {
        "items": [
            {
                "id": "ab12",
                "type": "sql_injection",
                "repo": "r",
                "location": "a.py:1",
                "severity": "high",
                "status": "likely",
                "excerpt": "</script><b>x",
                "label": None,
            }
        ]
    }
    page = render_labelling_page(data)
    assert "__DATA__" not in page and "a.py:1" in page
    assert "</script><b>x" not in page  # a literal script end in a finding cannot break the page
    assert page.count("</script>") == 1
