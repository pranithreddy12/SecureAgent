"""Precision/recall evaluation on real repositories (paper RQ1; MCP plan phase 4).

The author-written benchmark (``secureagent benchmark``) is a regression guard, not a real-world
rate.
This module measures the thing that matters: of the findings the scanner reports on code *it was
not
written against*, how many are real, and how many known-real issues does it miss.

    python -m app.evaluation prepare REPO [REPO ...] --out DIR [--per-type 6]
        scans each repository and writes DIR/labels.json: a stratified sample of findings, each
        with a
        redacted code excerpt, ``label`` = null to be filled in by a human with "true" | "false"
        |
        "unsure". Also holds ``extras`` (issues found some other way, e.g. by an assistant, with
        ``found_by_tool``) to estimate recall.
    python -m app.evaluation score DIR/labels.json
        per-type and overall precision, the unlabelled/unsure counts, and a recall estimate.

Rules that keep the numbers honest: only labelled items count; "unsure" is reported, not hidden;
the sample is stratified by finding type (so per-type precision is meaningful and the overall
figure is
*not* a population estimate); the labeller should be a person who read the code, and the
labeller's
identity goes in ``labelled_by``. Secret values are redacted in excerpts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

LABELS = ("true", "false", "unsure")


def _excerpt(root: Path, location: str, radius: int = 4) -> str:
    from app.analysis.llm_review import redact_secrets

    rel, _, line_s = location.rpartition(":")
    if not rel or not line_s.isdigit():
        return ""
    target = (root / rel).resolve()
    if root.resolve() not in target.parents or not target.is_file():
        return ""
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""
    line = int(line_s)
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    body = "\n".join(f"{i:>5}{'>' if i == line else ' '} {lines[i - 1]}" for i in range(lo, hi + 1))
    return redact_secrets(body)


def prepare(repos: list[str], out_dir: str, per_type: int = 6) -> dict[str, Any]:
    from app.analysis.baseline import fingerprint
    from app.analysis.reporting import scan_to_report_context
    from app.analysis.scanner import scan_repo

    items: list[dict[str, Any]] = []
    meta: list[dict[str, Any]] = []
    for repo in repos:
        root = Path(repo).resolve()
        result = scan_repo(str(root), check_osv=False)
        findings = scan_to_report_context(result).findings
        reviewable = [
            f for f in findings if f.status.value not in ("informational", "false_positive")
        ]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        reviewable.sort(key=lambda f: (order.get(f.severity.value, 9), f.endpoint))
        taken: dict[str, int] = {}
        sample = []
        for f in reviewable:
            if taken.get(f.type, 0) < per_type:
                taken[f.type] = taken.get(f.type, 0) + 1
                sample.append(f)
        meta.append(
            {
                "repo": root.name,
                "files_scanned": result.stats.files_scanned,
                "findings_total": len(findings),
                "findings_reviewable": len(reviewable),
                "sampled": len(sample),
            }
        )
        for f in sample:
            items.append(
                {
                    "repo": root.name,
                    "id": fingerprint(f)[:8],
                    "type": f.type,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "location": f.endpoint,
                    "title": f.title,
                    "excerpt": _excerpt(root, f.endpoint),
                    "label": None,
                    "note": "",
                }
            )
    data = {
        "version": 1,
        "per_type_cap": per_type,
        "labelled_by": "",
        "repos": meta,
        "items": items,
        "extras": [],
        "extras_help": {
            "repo": "name",
            "location": "file:line",
            "description": "what is wrong",
            "source": "who found it (e.g. assistant-no-mcp)",
            "found_by_tool": "true if SecureAgent also reported it",
        },
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "labels.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return data


def _pct(num: int, den: int) -> str:
    return f"{100 * num / den:.0f}%" if den else "n/a"


def score(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    per_type: dict[str, dict[str, int]] = {}
    for it in data.get("items", []):
        row = per_type.setdefault(
            it["type"], {"sampled": 0, "true": 0, "false": 0, "unsure": 0, "unlabelled": 0}
        )
        row["sampled"] += 1
        label = it.get("label")
        if label in LABELS:
            row[label] += 1
        else:
            row["unlabelled"] += 1
    totals = {
        k: sum(r[k] for r in per_type.values())
        for k in ("sampled", "true", "false", "unsure", "unlabelled")
    }
    extras = [e for e in data.get("extras", []) if e.get("description")]
    missed = [e for e in extras if not e.get("found_by_tool")]
    known_true = totals["true"] + len(extras)
    found_true = totals["true"] + (len(extras) - len(missed))
    return {
        "labelled_by": data.get("labelled_by", ""),
        "repos": data.get("repos", []),
        "per_type": per_type,
        "totals": totals,
        "precision": (totals["true"] / (totals["true"] + totals["false"]))
        if totals["true"] + totals["false"]
        else None,
        "extras": len(extras),
        "missed": missed,
        "recall_estimate": (found_true / known_true) if known_true else None,
        "known_true": known_true,
    }


def render(result: dict[str, Any]) -> str:
    out = []
    t = result["totals"]
    out.append(f"labelled by: {result['labelled_by'] or '(not recorded)'}")
    out.append(
        f"{'type':<38}{'sampled':>8}{'true':>6}{'false':>6}{'unsure':>7}{'todo':>6}{'precision':>11}"
    )
    for name, r in sorted(result["per_type"].items()):
        out.append(
            f"{name:<38}{r['sampled']:>8}{r['true']:>6}{r['false']:>6}{r['unsure']:>7}"
            f"{r['unlabelled']:>6}{_pct(r['true'], r['true'] + r['false']):>11}"
        )
    out.append(
        f"{'ALL (stratified sample)':<38}{t['sampled']:>8}{t['true']:>6}{t['false']:>6}"
        f"{t['unsure']:>7}{t['unlabelled']:>6}{_pct(t['true'], t['true'] + t['false']):>11}"
    )
    if result["known_true"]:
        known = result["known_true"]
        found = known - len(result["missed"])
        out.append(f"recall estimate: {_pct(found, known)} ({found}/{known} known-real issues)")
        for m in result["missed"]:
            out.append(f"  missed: {m.get('repo')} {m.get('location')}: {m.get('description')}")
    else:
        out.append("recall estimate: n/a (no extras recorded)")
    out.append("NOTE: stratified by finding type; the overall figure is not a population rate.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m app.evaluation", description=__doc__.split("\n")[0]
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare", help="scan repositories and write a labelling sheet")
    p.add_argument("repos", nargs="+")
    p.add_argument("--out", required=True)
    p.add_argument("--per-type", type=int, default=6)
    s = sub.add_parser("score", help="score a filled-in labels.json")
    s.add_argument("labels")
    s.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "prepare":
        for r in args.repos:
            if not os.path.isdir(r):
                print(f"error: not a directory: {r}", file=sys.stderr)
                return 2
        data = prepare(args.repos, args.out, args.per_type)
        for m in data["repos"]:
            print(
                f"{m['repo']}: {m['files_scanned']} files, {m['findings_total']} findings "
                f"({m['findings_reviewable']} reviewable), sampled {m['sampled']}"
            )
        print(f'wrote {Path(args.out) / "labels.json"} -- fill in each item\'s "label"')
        return 0
    result = score(args.labels)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
