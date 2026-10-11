# Paper plan: SecureAgent

Status: **plan only.** No result below is a measured research result unless it says so. Nothing in
this file may be cited as evidence until the evaluation in §4 has been run and recorded.

## 1. What can honestly be claimed today

| Claim | Evidence we have | Strength |
|---|---|---|
| A grey-box static auditor that combines taint analysis, authorization-matrix analysis, a developer *intent spec*, and attack-chain correlation, with an explicit **honesty model** (static findings are never "confirmed"; CVE/CVSS only from real advisories) | Working, tested implementation (ADR-008/010/012/013/015) | Engineering contribution; fine for a tool paper |
| **Verified fix patches**: a patch is "verified" only if it parses and a re-scan shows the finding gone with nothing new | Implemented + unit-tested (ADR-013) | Novel-ish and cheap to evaluate properly |
| **Benchmarks written by the tool's author overstate real-world precision** | Author corpus: 97% precision / 95% recall. First independent scan of a real multi-project directory: 204 findings, a large majority false positives (root causes enumerated in `PROJECT_CHANGELOG.md`, 2026-10-12) | A useful, honest *negative result*; currently anecdotal (n = 1 project, triage by an LLM assistant) |
| Deterministic scanner as the exhaustive layer under an LLM reviewer (MCP, and the built-in `review` command) | MCP server and an opt-in LLM review layer exist (ADR-017); fake-transport tests only, no live run, no accuracy data | Position/vision; **RQ5 not evaluated** |

What can **not** be claimed: that it outperforms CodeQL/Semgrep/Bandit/Snyk, that it finds business-logic
flaws a human would miss, any detection rate on real software, or that the LLM-assisted workflow works
(there is no LLM component yet).

## 2. Recommended paper type (most achievable first)

1. **Tool / demo paper (4-6 pages)** -- the system, the honesty model, verified fixes, MCP integration,
   with an honest evaluation section. Fits ASE/ISSTA/ICSE tool tracks and security-engineering workshops.
2. **Short empirical paper** -- "Author-written benchmarks mislead: a precision audit of a static auditor
   on real projects", built from §4 with several independent projects. This is the strongest *research*
   angle we have, because the negative result is real.
3. A full research paper needs a head-to-head against established tools on public corpora (§4.2) and a
   user study; do not attempt it without them.

## 3. Candidate research questions

- **RQ1 (precision on real code):** What is the precision of each detector family on projects the authors did
  not write, and which false-positive classes dominate? *(We already have an anecdote; needs n >= 10.)*
- **RQ2 (what fixes precision):** How much does each precision mechanism contribute -- word-based key matching,
  router-level dependency guards, sanitizer modelling, gitignore awareness, validation rules? *(ablation)*
- **RQ3 (verified fixes):** For the findings that have a deterministic fix, how often is the verified patch
  correct, accepted by a developer, and behaviour-preserving? *(manual review of N patches)*
- **RQ4 (triage cost):** Does adding chains + fix-first ordering reduce developer review effort
  vs a flat list? *(small user study or time-to-triage experiment)*
- **RQ5 (LLM layer, only if built):** Does LLM triage of the deterministic findings improve precision without
  losing true positives, and how often does it hallucinate evidence? *(requires the planned LLM review)*

## 4. Evaluation protocol (what has to be run before submission)

### 4.1 Ground truth
- Choose >= 10 open-source Python/JS web projects the authors did not write (record commit SHAs).
- Two independent annotators label every finding as TP / FP / unclear; report inter-annotator agreement
  (Cohen's kappa). An LLM may be used as a *third* opinion, never as ground truth.
- Report **precision per detector family**, not one pooled number; report recall only where a seeded or
  known-vulnerability ground truth exists.

### 4.2 Baselines (same projects, same labelling)
- Semgrep (default + security-audit rulesets), Bandit (Python), CodeQL (if licence/time permits),
  ESLint security plugin (JS). Record versions and configs. Treat results as comparisons, not as a
  claim of superiority.

### 4.3 Public corpora for recall
- Known-vulnerable applications with documented flaws (e.g. OWASP Juice Shop, DVWA, DVNA, VulPy-style
  projects) and CVE-fix commits (CVEfixes-style datasets). Cite the dataset papers; do not invent figures.
- Seed-based recall: inject known flaw patterns into clean code and measure detection (clearly labelled
  synthetic).

### 4.4 Ablations
- Remove each precision mechanism in turn and re-measure (RQ2).
- Chains on/off for triage effort (RQ4).

### 4.5 Reproducibility artifact
- Pin tool versions (`requirements.lock`), record project SHAs, publish labels and the scoring script
  (`secureagent benchmark` already scores `VULN:` markers); archive on Zenodo with a DOI.

## 5. Threats to validity (write these honestly)

- The detectors were tuned on the same real projects used to evaluate them (the 2026-10-12 scan) -- use a
  held-out set.
- One tool author wrote both the tool and the first benchmark.
- Static analysis, Python/JS only; JS is regex-based and shallower.
- Labelling is subjective for authorization findings (global middleware is invisible).
- LLM-assisted triage (if used for labelling) can be wrong and correlated with LLM-based tooling.

## 6. Ethics and disclosure

- Scan only code you own or are authorized to analyse; obtain written permission from maintainers for any
  third-party project, and follow responsible disclosure for any real vulnerability found.
- The tool never executes scanned code and ships no exploit payloads; state this in the paper.
- Report findings about third-party projects in aggregate or anonymised unless the maintainers agree.

## 7. Suggested title directions (pick after §4 results)

- *SecureAgent: A Deterministic Grey-Box Static Auditor with Verified Fixes and an Honest Finding Model*
- *When the Benchmark Flatters the Tool: A Precision Audit of a Static Application-Security Auditor*

## 8. Work needed before writing

| Item | Effort | Blocking? |
|---|---|---|
| Independent evaluation on >= 10 projects with two annotators | days | **yes** |
| Baseline runs (Semgrep, Bandit, ...) | 1-2 days | yes for any comparison claim |
| Held-out split + ablation script | 1 day | yes for RQ2 |
| Patch correctness review (RQ3) | 1 day | for the verified-fix claim |
| LLM review layer + evaluation (RQ5) | 1-2 weeks | only if claimed |
| Related work (SAST, taint analysis, authz/BOLA detection, LLM-assisted triage) | 2-3 days | yes |
