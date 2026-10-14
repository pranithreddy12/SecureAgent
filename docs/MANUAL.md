# SecureAgent — User Manual

A practical "how do I actually run this" guide. For *what was built and why* see
[docs/OVERVIEW.md](OVERVIEW.md); for the honesty/safety model and limitations see the main
[README.md](../README.md). This page only covers using the tool.

There are four independent ways to run SecureAgent. Pick whichever fits what you're doing right now —
they all share the same deterministic scanner underneath.

| Way | Best for | Needs |
|---|---|---|
| **CLI** (`secureagent`) | One-off scans, CI gating, scripting | Python 3.12+, nothing else |
| **Web app** (`/run` page) | Reviewing findings interactively, tracking audits over time, the opt-in AI layer | Docker Compose |
| **Desktop app** | The same web app, as a native window instead of a browser tab | Docker Compose, Node |
| **MCP server** | Letting Claude Code / another AI assistant check its own work as it codes | Your AI tool's MCP support |

---

## 1. Command-line (`secureagent`)

### Install

```bash
pip install "git+https://github.com/pranithreddy12/SecureAgent.git#subdirectory=backend"
```

Or from a local checkout: `pip install ./backend`. No database, no Docker, nothing to configure —
it reads your source tree and writes a report. **Only scan code you own or are authorized to test.**

### The six subcommands

```
secureagent {scan,fix,suppress,review,benchmark,demo}
```

#### `scan` — the main command

```bash
secureagent                                   # same as: secureagent scan . --open
secureagent scan . --report report.html --pdf report.pdf
secureagent scan . --matrix --recon           # + route×guard matrix, + tech/inputs/hosts/env vars
secureagent scan . --since origin/main        # only findings new vs. a git ref (PR review)
secureagent scan . --format sarif --output secureagent.sarif    # GitHub code scanning upload
secureagent scan . --baseline .secureagent-baseline.json --fail-on high   # CI gate on new high+
```

Full flag reference (`secureagent scan --help`):

| Flag | What it does |
|---|---|
| `--since REF` | Diff mode: only findings new vs. `REF` (branch/tag/commit). Gating applies to those only. |
| `--exit-zero` | Exit 0 even with findings (interactive use; CI should use `--fail-on` instead). |
| `--open` | Write the HTML report to a temp file and open it in your browser. |
| `--format {text,json,sarif}` | Machine-readable output. |
| `--output FILE` | Write text/JSON to a file instead of stdout. |
| `--report FILE` / `--pdf FILE` | A full HTML / PDF report (PDF needs WeasyPrint's system libs). |
| `--max-files N` | Cap how many files are scanned. |
| `--exclude PATTERN` | Skip a glob (repeatable); `<path>/.secureagentignore` patterns apply too. |
| `--no-osv` | Skip the OSV known-vulnerable-dependency lookup (fully offline). |
| `--intent FILE` | Your own rules the code must satisfy (defaults to `secureagent-intent.json`). |
| `--baseline FILE` / `--write-baseline FILE` | Suppress a known set of findings / freeze the current set. |
| `--fail-on {critical,high,medium,low}` | Exit non-zero only above this severity (new findings in `--since` mode). |
| `--recon` | Print the static reconnaissance model (tech, inputs, outbound hosts, env vars). |
| `--matrix` | Print the route × guard authorization matrix. |
| `--no-color` | Plain text output. |

Exit code: `1` if (gated) findings remain, `0` clean, `2` on error — so it drops straight into CI.

#### `fix` — verified patches

```bash
secureagent fix .              # print diffs for deterministic findings it can verify a patch for
secureagent fix . --apply       # write only the VERIFIED ones; unverified patches are never written
```

#### `suppress` — a reviewed, justified false-positive list

```bash
secureagent suppress . --list
secureagent suppress . --id 3f9a1c0b --reason "cache key only, not a secret" --expires 2027-01-01
```
Writes to `secureagent-suppressions.json`. Nothing is ever suppressed silently: excluded files and
`# secureagent: ignore` lines are still counted in the scan output.

#### `review` — opt-in LLM second opinion

```bash
secureagent review . --dry-run                              # see exactly what would be sent, nothing sent
secureagent review . --yes                                   # send it (asks for confirmation without --yes)
secureagent review . --provider mistral --model codestral-latest --yes
secureagent review . --report with-ai.html --yes
```
Reads the key from `ANTHROPIC_API_KEY` or `MISTRAL_API_KEY` (never a flag, never logged). See
[§5](#5-the-opt-in-ai-layer-providers) for what each provider needs. The verdict is shown beside each
finding and **never** changes its status or the exit code.

#### `benchmark` — measure precision/recall against a labelled corpus

```bash
secureagent benchmark backend/benchmark/corpus
secureagent benchmark backend/benchmark/corpus --min-precision 0.9 --min-recall 0.8   # CI gate
```
The corpus marks real flaws with `# VULN:<type>` comments; anything else reported is a false positive.

#### `demo` — try it with zero setup

```bash
secureagent demo                 # scans a bundled, deliberately vulnerable sample app; works offline
secureagent demo --report demo.html
```

---

## 2. The web application

This is the interactive version: register/login, pick a project, watch an audit run stage by stage, and
review findings as an expandable, filterable, triage-able list — not a document you have to re-read.

### Bring it up

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste the result into SECRET_KEY in .env
# also set POSTGRES_PASSWORD and ZAP_API_KEY to random values

docker compose up --build -d postgres backend frontend
docker compose ps                 # wait for backend to show "healthy"
```

Open **http://localhost:3000**, register an account, and log in.

### The fastest path: the Run page

Click **Run** in the sidebar (or go to `/run`). It's a single page:

1. **Source** — either click "Choose folder…" and pick a folder on your machine (it's zipped in your
   *browser* and uploaded — `node_modules`, `.git`, `.next`, `venv`, `dist`, `build` are skipped
   automatically so the archive stays small), or pick a project you registered earlier.
2. **How to analyse it** — static analysis always runs; tick **AI review** if you want a second opinion
   (only shown when a key is configured on the server — see §5). "Agent (MCP-driven)" is shown but
   disabled; it isn't built yet.
3. **Authorization and run** — tick the confirmation and click **Run security audit**.

You land on the audit page: a live stage checklist (authorization → reconnaissance → scanner → fix
verification → validator → the two AI stages if enabled → correlation → report) that polls every two
seconds, a scrolling activity log, and the findings themselves — severity-filterable, each one
expandable to its evidence, taint path, remediation, CVE/CVSS and (if AI review ran) the model's verdict
with its supporting quote. Click **Suggest a fix** on a finding for a deterministic, verified patch
if one exists (a handful of types: `weak_hash`, `hardcoded_secret`, `debug_enabled`,
`csrf_disabled`, `jwt_verification_disabled`, `insecure_deserialization`/yaml) — for everything
else it says plainly that there's no automatic fix yet, rather than inventing a plausible snippet.
Any finding can be marked a false positive with a reason (reversible); a failed audit can be
retried or resumed from the stage that failed.

### The longer way (registering a project first)

Useful for code that already lives on the server, or for code you'll audit repeatedly:

- **A server path**: `docker-compose.yml` mounts `./workspace` into the backend read-only at
  `/workspace`. Put (or symlink) your project under `./workspace/myapp`, then register it on the
  **Projects** page with path `/workspace/myapp`.
- **A zip upload**: same page, "Or upload a zip of your code" — unpacked safely into a private folder
  (zip-slip/bomb/symlink rejected) and deleted when you delete the project.

Either way: confirm authorization once (it's append-only and revocable, with a visible history), then
**Run an audit** with an optional exclude-pattern list and the same AI-review checkbox. Every audit for
that project is listed, each linking to the same live view described above.

### Reports

Once an audit completes, the audit page offers **View report**, **Download HTML** and **Download PDF** —
the same report the CLI's `--report`/`--pdf` produce, generated from the same data the page already
shows you.

---

## 3. The desktop app

The exact same web app, in a native window instead of a browser tab -- no address bar, a real title
bar and app menu.

```bash
cd desktop
npm install
npm start
```

It runs `docker compose up -d postgres backend frontend` for you (safe to call even if the stack is
already running), shows a branded splash while it waits for the backend to answer, then loads the app.
If Docker isn't running, or the backend doesn't come up within two minutes, the splash says so instead
of hanging silently. Details, including why Electron rather than Tauri: [desktop/README.md](../desktop/README.md),
[ADR-038](adr/ADR-038-desktop-shell.md).

It doesn't bundle the backend/database into the app -- Docker Compose is still the runtime underneath.

---

## 4. MCP — inside your AI coding assistant

Lets Claude Code (or any MCP client) check code it just wrote, explain a finding with its taint path,
or get verified-patch suggestions, without you leaving your editor.

```bash
pip install ./backend              # provides the secureagent-mcp command (stdlib only)
claude mcp add secureagent -- secureagent-mcp
```

Tools: `scan_snippet`, `scan_path` (paged, filterable, cached), `scan_diff`, `explain_finding`,
`suggest_fixes`, `application_model`, `authorization_matrix`, and opt-in `record_verdict`. Read-only,
confined to the working directory, offline by default. Full setup (Claude Desktop, OpenCode, the
`security_review` prompt, write access) is in **[docs/mcp.md](mcp.md)** — this manual won't repeat it.

---

## 5. The opt-in AI layer: providers

Both the CLI's `review` command and the web app's `ai_review`/`ai_validator`/`ai_narrative` stages go
through the same provider table (`app/analysis/llm_review.py`). Two providers exist today:

| Provider | Env var for the key | Default model | Notes |
|---|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY` | `claude-sonnet-5-5` | |
| `mistral` | `MISTRAL_API_KEY` | `mistral-large-latest` → see caveat below | OpenAI-compatible request shape |

**Web app:** set in `.env`, then restart the backend:
```bash
LLM_PROVIDER=mistral
LLM_API_KEY=your-key-here
LLM_MODEL=              # empty picks the provider's default; see the tier caveat below
```
`.env` is git-ignored — never commit a real key. `GET /api/health` reports `llm_configured: true/false`
so the UI knows whether to offer the AI-review checkbox at all.

**CLI:** `--provider {anthropic,mistral}` and `--model`, or `SECUREAGENT_REVIEW_PROVIDER` /
`SECUREAGENT_REVIEW_MODEL` env vars.

**A real caveat, learned live (2026-10-14, ADR-033):** on a free-tier Mistral key, `mistral-large-latest`
returned `403 tier_not_allowed` and `mistral-small-latest` was rate-limited (`429`) on every attempt.
`codestral-latest` worked cleanly end to end — a real audit's `ai_validator`/`ai_narrative` stages ran
against it live: 15/15 findings reviewed, 13 correct `true_positive` verdicts, an accurate AI summary.
**If a Mistral key returns 403 or persistent 429, try `LLM_MODEL=codestral-latest` before assuming
something is broken** — it's very likely your account's tier, not the integration. See
[ADR-033](adr/ADR-033-mistral-provider.md) for the full record.

In every case: secrets and secret-named values are redacted before anything is sent, the model's quoted
evidence is checked against the code actually sent (an invented quote downgrades the verdict to
`unclear`), and the AI verdict/summary can never change a finding's status, severity or the gate.

---

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `docker compose ps` shows backend unhealthy | Check `docker compose logs backend`; usually a missing/short `SECRET_KEY` or Postgres still starting. |
| "AI review" checkbox doesn't appear | `GET /api/health` → `llm_configured: false`; `LLM_API_KEY` isn't set on the backend, or the backend hasn't been restarted since you set it. |
| `secureagent review` says a var `is not set` | That's `ANTHROPIC_API_KEY` or `MISTRAL_API_KEY` depending on `--provider` — it reads the real process environment, not `.env` (the CLI doesn't load `.env`; the web app does, via the backend container). |
| Mistral `403 tier_not_allowed` or repeated `429` | Account tier/rate limit, not a bug — see §5's caveat. |
| Project registration rejects a path | Must be under `SOURCE_ROOTS` (compose sets this to `/workspace`, mounted from `./workspace` on the host, read-only). Use the zip upload or the Run page's folder picker instead if your code isn't there. |
| Zip upload rejected | Size/file-count limits (`MAX_UPLOAD_MB`, default 25) or an unsafe archive (zip-slip, symlink, zip bomb, encrypted) — all rejected on purpose. |

For anything deeper than "how do I run it", see [docs/OVERVIEW.md](OVERVIEW.md) (full inventory),
[docs/evaluation.md](evaluation.md) (how accurate it actually is, honestly), and
[docs/REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md) (every requirement, mapped to code).
