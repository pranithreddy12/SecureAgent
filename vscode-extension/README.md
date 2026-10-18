# SecureAgent for VS Code

Runs the `secureagent` CLI over your workspace and shows its findings as inline diagnostics --
the same scanner the CLI, the MCP server and the web app use, surfaced where you're already
looking: underlines on the vulnerable line, severity-coloured, with the finding type and
message in the Problems panel and on hover.

## Requirements

The `secureagent` CLI must be installed and on PATH (or pointed at via the
`secureagent.executable` setting):

```bash
pip install ./backend   # from a checkout of this repo
```

## What it does

- Scans every open workspace folder on activation.
- Re-scans a folder ~400ms after you save a file in it (`secureagent.scanOnSave`, default on).
- `SecureAgent: Scan Workspace` / `SecureAgent: Clear Findings` commands.
- Each run is `secureagent scan <folder> --format sarif --exit-zero` (plus `--no-osv` by
  default, `secureagent.excludeOsv`, so a save doesn't wait on a network call) -- the exact
  SARIF the CI gate and GitHub code scanning consume, so what you see here matches what a
  pull request would see.

## What it deliberately doesn't do

No partial/incremental analysis -- it re-scans the whole folder each time, same as the CLI
always has. No bundler or TypeScript build step (`ADR-009`'s dependency-light philosophy
applies here too); `extension.js` is the whole extension.

## Running it locally

Open this folder in VS Code and press F5 (`Run Extension`) to launch an Extension
Development Host with it loaded. There is no marketplace listing yet.

## Self-check

`groupSarifByFile`, the pure SARIF-to-per-file-findings step, has a plain-Node test with no
`vscode` dependency:

```bash
node extension.test.js
```
