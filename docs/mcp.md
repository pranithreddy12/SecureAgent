# SecureAgent as an MCP server

SecureAgent's static analyser can be called directly by an AI coding assistant over the
[Model Context Protocol](https://modelcontextprotocol.io). The most useful call is
`scan_snippet`: the assistant checks code it just wrote before handing it to you.

## Tools

| Tool | Purpose |
|---|---|
| `scan_snippet` | Analyse a code string (`code`, optional `filename`, e.g. `app.py`, `server.js`). |
| `scan_path` | Analyse a directory (`path`, optional `exclude`, `intent`, `include_osv`). |
| `suggest_fixes` | Verified patches (unified diffs + caveats) for deterministic findings; never writes files. |
| `explain_finding` | One finding in full: evidence, numbered taint path, remediation, and the enclosing function plus resolved helpers (secrets redacted). Pass the `id` from a scan result. |
| `scan_diff` | Findings that are new compared with a git ref (`since`), so a change can be reviewed instead of the whole repository. |
| `application_model` | Static reconnaissance: technologies, inputs read, outbound hosts, env vars. Reads files only. |
| `authorization_matrix` | Route × guard grid for a directory, grouped by resource. |

Findings carry `severity`, `status` (`likely` / `suspicious`, never `confirmed`), `confidence`,
`location`, `cwe`, `owasp`, `evidence` and `remediation`. At most 200 findings are returned per call
(`truncated` says if more exist).

## Install and register

```bash
pip install ./backend            # provides the `secureagent-mcp` command (stdlib only, no extra deps)
```

Claude Code:

```bash
claude mcp add secureagent -- secureagent-mcp
```

Claude Desktop / any client with a JSON config:

```json
{
  "mcpServers": {
    "secureagent": { "command": "secureagent-mcp" }
  }
}
```

OpenCode (`opencode.json` in the project root, or `~/.config/opencode/opencode.json` for all projects).
`SECUREAGENT_MCP_ROOTS` lists the directories the tools may read; separate several with `;` on Windows or
`:` elsewhere. Without it the server is confined to the directory it was started from:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "secureagent": {
      "type": "local",
      "command": ["secureagent-mcp"],
      "enabled": true,
      "environment": { "SECUREAGENT_MCP_ROOTS": "C:\Pranith\Personal Projects\10-02-2026-Security_Auditor_Pranith" }
    }
  }
}
```

From a checkout without installing, use `"command": ["<repo>\backend\.venv\Scripts\python.exe", "-m",
"app.mcp_server"]` and make sure the working directory is `backend/`. Not tested against OpenCode itself.

Without installing, from a checkout: `python -m app.mcp_server` with `backend/` as the working directory.

## Safety model

- **Read-only.** Scanned code is never executed; nothing is written except a private temp directory
  that `scan_snippet` deletes.
- **Path-confined.** `path` and `intent` must resolve (symlinks and `..` included) under an allowed
  root: the server's working directory by default, or the `os.pathsep`-separated
  `SECUREAGENT_MCP_ROOTS` environment variable. Anything else is returned as a tool error.
- **Offline by default.** The OSV dependency lookup (the only network call) runs only when a call
  passes `include_osv: true`.
- **Authorized targets only.** Scan code you own or are authorized to analyse, exactly as with the
  CLI.

## Protocol notes

stdio transport, newline-delimited JSON-RPC 2.0 (`initialize`, `ping`, `tools/list`, `tools/call`).
It is implemented with the standard library on purpose, so the installable scanner keeps its
stdlib + jinja2 + pydantic dependency set (ADR-009). It does not implement resources, prompts,
sampling or HTTP transports; add the official `mcp` SDK behind an optional extra if those are needed.
