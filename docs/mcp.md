# SecureAgent as an MCP server

SecureAgent's static analyser can be called directly by an AI coding assistant over the
[Model Context Protocol](https://modelcontextprotocol.io). The most useful call is
`scan_snippet`: the assistant checks code it just wrote before handing it to you.

## Tools

| Tool | Purpose |
|---|---|
| `scan_snippet` | Analyse a code string (`code`, optional `filename`, e.g. `app.py`, `server.js`). |
| `scan_path` | Analyse a directory (`path`, optional `exclude`, `intent`, `include_osv`). |
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
