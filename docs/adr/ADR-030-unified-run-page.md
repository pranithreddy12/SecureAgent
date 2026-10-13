# ADR-030: A single "Run" page instead of three separate forms

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "i want a application ui ... select some project folder and maybe i
  need to hit run button and i need a provider option or some mcp option or some static run kind of
  options and it should visualize every agent action ... the output is not a document but a UI")

## Context

The product already had everything the request needed, split across three pages: register a project
(zip upload or server path) -> confirm authorization -> start an audit with an exclude list and an
AI-review checkbox -> watch a live stage timeline, activity log and an interactive findings list on
the audit page (ADR-011/017/018/019). There was no true folder picker (only "choose a .zip file you
already made"), and no page that put source, options and the authorization check in one place.

There is **no MCP-driven agent mode to wire up**: `app/agents/`, `app/tools/`, `app/workflows/` and the
two target-management services are untracked files from a concurrent session that this session was told
not to read, edit or commit; `app/main.py` does not import or register any router from them, so they are
not reachable from the running app. Building a fake "agent" option against them was not an option.

## Decision

1. Add one page, `/run` (`frontend/app/(app)/run/page.tsx`), that chains the existing APIs instead of
   replacing them: pick a local folder (zipped client-side with `jszip` and sent to the existing
   `POST /projects/upload`) or an existing project, show the real authorization statement and an
   options panel, then call `authorize` + `POST /projects/{id}/audits` and hand off to the existing
   `/audits/{id}` page -- which already visualises every stage and renders findings as an interactive
   UI, not a document. No backend change.
2. Options panel offers what is real today: static analysis (always on), the existing opt-in AI review
   (reusing `<AiConsent>` verbatim, so the same consent copy and `llm_configured` gating applies), and an
   **MCP agent mode shown but disabled**, labelled "soon" with the same visual language the sidebar
   already uses for unbuilt pages -- visible because the owner asked for it, honest that it does not
   exist yet.
3. `lib/zipFolder.ts`: turns a `webkitdirectory` `FileList` into a zip `File`, skipping
   `node_modules`/`.git`/`.next`/`venv`/`dist`/`build`/`__pycache__`. This is a convenience filter; the
   server still does the real zip-slip/bomb/symlink checks on upload.

## Not claimed

- "Provider option" is the existing single server-configured LLM (env var), not a per-run model/provider
  picker -- the backend has no such concept, and the UI says so rather than faking a dropdown.
- The MCP agent mode is a label, not a feature.
- Only the "existing project" path through `/run` has a unit test; the folder-zip path is exercised
  manually (jsdom cannot meaningfully drive a real `FileList` + `JSZip`).
