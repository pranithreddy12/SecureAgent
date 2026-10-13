# ADR-038: A desktop shell, not just a web app

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "and i need a application ui not web ui")

## Context

SecureAgent's "web application" (frontend + backend + postgres via Docker Compose) is a real,
interactive UI (ADR-011, ADR-032's `/run` page, ADR-037's design pass) -- but it's still opened in a
browser tab, with a URL bar and other tabs around it. The owner wants it to read as an application, not
a website.

## Decision

Add `desktop/`: a thin Electron shell, not a rewrite of the UI.

- `main.js` starts `docker compose up -d postgres backend frontend` from the repo root, shows a
  branded splash (`splash.html`, matching ADR-037's palette) while polling
  `http://localhost:8000/api/health`, then loads the real app at `http://localhost:3000` in a native
  `BrowserWindow` -- no Node integration exposed to the loaded page (`contextIsolation: true`,
  `nodeIntegration: false`, `sandbox: true`), since it's still rendering web content.
- A minimal native menu (Edit/View/Window/Help) replaces the browser's own chrome.
- `electron-builder` config exists for a real installer (`npm run dist`), not yet built or shipped.

**Electron over Tauri:** the machine has no Rust toolchain installed; Electron only needs Node, which
this project already depends on everywhere else. Since SecureAgent has no native UI to speak of (it's
fully web-rendered), Tauri's smaller footprint isn't worth a new system dependency.

**Not bundling the backend into the app:** Docker Compose remains the runtime. A true standalone
desktop app (no Docker, bundled Python/Postgres) is a much larger project -- embedding an interpreter,
replacing Postgres with something embeddable, packaging per OS -- and wasn't what was asked; today's
decision is to change *how the UI is presented*, not the architecture underneath it.

## Verification

Both by screenshotting the real native window, not the dev-tools preview:

1. **Stack already running:** `npm start` opens the window, flashes the splash briefly, loads the real
   login screen; title bar reads "SecureAgent", native menu bar, no browser chrome.
2. **Stack stopped:** `docker compose stop backend frontend`, then `npm start` -- the shell ran
   `docker compose up -d`, which restarted the stopped containers, the health poll picked it up, and
   the window reached the login screen on its own, no manual Docker command needed.

## Not claimed

No installer has been built (`npm run dist` untested, no app icon supplied yet). What (2) tested was
*stopped containers*, not Docker Desktop itself being off -- that failure path (the splash's "is Docker
Desktop running?" message, and the two-minute timeout message) is implemented but not exercised.
