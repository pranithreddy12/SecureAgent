# SecureAgent desktop shell

A native window around the web app (ADR-038): no browser tab, no address bar, a real title bar and
menu, a branded splash while the backend starts. It does **not** repackage the backend/database into
the app -- Docker Compose is still the runtime; this is a launcher and a window around it.

## Run it

```bash
cd desktop
npm install
npm start
```

On launch it runs `docker compose up -d postgres backend frontend` from the repo root (safe to call
even if they're already running) and polls `http://localhost:8000/api/health` while showing the splash
screen, then loads `http://localhost:3000` once the backend answers. If Docker isn't running, or the
backend never comes up within two minutes, the splash screen says so instead of hanging silently.

Set `SECUREAGENT_APP_URL` / `SECUREAGENT_HEALTH_URL` to point at a different frontend/backend (e.g. a
non-default port).

## Build an installer

```bash
npm run dist
```

Uses `electron-builder` (NSIS on Windows, AppImage on Linux, dmg on macOS). **Not yet done:** a real
`icon.ico`/`icon.icns`/`icon.png` -- `npm start` works without one (falls back to Electron's default
icon), but `npm run dist` should get a real one before it's distributed.

## Why Electron, not Tauri

Tauri would need the Rust toolchain installed; Electron only needs the Node toolchain the rest of this
project already uses. Given SecureAgent is fully web-rendered already (no native UI needed beyond the
window chrome), Electron's larger footprint is the cheaper trade here.
