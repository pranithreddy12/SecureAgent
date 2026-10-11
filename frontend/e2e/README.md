# End-to-end tests (Playwright)

Drive a real browser against the running stack: register, start a source audit, watch it
complete, read findings / attack chains / the report, ownership isolation, sign-out and login
throttling. They need Docker, so they are separate from `npm test` (Vitest).

```bash
# 1. put something to audit under ./workspace (a copy of the bundled demo works)
mkdir -p workspace && cp -r backend/app/demo/demo_fixtures/vulnerable_shop workspace/shop

# 2. start the stack (needs a .env; see docs/deployment.md)
docker compose up --build -d backend frontend

# 3. run the tests
cd frontend
npx playwright install chromium          # once; or reuse installed Chrome with E2E_CHANNEL=chrome
npm run e2e
```

| Variable | Meaning |
|---|---|
| `E2E_BASE_URL` | App URL (default `http://localhost:3000`) |
| `E2E_CHANNEL` | `chrome` / `msedge` to use an installed browser instead of the bundled Chromium |

Each test registers its own unique user, so runs do not need a clean database. CI runs this job
(`e2e` in `.github/workflows/ci.yml`) and uploads the Playwright report on failure.
