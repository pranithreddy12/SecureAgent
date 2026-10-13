// SecureAgent desktop shell: a native window around the existing web app, not a browser tab.
//
// What it does: starts the Docker Compose stack (postgres + backend + frontend) if it isn't
// already running, shows a branded splash while the backend comes up, then loads the real app.
// What it does NOT do: bundle the backend/database into the app itself -- Docker is still the
// runtime, this is a window and a launcher around it, not a repackage of the whole product.

const { app, BrowserWindow, Menu, shell } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");

const APP_URL = process.env.SECUREAGENT_APP_URL || "http://localhost:3000";
const HEALTH_URL = process.env.SECUREAGENT_HEALTH_URL || "http://localhost:8000/api/health";
const REPO_ROOT = path.join(__dirname, ".."); // desktop/ is a sibling of docker-compose.yml
const POLL_MS = 2000;
const MAX_POLLS = 60; // ~2 minutes

let win;

function checkHealth() {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, { timeout: 2000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

function setStatus(text) {
  if (!win || win.isDestroyed()) return;
  win.webContents
    .executeJavaScript(`document.getElementById("status").textContent = ${JSON.stringify(text)};`)
    .catch(() => {});
}

function startDockerCompose() {
  return new Promise((resolve) => {
    setStatus("Starting the SecureAgent stack (docker compose up -d)…");
    const child = spawn("docker", ["compose", "up", "-d", "postgres", "backend", "frontend"], {
      cwd: REPO_ROOT,
      shell: true,
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", (err) => resolve(`could not run "docker": ${err.message}`));
    child.on("close", (code) => resolve(code === 0 ? null : stderr.trim() || `docker compose exited ${code}`));
  });
}

async function waitForBackend() {
  const dockerError = await startDockerCompose();
  if (dockerError) {
    setStatus(
      `Docker didn't start the stack (${dockerError}). Is Docker Desktop running? ` +
        "Waiting in case it comes up on its own…",
    );
  }
  for (let i = 0; i < MAX_POLLS; i++) {
    if (await checkHealth()) return true;
    setStatus(`Waiting for the backend to be ready… (${i + 1}/${MAX_POLLS})`);
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  return false;
}

async function boot() {
  win = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 860,
    minHeight: 560,
    backgroundColor: "#0e0f12", // matches --background, avoids a white flash on load
    title: "SecureAgent",
    icon: path.join(__dirname, "icon.ico"),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  await win.loadFile(path.join(__dirname, "splash.html"));

  if (await checkHealth()) {
    await win.loadURL(APP_URL);
    return;
  }
  const ready = await waitForBackend();
  if (win.isDestroyed()) return;
  if (ready) {
    await win.loadURL(APP_URL);
  } else {
    setStatus(
      "Still not reachable after two minutes. Check Docker Desktop is running, then " +
        '"docker compose logs backend" from the project root, and restart this app.',
    );
  }
}

function buildMenu() {
  const isMac = process.platform === "darwin";
  const template = [
    ...(isMac ? [{ role: "appMenu" }] : []),
    { role: "editMenu" },
    {
      label: "View",
      submenu: [
        {
          label: "Reload",
          accelerator: "CmdOrCtrl+R",
          click: () => win && win.loadURL(APP_URL),
        },
        { role: "toggleDevTools" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    { role: "windowMenu" },
    {
      role: "help",
      submenu: [
        {
          label: "SecureAgent on GitHub",
          click: () => shell.openExternal("https://github.com/pranithreddy12/SecureAgent"),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(() => {
  buildMenu();
  boot();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) boot();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
