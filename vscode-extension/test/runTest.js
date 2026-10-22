// Launches a REAL but throwaway VS Code instance (its own --user-data-dir / --extensions-dir,
// created fresh under os.tmpdir() -- never the developer's real profile or open windows) with
// this extension loaded, opens test/fixture/ as the workspace, and runs test/suite's Mocha
// suite inside it. This is the scripted equivalent of pressing F5 and checking the Problems
// panel, safe to run unattended (CI, or here).
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { runTests } = require("@vscode/test-electron");

// On Windows, VS Code splits --extensionDevelopmentPath/--extensionTestsPath at spaces, so a
// checkout under e.g. "C:\Personal Projects\..." fails (and can even resolve to an unrelated
// file named "C:\Personal"). If the extension folder's path has a space, stage a copy of it under
// the OS temp dir and run from there; otherwise run in place.
function stageIfPathHasSpace(src) {
  if (!src.includes(" ")) return { dir: src, cleanup: () => {} };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureagent-vscode-run-"));
  fs.cpSync(src, dir, {
    recursive: true,
    filter: (p) => !p.includes(`${path.sep}.vscode-test`),
  });
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

async function main() {
  const staged = stageIfPathHasSpace(path.resolve(__dirname, ".."));
  const extensionDevelopmentPath = staged.dir;
  const extensionTestsPath = path.join(staged.dir, "test", "suite", "index.js");
  const workspacePath = path.join(staged.dir, "test", "fixture");
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "secureagent-vscode-user-"));
  const extensionsDir = fs.mkdtempSync(path.join(os.tmpdir(), "secureagent-vscode-ext-"));

  try {
    await runTests({
      version: process.env.VSCODE_TEST_VERSION || "1.142.0", // pinned: reproducible, no re-download
      // VS Code cannot load its own worker files when its install path contains a space (e.g.
      // "C:\Users\Jane Doe\Personal Projects\..."), so cache the downloaded build under the
      // OS temp dir rather than inside the repo checkout. Override with VSCODE_TEST_CACHE.
      cachePath: process.env.VSCODE_TEST_CACHE || path.join(os.tmpdir(), "secureagent-vscode-test"),
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: [
        workspacePath,
        "--user-data-dir",
        userDataDir,
        "--extensions-dir",
        extensionsDir,
        "--disable-workspace-trust",
        "--skip-welcome",
        "--skip-release-notes",
      ],
    });
  } finally {
    fs.rmSync(userDataDir, { recursive: true, force: true });
    fs.rmSync(extensionsDir, { recursive: true, force: true });
    staged.cleanup();
  }
}

main().catch((err) => {
  console.error("Extension Development Host test run failed:", err);
  process.exit(1);
});
