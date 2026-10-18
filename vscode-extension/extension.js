// SecureAgent for VS Code: runs the `secureagent` CLI (SARIF output) over a workspace
// folder and shows the findings as inline diagnostics -- the same scanner as the CLI, the
// MCP server and the web app, just surfaced where you're already looking.
//
// Deliberately plain JS (no TypeScript build step), matching the CLI's own
// dependency-light philosophy (ADR-009).

// `vscode` only resolves inside the extension host. Guarded so `groupSarifByFile` -- the
// pure part of this file -- stays importable from a plain Node test.
let vscode;
try {
  vscode = require("vscode");
} catch {
  vscode = null;
}
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SEVERITY_FROM_LEVEL = vscode && {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  note: vscode.DiagnosticSeverity.Information,
};

let diagnostics;
let outputChannel;
let debounceTimers = new Map();

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("secureagent");
  outputChannel = vscode.window.createOutputChannel("SecureAgent");
  context.subscriptions.push(diagnostics, outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("secureagent.scanWorkspace", () => scanAllFolders()),
    vscode.commands.registerCommand("secureagent.clear", () => diagnostics.clear())
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("secureagent");
      if (!cfg.get("scanOnSave")) return;
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder) return;
      // Debounce: a save-everything action shouldn't launch N scans of the same folder.
      clearTimeout(debounceTimers.get(folder.uri.fsPath));
      debounceTimers.set(
        folder.uri.fsPath,
        setTimeout(() => scanFolder(folder), 400)
      );
    })
  );

  scanAllFolders();
}

function scanAllFolders() {
  for (const folder of vscode.workspace.workspaceFolders || []) scanFolder(folder);
}

function scanFolder(folder) {
  const cfg = vscode.workspace.getConfiguration("secureagent");
  const exe = cfg.get("executable") || "secureagent";
  const sarifPath = path.join(os.tmpdir(), `secureagent-${process.pid}-${Date.now()}.sarif`);
  const args = ["scan", folder.uri.fsPath, "--format", "sarif", "--output", sarifPath, "--exit-zero"];
  if (cfg.get("excludeOsv")) args.push("--no-osv");

  execFile(exe, args, { cwd: folder.uri.fsPath, timeout: 120000 }, (err, _stdout, stderr) => {
    if (err && !fs.existsSync(sarifPath)) {
      outputChannel.appendLine(`[${folder.name}] ${err.message}`);
      if (stderr) outputChannel.appendLine(stderr);
      if (err.code === "ENOENT") {
        vscode.window.showErrorMessage(
          "SecureAgent: the 'secureagent' CLI was not found. Install it (pip install secureagent) " +
            "or set secureagent.executable, then run 'SecureAgent: Scan Workspace'."
        );
      }
      return;
    }
    try {
      applySarif(folder, JSON.parse(fs.readFileSync(sarifPath, "utf8")));
    } catch (parseErr) {
      outputChannel.appendLine(`[${folder.name}] could not read SARIF: ${parseErr.message}`);
    } finally {
      fs.unlink(sarifPath, () => {});
    }
  });
}

// Pure (no `vscode` dependency, so it's unit-testable with plain Node): a SARIF document ->
// { absoluteFilePath: [{ line (0-based), message, ruleId, level }] }.
function groupSarifByFile(sarif, folderFsPath, isAbsolute = path.isAbsolute, join = path.join) {
  const byFile = {};
  const results = (sarif.runs && sarif.runs[0] && sarif.runs[0].results) || [];
  for (const r of results) {
    const loc = r.locations && r.locations[0] && r.locations[0].physicalLocation;
    if (!loc) continue;
    const uri = loc.artifactLocation.uri;
    const line = Math.max(0, (loc.region && loc.region.startLine ? loc.region.startLine : 1) - 1);
    const abs = isAbsolute(uri) ? uri : join(folderFsPath, uri);
    (byFile[abs] = byFile[abs] || []).push({
      line,
      message: `[${r.ruleId}] ${r.message.text}`,
      ruleId: r.ruleId,
      level: r.level,
    });
  }
  return byFile;
}

function applySarif(folder, sarif) {
  const byFile = groupSarifByFile(sarif, folder.uri.fsPath);

  // Clear every diagnostic this folder previously owned, then set the fresh set, so a
  // fixed finding actually disappears instead of lingering from a stale scan.
  diagnostics.forEach((uri) => {
    if (uri.fsPath.startsWith(folder.uri.fsPath) && !(uri.fsPath in byFile)) {
      diagnostics.delete(uri);
    }
  });
  for (const [file, items] of Object.entries(byFile)) {
    const diags = items.map((item) => {
      const range = new vscode.Range(item.line, 0, item.line, 1000);
      const diag = new vscode.Diagnostic(
        range,
        item.message,
        SEVERITY_FROM_LEVEL[item.level] ?? vscode.DiagnosticSeverity.Warning
      );
      diag.source = "SecureAgent";
      diag.code = item.ruleId;
      return diag;
    });
    diagnostics.set(vscode.Uri.file(file), diags);
  }
  const total = Object.values(byFile).reduce((n, items) => n + items.length, 0);
  outputChannel.appendLine(`[${folder.name}] ${total} finding(s)`);
}

function deactivate() {
  for (const t of debounceTimers.values()) clearTimeout(t);
}

module.exports = { activate, deactivate, groupSarifByFile };
