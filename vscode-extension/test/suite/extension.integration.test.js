// Runs inside the real Extension Development Host (launched by ../runTest.js). Opens
// test/fixture/app.py (a known debug_enabled + sql_injection + missing-auth sample) and
// asserts the extension turns the scan's SARIF into actual vscode.Diagnostics on that file --
// the same thing a developer would see as squiggly underlines in the editor.
const assert = require("node:assert");
const path = require("node:path");
const vscode = require("vscode");

suite("SecureAgent extension (Extension Development Host)", () => {
  test("activates and a workspace scan produces diagnostics on the vulnerable file", async () => {
    const ext = vscode.extensions.getExtension("secureagent.secureagent-vscode");
    assert.ok(ext, "extension not found by id -- check publisher/name in package.json");
    await ext.activate();
    assert.ok(ext.isActive, "extension did not report active after activate()");

    const fixtureUri = vscode.Uri.file(
      path.resolve(__dirname, "..", "fixture", "app.py")
    );

    // The on-activation scan runs the real `secureagent` CLI as a child process; poll for
    // its result rather than assuming a fixed delay.
    const diags = await waitFor(
      () => vscode.languages.getDiagnostics(fixtureUri),
      (d) => d.length > 0,
      30000
    );

    assert.ok(diags.length >= 2, `expected >=2 diagnostics, got ${diags.length}`);
    const codes = diags.map((d) => d.code).sort();
    assert.ok(codes.includes("debug_enabled"), `missing debug_enabled in ${codes}`);
    assert.ok(codes.includes("sql_injection"), `missing sql_injection in ${codes}`);
    for (const d of diags) {
      assert.strictEqual(d.source, "SecureAgent");
      assert.ok(d.range.start.line >= 0);
    }
  });

  test("SecureAgent: Clear Findings empties the diagnostic collection", async () => {
    await vscode.commands.executeCommand("secureagent.clear");
    const fixtureUri = vscode.Uri.file(
      path.resolve(__dirname, "..", "fixture", "app.py")
    );
    const diags = vscode.languages.getDiagnostics(fixtureUri);
    assert.strictEqual(diags.length, 0);
  });

  test("SecureAgent: Scan Workspace repopulates them", async () => {
    await vscode.commands.executeCommand("secureagent.scanWorkspace");
    const fixtureUri = vscode.Uri.file(
      path.resolve(__dirname, "..", "fixture", "app.py")
    );
    const diags = await waitFor(
      () => vscode.languages.getDiagnostics(fixtureUri),
      (d) => d.length > 0,
      30000
    );
    assert.ok(diags.length >= 2);
  });
});

function waitFor(getValue, predicate, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const value = getValue();
      if (predicate(value)) return resolve(value);
      if (Date.now() - start > timeoutMs) {
        return reject(new Error(`timed out after ${timeoutMs}ms waiting for condition`));
      }
      setTimeout(tick, 300);
    };
    tick();
  });
}
