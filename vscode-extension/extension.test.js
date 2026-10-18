// Self-check for the one piece of extension.js that doesn't need the `vscode` module:
// turning a SARIF document into a per-file list of findings. Run with: node extension.test.js
const assert = require("node:assert");
const path = require("node:path");
const { groupSarifByFile } = require("./extension.js");

function sarif(results) {
  return { runs: [{ results }] };
}

function result(uri, startLine, ruleId = "sql_injection", level = "error") {
  return {
    ruleId,
    level,
    message: { text: "example" },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine } } }],
  };
}

// Relative URIs resolve against the workspace folder; lines are converted to 0-based.
{
  const grouped = groupSarifByFile(sarif([result("app.py", 12)]), "/repo");
  const expected = path.join("/repo", "app.py");
  assert.deepStrictEqual(Object.keys(grouped), [expected]);
  assert.strictEqual(grouped[expected][0].line, 11);
  assert.strictEqual(grouped[expected][0].ruleId, "sql_injection");
}

// Two findings in the same file land under one key, in order.
{
  const grouped = groupSarifByFile(
    sarif([result("app.py", 5), result("app.py", 20, "weak_hash", "warning")]),
    "/repo"
  );
  const key = path.join("/repo", "app.py");
  assert.strictEqual(grouped[key].length, 2);
  assert.strictEqual(grouped[key][1].ruleId, "weak_hash");
}

// A result with no location is skipped rather than crashing.
{
  const grouped = groupSarifByFile(sarif([{ ruleId: "x", level: "error", message: { text: "x" } }]), "/repo");
  assert.deepStrictEqual(grouped, {});
}

// An empty/missing results array is a no-op.
assert.deepStrictEqual(groupSarifByFile({}, "/repo"), {});

console.log("extension.test.js: all checks passed");
