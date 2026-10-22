// Standard @vscode/test-electron Mocha entry point: runs inside the Extension Development
// Host process (not the outer Node process that launched it), so `require("vscode")` here
// resolves to the real API.
const path = require("node:path");
const Mocha = require("mocha");

function run() {
  const mocha = new Mocha({ ui: "tdd", timeout: 60000, color: true });
  mocha.addFile(path.resolve(__dirname, "extension.integration.test.js"));
  return new Promise((resolve, reject) => {
    mocha.run((failures) => {
      if (failures > 0) reject(new Error(`${failures} test(s) failed.`));
      else resolve();
    });
  });
}

module.exports = { run };
