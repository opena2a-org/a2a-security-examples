// Example checks. Run with: node --test test/examples.test.mjs (npm test at the
// repository root runs every test file).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function filesUnder(dir) {
  return readdirSync(dir).flatMap((name) => {
    if (name === "node_modules" || name === "dist") return [];
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

// Links a visitor cannot open: a private repository and pages that return 404.
// Checked 2026-10-09.
const unreachable = [
  "https://github.com/opena2a-org/trapmyagent",
  "https://agentpwn.com/attacks/a2a-attack/task-injection",
  "https://agentpwn.com/attacks/a2a-attack/response-poisoning",
];

test("README and example sources link no private repository or missing page", () => {
  const files = [join(root, "README.md"), ...filesUnder(join(root, "examples"))];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const url of unreachable) {
      assert.ok(!text.includes(url), `${file.slice(root.length + 1)} links ${url}`);
    }
  }
});

test(".gitignore excludes environment, key and secrets files", () => {
  const patterns = readFileSync(join(root, ".gitignore"), "utf8").split("\n").map((l) => l.trim());
  for (const pattern of [".env", ".env.*", "*.key", "*.pem", "secrets.json"]) {
    assert.ok(patterns.includes(pattern), `.gitignore lists ${pattern}`);
  }
});

test("npm test at the repository root installs every example and runs every test file", () => {
  const script = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts?.test ?? "";
  const examples = readdirSync(join(root, "examples")).filter((name) =>
    existsSync(join(root, "examples", name, "package.json"))
  );
  for (const name of examples) {
    assert.match(script, new RegExp(`npm ci --prefix examples/${name}\\b`), `npm test installs examples/${name}`);
  }
  const run = script.match(/&& node --test ((?:test\/\S+\.test\.mjs ?)+)$/);
  assert.ok(run, "npm test runs node --test on the test files after installing");
  const listed = run[1].trim().split(" ").sort();
  const present = readdirSync(join(root, "test"))
    .filter((name) => name.endsWith(".test.mjs"))
    .map((name) => `test/${name}`)
    .sort();
  assert.deepEqual(listed, present, "npm test runs every file in test/");
});
