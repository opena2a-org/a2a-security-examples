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

test("the repository root and every example have a lock file that matches their package.json, so npm ci can install them", () => {
  const dirs = [
    "",
    ...readdirSync(join(root, "examples"))
      .filter((name) => existsSync(join(root, "examples", name, "package.json")))
      .map((name) => `examples/${name}/`),
  ];
  for (const dir of dirs) {
    const lockPath = join(root, dir, "package-lock.json");
    assert.ok(existsSync(lockPath), `${dir}package-lock.json exists`);
    const pkg = JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    assert.ok(lock.lockfileVersion >= 1, `${dir}package-lock.json has lockfileVersion >= 1`);
    assert.equal(lock.name, pkg.name, `${dir}package-lock.json names the package in ${dir}package.json`);
    const locked = lock.packages?.[""] ?? {};
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      assert.deepEqual(locked[field] ?? {}, pkg[field] ?? {}, `${dir}package-lock.json records the ${field} of ${dir}package.json`);
    }
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

test("every test file uses each name it imports", () => {
  for (const name of readdirSync(join(root, "test")).filter((file) => file.endsWith(".mjs"))) {
    const text = readFileSync(join(root, "test", name), "utf8");
    const body = text.replace(/^import\s[^;]*;$/gm, "");
    for (const [, clause] of text.matchAll(/^import\s+([^"';]+?)\s+from\s+["'][^"']+["'];$/gm)) {
      const names = clause
        .replace(/[{}]/g, ",")
        .split(",")
        .map((part) => part.trim().split(/\s+as\s+/).pop())
        .filter(Boolean);
      for (const imported of names) {
        assert.match(body, new RegExp(`\\b${imported}\\b`), `test/${name} imports ${imported} and never uses it`);
      }
    }
  }
});
