// Example checks. Run with: node --test test/examples.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const example = join(root, "examples", "validated-task-handler");

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

test("npm run build emits the file npm start runs", () => {
  const pkg = JSON.parse(readFileSync(join(example, "package.json"), "utf8"));
  assert.equal(pkg.scripts.build, "tsc");
  const start = pkg.scripts.start.match(/^node (\S+)$/);
  assert.ok(start, "npm start runs one file with node");

  const tsconfigPath = join(example, "tsconfig.json");
  assert.ok(existsSync(tsconfigPath), "tsc has a tsconfig.json to build from");
  const tsconfig = JSON.parse(readFileSync(tsconfigPath, "utf8"));
  const { outDir, noEmit } = tsconfig.compilerOptions ?? {};
  assert.notEqual(noEmit, true, "the build emits JavaScript");
  assert.ok(outDir, "the build sets an output directory");

  const sources = tsconfig.files ?? [];
  assert.ok(sources.includes("handler.ts"), "the build compiles handler.ts");
  const emitted = join(outDir, basename("handler.ts", extname("handler.ts")) + ".js");
  assert.equal(normalize(start[1]), normalize(emitted), "npm start runs the compiled handler");
  assert.equal(normalize(pkg.main), normalize(emitted), "main names the compiled handler");
});
