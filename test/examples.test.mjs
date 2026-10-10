// Example checks. npm test at the repository root installs the example's
// dependencies and runs every test file. To run this file alone:
//   (cd examples/validated-task-handler && npm ci)
//   node --test test/examples.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const typescript = join(root, "examples/validated-task-handler/node_modules/typescript/lib/typescript.js");

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

// The names each module imports and never reads, as the TypeScript compiler
// the example installs reports them, so a name that appears only in a comment
// or a string is not a use. sources maps a file name to the module's text.
function unusedImports(sources) {
  assert.ok(existsSync(typescript), "run npm ci in examples/validated-task-handler first");
  const ts = createRequire(import.meta.url)(typescript);
  const options = { allowJs: true, checkJs: true, noEmit: true, noResolve: true, noUnusedLocals: true, types: [] };
  const host = ts.createCompilerHost(options);
  const readLibrary = host.getSourceFile;
  host.getSourceFile = (file, languageVersion) =>
    file in sources ? ts.createSourceFile(file, sources[file], languageVersion) : readLibrary(file, languageVersion);
  const program = ts.createProgram(Object.keys(sources), options, host);
  const unused = [];
  for (const file of Object.keys(sources)) {
    const source = program.getSourceFile(file);
    // TS6133 starts at the unused name. When no name in an import statement is
    // read, TS6133 (one name) or TS6192 (several) starts at the statement.
    const reported = new Set(
      program
        .getSemanticDiagnostics(source)
        .filter((diagnostic) => diagnostic.code === 6133 || diagnostic.code === 6192)
        .map((diagnostic) => diagnostic.start)
    );
    for (const statement of source.statements.filter(ts.isImportDeclaration)) {
      const { name, namedBindings } = statement.importClause ?? {};
      const names = [name, namedBindings?.name, ...(namedBindings?.elements ?? []).map((element) => element.name)];
      for (const imported of names.filter(Boolean)) {
        if (reported.has(statement.getStart(source)) || reported.has(imported.getStart(source))) {
          unused.push(`${file} imports ${imported.text} and never uses it`);
        }
      }
    }
  }
  return unused;
}

test("every test file uses each name it imports", () => {
  const sources = {};
  for (const name of readdirSync(join(root, "test")).filter((file) => file.endsWith(".mjs"))) {
    sources[`test/${name}`] = readFileSync(join(root, "test", name), "utf8");
  }
  assert.deepEqual(unusedImports(sources), []);
});

test("the import check reports a name that appears only in a comment, a string or a regular expression", () => {
  const mentions = {
    "line-comment.mjs": "// pathToFileURL",
    "block-comment.mjs": "/* pathToFileURL */",
    "string.mjs": 'console.log("pathToFileURL");',
    "template.mjs": "console.log(`pathToFileURL`);",
    "regular-expression.mjs": "console.log(/pathToFileURL/);",
  };
  const sources = {};
  for (const [file, mention] of Object.entries(mentions)) {
    sources[file] = `import { fileURLToPath, pathToFileURL } from "node:url";\n${mention}\nfileURLToPath(import.meta.url);\n`;
  }
  assert.deepEqual(
    unusedImports(sources),
    Object.keys(mentions).map((file) => `${file} imports pathToFileURL and never uses it`)
  );
});

test("the import check reads an import statement that has a trailing comment or no semicolon", () => {
  const endings = {
    "line-comment.mjs": "; // url helpers",
    "block-comment.mjs": "; /* url helpers */",
    "no-semicolon.mjs": "",
  };
  const sources = {};
  for (const [file, ending] of Object.entries(endings)) {
    sources[file] = `import { fileURLToPath, pathToFileURL } from "node:url"${ending}\nfileURLToPath(import.meta.url);\n`;
  }
  assert.deepEqual(
    unusedImports(sources),
    Object.keys(endings).map((file) => `${file} imports pathToFileURL and never uses it`)
  );
});

test("the import check reports every form of import and counts only a read of the imported name as a use", () => {
  const sources = {
    "forms.mjs": 'import fallback, * as everything from "a";\nimport { first as renamed, second } from "b";\nimport alone from "c";\nimport "d";\n',
    "partly-used.mjs": 'import fallback, { first as renamed, second } from "a";\nimport other, * as everything from "b";\nconsole.log(second, other);\n',
    "shadowed.mjs": 'import { join } from "node:path";\nconst paths = { join: 1 };\nfunction last(join) {\n  return join;\n}\nconsole.log(last(paths.join));\n',
    "used.mjs": 'import { join } from "node:path";\nimport fallback, * as everything from "a";\nconsole.log(`${join("a", "b")}`, { fallback }, everything.name);\n',
  };
  assert.deepEqual(unusedImports(sources), [
    "forms.mjs imports fallback and never uses it",
    "forms.mjs imports everything and never uses it",
    "forms.mjs imports renamed and never uses it",
    "forms.mjs imports second and never uses it",
    "forms.mjs imports alone and never uses it",
    "partly-used.mjs imports fallback and never uses it",
    "partly-used.mjs imports renamed and never uses it",
    "partly-used.mjs imports everything and never uses it",
    "shadowed.mjs imports join and never uses it",
  ]);
});
