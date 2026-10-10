// Example checks. npm test at the repository root installs the example's
// dependencies and runs every test file. To run this file alone:
//   (cd examples/validated-task-handler && npm ci)
//   node --test test/examples.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, posix } from "node:path";
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

// The fields of package.json that npm install records in the lock file's root
// entry, as measured with npm 11.19.0.
const rootEntryFields = [
  "name",
  "version",
  "license",
  "funding",
  "bin",
  "engines",
  "os",
  "cpu",
  "libc",
  "deprecated",
  "hasInstallScript",
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "acceptDependencies",
  "bundleDependencies",
  "workspaces",
];

// The bin npm records for a package.json: each command with the path of its
// file inside the package. A command is named after the last segment of its
// name once that name is resolved as a path, so a bin named a/b/.. is a. A bin
// that is one path is a command named after the package, a bin that is a list
// names each command after its file, and an entry left without a name or a
// path is dropped.
function recordedBin({ name, bin }) {
  if (typeof bin === "string") bin = name ? { [name]: bin } : {};
  if (Array.isArray(bin)) bin = Object.fromEntries(bin.map((path) => [path, path]));
  const recorded = {};
  for (const [command, path] of Object.entries(bin ?? {})) {
    const base = posix.basename(posix.join("/", command.replace(/[\\:]/g, "/")));
    const file = typeof path === "string" ? posix.join("/", path.replace(/\\/g, "/")).slice(1) : "";
    if (base && file) recorded[base] = file;
  }
  return recorded;
}

// The root entry npm install writes to the lock file for a package.json,
// measured with npm 11.19.0. It leaves out a field whose value is falsy, an
// empty object or an empty array, except devDependencies, which it leaves out
// only when falsy. It records a license object as its type when that type is
// truthy, even an empty object or array, a funding string
// as an object with that url, bin as recordedBin returns it, hasInstallScript
// as true when that field is truthy or a preinstall, install or postinstall
// script is a non-empty string, dependencies without the packages
// optionalDependencies also lists, and bundleDependencies as a list of names,
// read from bundledDependencies when it is not set.
//
// Three measured cases are not handled. In each, npm 11.19.0 can record
// another bin than this function returns, and the lock file check then fails
// for a lock file npm has just written. With directories.bin and no bin, npm
// fills bin from that directory, which this function does not read. A colon
// in a bin path becomes a slash: for bin { a: "c:d.js" }, npm records
// { a: "c/d.js" }. A command renamed to the name of a later one keeps its own
// file: for bin { "a/b": "x.js", b: "y.js" }, npm records { b: "x.js" }.
function rootEntry(pkg) {
  const installScripts = ["preinstall", "install", "postinstall"].map((name) => pkg.scripts?.[name]);
  const optional = pkg.optionalDependencies && typeof pkg.optionalDependencies === "object" ? pkg.optionalDependencies : {};
  let bundle = pkg.bundleDependencies !== undefined ? pkg.bundleDependencies : pkg.bundledDependencies;
  if (bundle === true) bundle = Object.keys(pkg.dependencies ?? {});
  else if (bundle && typeof bundle === "object") bundle = Array.isArray(bundle) ? bundle : Object.keys(bundle);
  else bundle = undefined;
  const rewritten = {
    license: pkg.license?.type || pkg.license,
    funding: pkg.funding && typeof pkg.funding === "string" ? { url: pkg.funding } : pkg.funding,
    bin: recordedBin(pkg),
    hasInstallScript: Boolean(pkg.hasInstallScript) || installScripts.some((script) => script && typeof script === "string"),
    dependencies:
      pkg.dependencies && Object.fromEntries(Object.entries(pkg.dependencies).filter(([name]) => !(name in optional))),
    bundleDependencies: bundle,
  };
  const entry = {};
  for (const field of rootEntryFields) {
    const value = field in rewritten ? rewritten[field] : pkg[field];
    const keptEmpty = field === "devDependencies" || (field === "license" && Boolean(pkg.license?.type));
    const empty = typeof value === "object" && !keptEmpty && Object.keys(value ?? {}).length === 0;
    if (value && !empty) entry[field] = value;
  }
  return entry;
}

// Fail unless lock, a parsed package-lock.json, is the lock file of pkg, the
// parsed package.json beside it in dir. A lock file whose root entry differs
// from the one npm install writes is rewritten by the next npm install.
function assertLockMatches(pkg, lock, dir = "") {
  assert.ok(lock.lockfileVersion >= 1, `${dir}package-lock.json has lockfileVersion >= 1`);
  assert.equal(lock.name, pkg.name, `${dir}package-lock.json names the package in ${dir}package.json`);
  const locked = lock.packages?.[""] ?? {};
  const written = rootEntry(pkg);
  for (const field of rootEntryFields) {
    assert.deepEqual(locked[field], written[field], `${dir}package-lock.json records the ${field} of ${dir}package.json`);
  }
}

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
    assertLockMatches(pkg, JSON.parse(readFileSync(lockPath, "utf8")), dir);
  }
});

// A lock file for a package named example, with entry in its root entry.
function lockWith(entry) {
  return { name: "example", lockfileVersion: 3, requires: true, packages: { "": { name: "example", ...entry } } };
}

// The message the lock file check fails with for a field of the root entry.
function stale(field) {
  return new RegExp(`package-lock\\.json records the ${field} of package\\.json`);
}

test("the lock file check fails for a lock file whose root entry lacks the funding or the bin of package.json", () => {
  const funding = { url: "https://example.com" };
  const bin = { example: "cli.js" };
  const pkg = { name: "example", funding, bin };
  assert.doesNotThrow(() => assertLockMatches(pkg, lockWith({ funding, bin })));
  assert.throws(() => assertLockMatches(pkg, lockWith({ bin })), stale("funding"));
  assert.throws(() => assertLockMatches(pkg, lockWith({ funding })), stale("bin"));
  // npm records a funding string as an object and a bin path under the package name.
  const short = { name: "example", funding: "https://example.com", bin: "./cli.js" };
  assert.doesNotThrow(() => assertLockMatches(short, lockWith({ funding, bin })));
  assert.throws(() => assertLockMatches(short, lockWith({ funding: short.funding, bin })), stale("funding"));
  assert.throws(() => assertLockMatches(short, lockWith({ funding, bin: short.bin })), stale("bin"));
});

test("the lock file check fails for a lock file whose root entry lacks the libc of package.json or holds another", () => {
  const pkg = { name: "example", libc: ["glibc"] };
  assert.doesNotThrow(() => assertLockMatches(pkg, lockWith({ libc: ["glibc"] })));
  assert.throws(() => assertLockMatches(pkg, lockWith({})), stale("libc"));
  assert.throws(() => assertLockMatches(pkg, lockWith({ libc: ["musl"] })), stale("libc"));
});

test("the lock file check expects hasInstallScript in the root entry when package.json has an install script", () => {
  const pkg = { name: "example", scripts: { preinstall: "node --version" } };
  assert.doesNotThrow(() => assertLockMatches(pkg, lockWith({ hasInstallScript: true })));
  // The next npm install adds hasInstallScript to a root entry that lacks it.
  assert.throws(() => assertLockMatches(pkg, lockWith({})), stale("hasInstallScript"));
  // npm records a hasInstallScript of "yes" as true.
  const field = { name: "example", hasInstallScript: "yes" };
  assert.doesNotThrow(() => assertLockMatches(field, lockWith({ hasInstallScript: true })));
  assert.throws(() => assertLockMatches(field, lockWith({ hasInstallScript: "yes" })), stale("hasInstallScript"));
});

test("the lock file check passes for a package.json value npm leaves out of the lock file, and fails for a lock file that holds one", () => {
  const empty = { name: "example", os: [], cpu: [], engines: {}, dependencies: {}, license: "" };
  assert.doesNotThrow(() => assertLockMatches(empty, lockWith({})));
  // The next npm install removes an empty value from the root entry.
  assert.throws(() => assertLockMatches(empty, lockWith({ os: [] })), stale("os"));
  assert.throws(() => assertLockMatches(empty, lockWith({ engines: {} })), stale("engines"));
  // Empty devDependencies are the one empty value npm records.
  const noDevDependencies = { name: "example", devDependencies: {} };
  assert.doesNotThrow(() => assertLockMatches(noDevDependencies, lockWith({ devDependencies: {} })));
  assert.throws(() => assertLockMatches(noDevDependencies, lockWith({})), stale("devDependencies"));
});

test("the lock file check expects the root entry npm 11.19.0 writes for a package.json", () => {
  // Each pair is a package.json and the root entry of the lock file that
  // npm install --package-lock-only, npm 11.19.0, wrote for it.
  const one = "file:./one";
  const two = "file:./two";
  const measured = [
    // Fields copied as they are, a scoped name, and empty values left out.
    [
      {
        name: "@scope/probe", version: "1.2.3", license: "MIT", funding: "https://example.com/fund", bin: "./cli.js",
        os: [], cpu: ["arm64"], engines: {}, peerDependenciesMeta: { x: { optional: true } }, bundleDependencies: [],
        workspaces: [], deprecated: "no", hasInstallScript: true, acceptDependencies: {}, description: "d",
        scripts: { install: "true" },
      },
      {
        name: "@scope/probe", version: "1.2.3", cpu: ["arm64"], deprecated: "no", hasInstallScript: true, license: "MIT",
        bin: { probe: "cli.js" }, funding: { url: "https://example.com/fund" },
        peerDependenciesMeta: { x: { optional: true } },
      },
    ],
    // A license object, a funding list, and bin entries npm rewrites or drops.
    [
      {
        name: "probe",
        license: { type: "MIT", url: "https://example.com/license" },
        funding: [{ type: "x", url: "https://example.com/a" }, "https://example.com/b"],
        bin: { a: "./bin/a.js", "dir/b": "bin\\b.js", c: 7, d: "../../up/d.js", "": "e.js", f: "" },
      },
      {
        name: "probe",
        funding: [{ type: "x", url: "https://example.com/a" }, "https://example.com/b"],
        license: "MIT",
        bin: { a: "bin/a.js", b: "bin/b.js", d: "up/d.js" },
      },
    ],
    [
      { name: "probe", bin: ["./bin/one.js", "two.js"], funding: { type: "individual", url: "https://example.com/c" } },
      { name: "probe", bin: { "one.js": "bin/one.js", "two.js": "two.js" }, funding: { type: "individual", url: "https://example.com/c" } },
    ],
    // A command name that ends in a . or .. segment is named after the segment
    // it resolves to, and the type of a license object is recorded even when empty.
    [
      {
        name: "probe", license: { type: {} },
        bin: { "a/b/..": "x.js", "c\\d\\.": "y.js", "e/f/../../g/h/..": "z.js", "..": "w.js", "i:..": "v.js" },
      },
      { name: "probe", bin: { a: "x.js", d: "y.js", g: "z.js" }, license: {} },
    ],
    [{ name: "probe", bin: { "a/.": "x.js" } }, { name: "probe", bin: { a: "x.js" } }],
    [{ name: "probe", license: { type: [] } }, { name: "probe", license: [] }],
    [{ name: "probe", license: "", funding: "", bin: {}, cpu: [], os: ["darwin"] }, { name: "probe", os: ["darwin"] }],
    // Measured on Linux with glibc: on macOS npm install stops with
    // EBADPLATFORM for this package.json.
    [{ name: "probe", libc: ["glibc"] }, { name: "probe", libc: ["glibc"] }],
    // An install script without the field, a field that is not true, and
    // scripts that are not install scripts.
    [{ name: "probe", scripts: { preinstall: "true" } }, { name: "probe", hasInstallScript: true }],
    [{ name: "probe", scripts: { install: "true" } }, { name: "probe", hasInstallScript: true }],
    [{ name: "probe", scripts: { postinstall: "true" } }, { name: "probe", hasInstallScript: true }],
    [{ name: "probe", hasInstallScript: "yes" }, { name: "probe", hasInstallScript: true }],
    [{ name: "probe", scripts: { preinstall: "", install: 7, postinstall: ["true"], prepare: "true" } }, { name: "probe" }],
    // A bin path has no command name in a package without a name.
    [{ bin: "cli.js", funding: [] }, {}],
    // A package in optionalDependencies is left out of dependencies.
    [
      {
        name: "probe", version: "1.0.0", dependencies: { one, two }, optionalDependencies: { two },
        bundleDependencies: ["one"], acceptDependencies: { one }, workspaces: ["packages/*"],
      },
      {
        name: "probe", version: "1.0.0", bundleDependencies: ["one"], workspaces: ["packages/*"],
        dependencies: { one }, acceptDependencies: { one }, optionalDependencies: { two },
      },
    ],
    [
      {
        name: "probe", dependencies: { one }, optionalDependencies: { one }, bundledDependencies: true,
        workspaces: { packages: ["packages/*"] },
      },
      { name: "probe", bundleDependencies: ["one"], optionalDependencies: { one }, workspaces: { packages: ["packages/*"] } },
    ],
    // Empty devDependencies, which npm records, and the other forms of bundleDependencies.
    [
      {
        name: "probe", dependencies: {}, devDependencies: {}, optionalDependencies: {}, peerDependencies: {},
        bundleDependencies: { one: true, two: false },
      },
      { name: "probe", bundleDependencies: ["one", "two"], devDependencies: {} },
    ],
    [
      { name: "probe", bundleDependencies: ["one"], bundledDependencies: ["two"], license: ["MIT"], os: "darwin", engines: ["node >=18"] },
      { name: "probe", bundleDependencies: ["one"], engines: ["node >=18"], license: ["MIT"], os: "darwin" },
    ],
    [
      { name: "probe", bundleDependencies: "one", bundledDependencies: ["two"], license: { url: "https://example.com/license" } },
      { name: "probe", license: { url: "https://example.com/license" } },
    ],
    [
      { name: "probe", bundledDependencies: ["two"], devDependencies: { one }, dependencies: { one } },
      { name: "probe", bundleDependencies: ["two"], dependencies: { one }, devDependencies: { one } },
    ],
    // No other field of this package.json reaches the root entry.
    [
      {
        name: "probe", version: "1.0.0", private: true, description: "d", keywords: ["k"],
        homepage: "https://example.com", bugs: "https://example.com/bugs", author: "A", contributors: ["B"],
        maintainers: ["C"], files: ["lib"], main: "index.js", module: "index.mjs", browser: "browser.js",
        exports: "./index.js", imports: { "#x": "./x.js" }, type: "module", types: "index.d.ts", man: "./man/doc.1",
        directories: { lib: "lib" }, repository: "github:example/probe", scripts: { test: "true" }, config: { x: 1 },
        overrides: {}, devEngines: { runtime: { name: "node" } }, publishConfig: { access: "public" },
        packageManager: "npm@11.19.0", sideEffects: false, gypfile: true, preferGlobal: true, allowScripts: { x: true },
        licenses: [{ type: "MIT" }], _integrity: "sha512-x", _hasShrinkwrap: true, _resolved: "x", bundleDependencies: false,
      },
      { name: "probe", version: "1.0.0" },
    ],
  ];
  for (const [pkg, entry] of measured) {
    assert.deepEqual(rootEntry(pkg), entry, `the root entry for ${JSON.stringify(pkg)}`);
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
