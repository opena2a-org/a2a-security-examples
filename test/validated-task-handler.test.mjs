// validated-task-handler checks. npm test at the repository root installs the
// example's dependencies and runs every test file. To run this file alone:
//   (cd examples/validated-task-handler && npm ci)
//   node --test test/validated-task-handler.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const example = join(root, "examples/validated-task-handler");
const tsc = join(example, "node_modules/typescript/bin/tsc");
const tsx = join(example, "node_modules/tsx/dist/cli.mjs");

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

let server;
let port;
let output = "";

// Complete JSON lines the server has written so far.
function auditLines() {
  return output
    .split("\n")
    .slice(0, -1)
    .filter((l) => l.startsWith("{"))
    .map((l) => JSON.parse(l));
}

// The server's stdout can arrive after its HTTP response, so poll for it.
async function waitForAudit(count) {
  for (let i = 0; i < 100 && auditLines().length < count; i++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return auditLines();
}

function postTask(headers, body) {
  return fetch(`http://127.0.0.1:${port}/tasks`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body,
  });
}

const validTask = JSON.stringify({
  task: { message: { role: "user", parts: [{ type: "text", text: "Hello" }] } },
});

before(async () => {
  assert.ok(existsSync(tsx), "run npm ci in examples/validated-task-handler first");
  port = await freePort();
  const env = { ...process.env, PORT: String(port) };
  delete env.AGENT_URL;
  server = spawn(process.execPath, [tsx, "handler.ts"], { cwd: example, env });
  server.stdout.on("data", (chunk) => (output += chunk));
  server.stderr.on("data", (chunk) => (output += chunk));
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start:\n${output}`)), 30000);
    server.stdout.on("data", () => {
      if (output.includes("listening on port")) {
        clearTimeout(timer);
        resolve();
      }
    });
    server.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited with ${code}:\n${output}`));
    });
  });
});

after(() => {
  server?.kill();
});

test("package-lock.json pins the dependencies package.json declares", () => {
  const pkg = JSON.parse(readFileSync(join(example, "package.json"), "utf8"));
  const lockPath = join(example, "package-lock.json");
  assert.ok(existsSync(lockPath), "examples/validated-task-handler/package-lock.json is committed");
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  assert.deepEqual(lock.packages[""].dependencies, pkg.dependencies);
  assert.deepEqual(lock.packages[""].devDependencies, pkg.devDependencies);
});

test("the TypeScript build emits the file npm start runs", () => {
  const pkg = JSON.parse(readFileSync(join(example, "package.json"), "utf8"));
  assert.equal(pkg.scripts.build, "tsc");
  assert.equal(pkg.scripts.start, `node ${pkg.main}`);
  const tsconfig = JSON.parse(readFileSync(join(example, "tsconfig.json"), "utf8"));
  const configuredOutDir = tsconfig.compilerOptions?.outDir;
  assert.ok(configuredOutDir, "tsconfig.json sets outDir");
  const main = relative(configuredOutDir, pkg.main);
  assert.ok(!main.startsWith("..") && !isAbsolute(main), `${pkg.main} is inside outDir ${configuredOutDir}`);
  // Build into a temporary directory so the test leaves dist/ untouched.
  const outDir = mkdtempSync(join(tmpdir(), "a2a-build-"));
  try {
    const build = spawnSync(process.execPath, [tsc, "-p", example, "--outDir", outDir], { encoding: "utf8" });
    assert.equal(build.status, 0, build.stdout + build.stderr);
    assert.ok(existsSync(join(outDir, main)), `tsc emits ${pkg.main}`);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("the agent card URL uses the port the server listens on", async () => {
  const res = await fetch(`http://127.0.0.1:${port}/.well-known/agent.json`);
  assert.equal(res.status, 200);
  const card = await res.json();
  assert.equal(card.url, `http://localhost:${port}`);
});

test("malformed JSON gets a JSON 400 and an audit line, not a stack trace", async () => {
  const seen = auditLines().length;
  const res = await postTask({ Authorization: "Bearer demo-token" }, "{bad");
  assert.equal(res.status, 400);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/);
  const body = await res.text();
  assert.doesNotMatch(body, /at parse \(|node_modules/);
  assert.deepEqual(JSON.parse(body), { error: "Invalid JSON" });
  const audited = (await waitForAudit(seen + 1)).slice(seen);
  assert.equal(audited.length, 1, `one audit line for the rejected body:\n${output}`);
  assert.equal(audited[0].action, "request_rejected");
  assert.deepEqual(audited[0].details, { status: 400, reason: "entity.parse.failed" });
  assert.doesNotMatch(output, /at parse \(/, "the stack trace is not written to the server log");
});

test("a body over 1 MB or in an unsupported encoding or charset gets a JSON error and a request_rejected audit line", async () => {
  const cases = [
    { headers: {}, body: JSON.stringify({ text: "a".repeat(1100 * 1024) }), status: 413, reason: "entity.too.large" },
    { headers: { "Content-Encoding": "br2" }, body: "{}", status: 415, reason: "encoding.unsupported" },
    { headers: { "Content-Type": "application/json; charset=latin1" }, body: "{}", status: 415, reason: "charset.unsupported" },
  ];
  for (const { headers, body, status, reason } of cases) {
    const seen = auditLines().length;
    const res = await postTask({ Authorization: "Bearer demo-token", ...headers }, body);
    assert.equal(res.status, status);
    assert.deepEqual(await res.json(), { error: "Invalid request body" });
    const audited = (await waitForAudit(seen + 1)).slice(seen);
    assert.equal(audited.length, 1, `one audit line for the rejected body:\n${output}`);
    assert.equal(audited[0].action, "request_rejected");
    assert.deepEqual(audited[0].details, { status, reason });
  }
});

test("a JSON body that is not an object or array gets the same 400 as malformed JSON", async () => {
  // The parser runs in strict mode, so valid JSON such as 123 is rejected.
  for (const body of ["123", '"text"', "null"]) {
    const seen = auditLines().length;
    const res = await postTask({ Authorization: "Bearer demo-token" }, body);
    assert.equal(res.status, 400, `body ${body}`);
    assert.deepEqual(await res.json(), { error: "Invalid JSON" });
    const audited = (await waitForAudit(seen + 1)).slice(seen);
    assert.equal(audited.length, 1, `one audit line for the body ${body}:\n${output}`);
    assert.equal(audited[0].action, "request_rejected");
    assert.deepEqual(audited[0].details, { status: 400, reason: "entity.parse.failed" });
  }
});

test("an empty body or a body not sent as application/json fails schema validation, not JSON parsing", async () => {
  // The parser reads an empty body as {} and skips a body that is not declared
  // as JSON, so the schema step answers both.
  const cases = [
    { name: "an empty application/json body", headers: {}, body: undefined },
    { name: "a text/plain body", headers: { "Content-Type": "text/plain" }, body: "hello" },
  ];
  for (const { name, headers, body } of cases) {
    const seen = auditLines().length;
    const res = await postTask({ Authorization: "Bearer demo-token", ...headers }, body);
    assert.equal(res.status, 400, name);
    assert.deepEqual(
      await res.json(),
      { error: "Invalid task format", details: [{ field: "task", message: "Required" }] },
      name
    );
    const audited = (await waitForAudit(seen + 1)).slice(seen);
    assert.equal(audited.length, 1, `one audit line for ${name}:\n${output}`);
    assert.equal(audited[0].action, "validation_failed");
  }
});

test("a compressed body that does not inflate gets a JSON 400 and a request_rejected audit line naming the inflate failure", async () => {
  const cases = [
    { encoding: "gzip", body: "notgzipdata-notgzipdata-xxxx" },
    { encoding: "deflate", body: "notgzipdata-notgzipdata-xxxx" },
    // A real gzip stream cut off part way fails with a different zlib code.
    { encoding: "gzip", body: gzipSync(validTask).subarray(0, 20) },
  ];
  for (const { encoding, body } of cases) {
    const seen = auditLines().length;
    const res = await postTask({ Authorization: "Bearer demo-token", "Content-Encoding": encoding }, body);
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "Invalid request body" });
    const audited = (await waitForAudit(seen + 1)).slice(seen);
    assert.equal(audited.length, 1, `one audit line for the ${encoding} body:\n${output}`);
    assert.equal(audited[0].action, "request_rejected");
    assert.deepEqual(audited[0].details, { status: 400, reason: "body.inflate.failed" });
  }
});

test("a body cut off by a closed connection gets at most a bare 400 and a request_rejected audit line", async () => {
  const seen = auditLines().length;
  const head = [
    "POST /tasks HTTP/1.1",
    "Host: 127.0.0.1",
    "Authorization: Bearer demo-token",
    "Content-Type: application/json",
    "Content-Length: 100",
    "",
    "",
  ].join("\r\n");
  // Send 6 of the 100 bytes, then stop sending. The half-closed socket can
  // still read whatever the server answers before it closes the connection.
  const reply = await new Promise((resolve, reject) => {
    let data = "";
    const socket = connect(port, "127.0.0.1", () => {
      socket.write(head + '{"a":1');
      setTimeout(() => socket.end(), 300);
    });
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => (data += chunk));
    socket.on("error", reject);
    socket.on("close", () => resolve(data));
  });
  // Either nothing, or a 400 status line and headers with no body after them.
  assert.match(
    reply,
    /^(HTTP\/1\.1 400 Bad Request\r\n(?:[^\r\n]+\r\n)*\r\n)?$/,
    `the client gets at most a bare HTTP 400 with no body:\n${reply}`
  );
  const audited = (await waitForAudit(seen + 1)).slice(seen);
  assert.equal(audited.length, 1, `one audit line for the truncated body:\n${output}`);
  assert.equal(audited[0].action, "request_rejected");
  assert.deepEqual(audited[0].details, { status: 400, reason: "request.aborted" });
});

test("unknown routes get a JSON 404, not the framework's HTML page", async () => {
  for (const path of ["/nope", "/tasks"]) {
    const res = await fetch(`http://127.0.0.1:${port}${path}`);
    assert.equal(res.status, 404, `GET ${path}`);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/, `GET ${path}`);
    assert.deepEqual(await res.json(), { error: "Not found" });
  }
});

test("a PORT that is not a port number exits with one line naming PORT", () => {
  // "1e3", "0x50" and " 3000" are numbers to Number(); only digits are a port.
  // An empty PORT is rejected too, not treated as unset.
  for (const value of ["abc", "65536", "1e3", "0x50", " 3000", ""]) {
    const run = spawnSync(process.execPath, [tsx, "handler.ts"], {
      cwd: example,
      env: { ...process.env, PORT: value },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.equal(run.status, 1, `PORT=${value}:\n${run.stdout}${run.stderr}`);
    assert.equal(run.stdout, "", `PORT=${value} starts no server`);
    assert.deepEqual(run.stderr.trim().split("\n"), [`PORT must be a number from 1 to 65535; got "${value}"`]);
  }
});

test("a PORT already in use exits with one line naming the port", () => {
  // The server started in before() holds the port.
  const run = spawnSync(process.execPath, [tsx, "handler.ts"], {
    cwd: example,
    env: { ...process.env, PORT: String(port) },
    encoding: "utf8",
    timeout: 30000,
  });
  assert.equal(run.status, 1, `PORT=${port}:\n${run.stdout}${run.stderr}`);
  assert.equal(run.stdout, "", "no listening message for a port the server could not bind");
  assert.deepEqual(run.stderr.trim().split("\n"), [`Port ${port} is already in use; set PORT to a free port`]);
});

// Start the example with a module loaded first that changes how the HTTP
// server listens, and return the finished run.
function runWithPreload(preload, env) {
  const dir = mkdtempSync(join(tmpdir(), "a2a-preload-"));
  try {
    const file = join(dir, "preload.mjs");
    writeFileSync(file, preload);
    const nodeOptions = [process.env.NODE_OPTIONS, `--import=${pathToFileURL(file).href}`];
    return spawnSync(process.execPath, [tsx, "handler.ts"], {
      cwd: example,
      env: { ...process.env, ...env, NODE_OPTIONS: nodeOptions.filter(Boolean).join(" ") },
      encoding: "utf8",
      timeout: 30000,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a listen failure other than a port in use exits with one line naming the port and the error", () => {
  // Fail the listen call the way a refused bind would, without binding.
  const run = runWithPreload(
    `import { Server } from "node:http";
Server.prototype.listen = function () {
  process.nextTick(() => this.emit("error", Object.assign(new Error("listen EACCES: permission denied"), { code: "EACCES" })));
  return this;
};
`,
    { PORT: "3999" }
  );
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.equal(run.stdout, "", "no listening message for a port the server could not bind");
  assert.deepEqual(run.stderr.trim().split("\n"), ["Cannot listen on port 3999: listen EACCES: permission denied"]);
});

test("a server error after the server is listening is not reported as a listen failure", async () => {
  // Raise an accept failure once the server has started listening.
  const errorPort = await freePort();
  const run = runWithPreload(
    `import { Server } from "node:http";
const listen = Server.prototype.listen;
Server.prototype.listen = function (...args) {
  this.once("listening", () =>
    setImmediate(() => this.emit("error", Object.assign(new Error("accept EMFILE"), { code: "EMFILE" })))
  );
  return listen.apply(this, args);
};
`,
    { PORT: String(errorPort) }
  );
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.match(run.stdout, /listening on port/, "the error came after the server started listening");
  assert.deepEqual(run.stderr.trim().split("\n"), [`Server error on port ${errorPort}: accept EMFILE`]);
});

test("malformed JSON without a bearer token gets 401 and no audit line", async () => {
  const seen = auditLines().length;
  const res = await postTask({}, "{bad");
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: "Authentication required" });
  // A valid task afterwards writes exactly one line, so the 401 wrote none.
  const accepted = await postTask({ Authorization: "Bearer demo-token" }, validTask);
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).task.status, "completed");
  const audited = (await waitForAudit(seen + 1)).slice(seen);
  assert.deepEqual(audited.map((a) => a.action), ["task_accepted"]);
});
