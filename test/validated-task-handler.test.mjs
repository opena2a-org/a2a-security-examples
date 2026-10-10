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
import { fileURLToPath } from "node:url";
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

// Stop tsx and the server process it starts without relying on tsx to pass a
// signal on. On POSIX they share the process group spawnExample creates, so one
// signal reaches both. On Windows ChildProcess.kill() ends tsx alone and the
// server keeps running with tsx's stdout and stderr open, so taskkill ends the
// whole process tree. Windows has no signals; signal applies on POSIX only.
function stopServer(proc, signal = "SIGTERM") {
  // A process that could not be spawned has no pid and nothing to stop.
  if (proc.pid === undefined) return;
  if (process.platform === "win32") {
    // A tree that has already exited makes taskkill fail with nothing to stop.
    const run = spawnSync("taskkill", ["/pid", String(proc.pid), "/t", "/f"], { stdio: "ignore" });
    if (run.error) throw run.error;
    return;
  }
  try {
    process.kill(-proc.pid, signal);
  } catch (err) {
    // macOS answers EPERM for a group whose processes have all exited but are
    // not yet reaped, which leaves nothing to stop.
    if (err.code !== "ESRCH" && err.code !== "EPERM") throw err;
  }
}

// Servers spawnExample has started whose output pipes are still open. The pipes
// close only once tsx and the server it started have both exited.
const started = new Set();

// Start tsx and the example. On POSIX tsx leads a process group of its own, so
// stopServer reaches the server tsx starts without tsx passing a signal on.
function spawnExample(env, cwd = example) {
  const proc = spawn(process.execPath, [tsx, "handler.ts"], {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32",
  });
  if (proc.pid !== undefined) {
    started.add(proc);
    proc.once("close", () => started.delete(proc));
  }
  return proc;
}

// Ctrl-C signals only the terminal's foreground process group, which the
// servers have left, and an interrupted run never reaches the after() hook or
// the finally blocks that stop them. So stop every server still running, then
// let the signal end this process as it would have. On Windows the servers
// share the console and receive Ctrl-C themselves.
if (process.platform !== "win32") {
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.once(signal, () => {
      for (const proc of started) stopServer(proc);
      process.kill(process.pid, signal);
    });
  }
}

// Wait for promise, and fail with message after ms instead of waiting forever.
async function within(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// Wait for closed, the close event of proc, and fail with message after ms
// instead of waiting forever. When the wait fails, proc and its stdout and
// stderr pipes are unref'd: a process still running would otherwise keep the
// test process alive, and the run would never end or print the failure.
async function closedWithin(proc, closed, ms, message) {
  try {
    await within(closed, ms, message);
  } catch (err) {
    proc.unref();
    proc.stdout?.unref();
    proc.stderr?.unref();
    throw err;
  }
}

// Start the example on a port and resolve with its process once it is
// listening. The process and its pipes are unref'd: Node.js 18 runs a
// top-level after() hook only once nothing keeps the test process alive, so a
// referenced server would keep the after() hook that stops it from running.
async function startServer(serverPort, onOutput = () => {}, cwd = example) {
  const env = { ...process.env, PORT: String(serverPort) };
  delete env.AGENT_URL;
  const proc = spawnExample(env, cwd);
  proc.unref();
  proc.stdout.unref();
  proc.stderr.unref();
  let seen = "";
  const record = (chunk) => {
    seen += chunk;
    onOutput(chunk);
  };
  proc.stdout.on("data", record);
  proc.stderr.on("data", record);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      stopServer(proc);
      reject(new Error(`server did not start:\n${seen}`));
    }, 30000);
    proc.stdout.on("data", () => {
      if (seen.includes("listening on port")) {
        clearTimeout(timer);
        resolve();
      }
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited with ${code}:\n${seen}`));
    });
    // A process that cannot be spawned emits error, never exit.
    proc.once("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`server did not start: ${err.message}\n${seen}`));
    });
  });
  return proc;
}

// Processes and pipes that keep this process alive; unref'd ones are not listed.
function heldHandles() {
  return process.getActiveResourcesInfo().filter((r) => r === "ProcessWrap" || r === "PipeWrap").length;
}

// Whether any process in the group led by pid is still running. A group whose
// processes have all exited counts as running until they are reaped: macOS
// answers EPERM for it until then and ESRCH after.
function groupRunning(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (err) {
    if (err.code === "ESRCH") return false;
    if (err.code === "EPERM") return true;
    throw err;
  }
}

// Why ps cannot run here with args, or false when it can. Some container images
// do not install ps, and BusyBox ps, in Alpine images, starts but rejects -p.
// Each test that reads processes with ps is skipped where its ps calls fail.
function psUnavailable(args) {
  const { error, status } = spawnSync("ps", args);
  if (error) return `ps cannot run here: ${error.message}`;
  return status === 0 ? false : `ps ${args.join(" ")} exits with status ${status} here`;
}

// The process groups, other than its own, of the processes descended from pid.
function descendantGroups(pid) {
  const ps = spawnSync("ps", ["-A", "-o", "pid=,ppid=,pgid="], { encoding: "utf8" });
  if (ps.error) throw ps.error;
  const rows = ps.stdout.trim().split("\n").map((line) => line.trim().split(/\s+/).map(Number));
  const tree = new Set([pid]);
  for (let grew = true; grew; ) {
    grew = false;
    for (const [child, parent] of rows) {
      if (tree.has(parent) && !tree.has(child)) {
        tree.add(child);
        grew = true;
      }
    }
  }
  return new Set(rows.filter(([child, , group]) => tree.has(child) && group !== pid).map(([, , group]) => group));
}

// The process groups that have a process that has not exited. A process that
// has exited stays listed, in state Z, until it is reaped. Once its parent has
// exited, that is up to whichever process adopts it, and in a container whose
// first process is Node.js, as when docker run starts the tests without
// --init, that process never reaps it.
function liveGroups() {
  const ps = spawnSync("ps", ["-A", "-o", "pgid=,stat="], { encoding: "utf8" });
  if (ps.error) throw ps.error;
  const rows = ps.stdout.trim().split("\n").map((line) => line.trim().split(/\s+/));
  return new Set(rows.filter(([, stat]) => !stat.startsWith("Z")).map(([group]) => Number(group)));
}

before(async () => {
  assert.ok(existsSync(tsx), "run npm ci in examples/validated-task-handler first");
  port = await freePort();
  server = await startServer(port, (chunk) => (output += chunk));
});

after(() => {
  if (server) stopServer(server);
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

test("a body the parser cannot read gets Invalid request body even when it is not an object or array, or is empty", async () => {
  // The body is read before it is parsed, so these never get the Invalid JSON reply.
  const cases = [
    { headers: {}, body: " ".repeat(1100 * 1024) + "123", status: 413, reason: "entity.too.large" },
    { headers: { "Content-Encoding": "br2" }, body: "123", status: 415, reason: "encoding.unsupported" },
    { headers: { "Content-Type": "application/json; charset=latin1" }, body: "123", status: 415, reason: "charset.unsupported" },
    { headers: { "Content-Type": "application/json; charset=latin1" }, body: "", status: 415, reason: "charset.unsupported" },
  ];
  for (const { headers, body, status, reason } of cases) {
    const seen = auditLines().length;
    const res = await postTask({ Authorization: "Bearer demo-token", ...headers }, body);
    assert.equal(res.status, status, reason);
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
    { name: "an empty text/plain body", headers: { "Content-Type": "text/plain" }, body: "" },
    // The parser only reads application/json, so a +json subtype is skipped too.
    { name: "an application/vnd.api+json body", headers: { "Content-Type": "application/vnd.api+json" }, body: "123" },
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

// A task request that declares 100 body bytes and carries only the first 6.
const truncatedTask = [
  "POST /tasks HTTP/1.1",
  "Host: 127.0.0.1",
  "Authorization: Bearer demo-token",
  "Content-Type: application/json",
  "Content-Length: 100",
  "",
  '{"a":1',
].join("\r\n");

test("a body cut off by a closed connection gets at most a bare 400 and a request_rejected audit line", async () => {
  const seen = auditLines().length;
  // Send 6 of the 100 bytes, then stop sending. The half-closed socket can
  // still read whatever the server answers before it closes the connection.
  const reply = await new Promise((resolve, reject) => {
    let data = "";
    const socket = connect(port, "127.0.0.1", () => {
      socket.write(truncatedTask);
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

// NODE_OPTIONS that keep the existing value and load a CommonJS file before the
// example starts. Every Node.js 18 release accepts --require in NODE_OPTIONS;
// 18.0 to 18.17 reject --import there. NODE_OPTIONS is split on spaces, so the
// path is quoted, and inside quotes a backslash escapes the next character. It
// decodes no other escape, so a control character is written as it is.
function requireOptions(file, existing = process.env.NODE_OPTIONS) {
  const quoted = `"${file.replace(/[\\"]/g, "\\$&")}"`;
  return [existing, `--require=${quoted}`].filter(Boolean).join(" ");
}

// Node's request timeout is 300 seconds by default. This preload records the
// value the example runs with, then shortens it so the stalled-upload test
// does not wait that long. The headers timeout is shortened too: left above
// the request timeout, it is the one that applies. The interval between
// connection checks is passed to createServer because some Node.js 18 releases
// start the check when the server is created, not when it starts listening.
const stallPreload = `const http = require("node:http");
const createServer = http.createServer;
http.createServer = function (...args) {
  const options = typeof args[0] === "function" ? {} : args.shift();
  return createServer({ ...options, connectionsCheckingInterval: 100 }, ...args);
};
const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  this.once("listening", () => {
    process.stderr.write("requestTimeout " + this.requestTimeout + "\\n");
    this.headersTimeout = 500;
    this.requestTimeout = 1000;
  });
  return listen.apply(this, args);
};
`;

test("an upload that stalls until the request timeout gets a bare 408 and a request_rejected audit line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "a2a-preload-"));
  const file = join(dir, "preload.cjs");
  writeFileSync(file, stallPreload);
  const stallPort = await freePort();
  const env = { ...process.env, PORT: String(stallPort), NODE_OPTIONS: requireOptions(file) };
  delete env.AGENT_URL;
  const stalled = spawnExample(env);
  const closed = new Promise((resolve) => stalled.once("close", resolve));
  let log = "";
  stalled.stdout.on("data", (chunk) => (log += chunk));
  stalled.stderr.on("data", (chunk) => (log += chunk));
  const logLines = () => log.split("\n").slice(0, -1);
  const audited = () => logLines().filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
  try {
    for (let i = 0; i < 600 && !log.includes("listening on port"); i++) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.match(log, /listening on port/, `server did not start:\n${log}`);
    assert.ok(logLines().includes("requestTimeout 300000"), `the example runs with Node's default request timeout:\n${log}`);
    // Send 6 of the 100 bytes, then send nothing more and keep the connection open.
    const reply = await new Promise((resolve, reject) => {
      let data = "";
      const socket = connect(stallPort, "127.0.0.1", () => socket.write(truncatedTask));
      socket.setEncoding("utf8");
      socket.setTimeout(10000, () => socket.destroy(new Error(`no reply within 10 seconds:\n${data}`)));
      socket.on("data", (chunk) => (data += chunk));
      socket.on("error", reject);
      socket.on("close", () => resolve(data));
    });
    // A 408 status line and headers with no body after them.
    assert.match(
      reply,
      /^HTTP\/1\.1 408 Request Timeout\r\n(?:[^\r\n]+\r\n)*\r\n$/,
      `the client gets a bare HTTP 408 with no body:\n${reply}`
    );
    for (let i = 0; i < 100 && audited().length < 1; i++) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(audited().length, 1, `one audit line for the stalled body:\n${log}`);
    assert.equal(audited()[0].action, "request_rejected");
    // The audit line records the 408 the client received, not the 400 the
    // parser's request.aborted error carries.
    assert.deepEqual(audited()[0].details, { status: 408, reason: "request.aborted" });
  } finally {
    // stopServer ends tsx and the server without tsx passing a signal on. Wait
    // until both have exited and the stdout and stderr pipes have closed, and
    // fail rather than hang if they do not. The process handle finishes
    // closing only when the event loop runs again; the test that counts the
    // handles keeping the test process alive lets one timer turn pass before
    // it counts. The preload directory is removed even when the wait fails.
    try {
      stopServer(stalled);
      await closedWithin(stalled, closed, 10000, `tsx and the server it started did not exit within 10 seconds:\n${log}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a process that has not closed when the wait fails no longer keeps the test process alive", async () => {
  // The process is left running. Were it and its output pipes still
  // referenced, the test run would neither end nor print the failure.
  await new Promise((resolve) => setTimeout(resolve, 0));
  const baseline = heldHandles();
  const proc = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const closed = new Promise((resolve) => proc.once("close", resolve));
  try {
    assert.ok(heldHandles() > baseline, "a running process with output pipes keeps the test process alive");
    await assert.rejects(closedWithin(proc, closed, 200, "still running"), /^Error: still running$/);
    assert.equal(heldHandles(), baseline, "the process and its pipes no longer keep the test process alive");
  } finally {
    proc.kill("SIGKILL");
    await within(closed, 10000, "the process did not exit within 10 seconds of SIGKILL");
  }
});

test("stopping a server ends tsx and the server it started even when tsx cannot pass the signal on", async () => {
  // SIGKILL ends tsx at once, as ChildProcess.kill() ends it on Windows, so tsx
  // passes nothing on. A server left running keeps tsx's stdout and stderr
  // open, the close event never comes, and a test that waits for it never
  // ends. Windows has no signals; there stopServer ends the process tree.
  const proc = await startServer(await freePort());
  const closed = new Promise((resolve) => proc.once("close", resolve));
  stopServer(proc, "SIGKILL");
  await within(closed, 10000, "tsx and the server it started still hold the output pipes 10 seconds after stopServer");
});

test("the stalled-upload test loads its preload with --require, not --import", () => {
  const source = readFileSync(fileURLToPath(import.meta.url), "utf8");
  const start = source.indexOf('test("an upload that stalls until the request timeout');
  assert.ok(start >= 0, "this file has the stalled-upload test");
  const stalledTest = source.slice(start, source.indexOf("\ntest(", start));
  // Node.js 18.0 to 18.17 exit with "--import= is not allowed in NODE_OPTIONS".
  assert.doesNotMatch(stalledTest, /--import/, "the stalled-upload test passes no --import in NODE_OPTIONS");
  assert.match(stalledTest, /NODE_OPTIONS: requireOptions\(file\)/, "the stalled-upload test loads its preload with --require");
});

test("the stalled-upload preload sets the connection check interval when the server is created", () => {
  // Some Node.js 18 releases start the check in the server's constructor. An
  // interval set in listen comes too late there: the 408 takes 30 seconds.
  const dir = mkdtempSync(join(tmpdir(), "a2a-preload-"));
  try {
    const file = join(dir, "preload.cjs");
    writeFileSync(file, stallPreload);
    const created = 'require("node:http").createServer(() => {}).connectionsCheckingInterval';
    const run = spawnSync(process.execPath, ["-p", created], {
      env: { ...process.env, NODE_OPTIONS: requireOptions(file) },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.equal(run.stdout, "100\n", "a server that is not listening yet has the shortened interval");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a preload path with a space, a quote, a backslash or a tab reaches Node as one --require option", () => {
  const dir = mkdtempSync(join(tmpdir(), "a2a preload-"));
  try {
    // Windows file names cannot contain a double quote or a tab, and the
    // backslashes that separate its directories are already in the path.
    const file = join(dir, process.platform === "win32" ? "pre load.cjs" : 'pre "lo\\ad"\t.cjs');
    writeFileSync(file, 'process.stdout.write("preloaded\\n");\n');
    const run = spawnSync(process.execPath, ["-e", ""], {
      env: { ...process.env, NODE_OPTIONS: requireOptions(file) },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.equal(run.stdout, "preloaded\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a preload's NODE_OPTIONS keep the options already in NODE_OPTIONS", () => {
  const dir = mkdtempSync(join(tmpdir(), "a2a-preload-"));
  try {
    const file = join(dir, "preload.cjs");
    writeFileSync(file, 'process.stdout.write("preloaded\\n");\n');
    const run = spawnSync(process.execPath, ["-p", "process.noDeprecation"], {
      env: { ...process.env, NODE_OPTIONS: requireOptions(file, "--no-deprecation") },
      encoding: "utf8",
      timeout: 30000,
    });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.equal(run.stdout, "preloaded\ntrue\n", "the preload ran and --no-deprecation still applies");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every preload in this file gets its NODE_OPTIONS from requireOptions", () => {
  const source = readFileSync(fileURLToPath(import.meta.url), "utf8");
  const start = source.indexOf("function requireOptions(");
  assert.ok(start >= 0, "this file has requireOptions");
  const outside = source.slice(0, start) + source.slice(source.indexOf("\n}\n", start));
  // Any other builder reads the existing value or writes its own --require.
  assert.doesNotMatch(outside, /process\.env\.NODE_OPTIONS/, "only requireOptions reads the existing NODE_OPTIONS");
  assert.doesNotMatch(outside, /[`"']--require/, "only requireOptions writes a --require option");
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

// Start the example with a CommonJS module loaded first that changes how the
// HTTP server listens, and return the finished run.
function runWithPreload(preload, env) {
  const dir = mkdtempSync(join(tmpdir(), "a2a-preload-"));
  try {
    const file = join(dir, "preload.cjs");
    writeFileSync(file, preload);
    return spawnSync(process.execPath, [tsx, "handler.ts"], {
      cwd: example,
      env: { ...process.env, ...env, NODE_OPTIONS: requireOptions(file) },
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
    `const { Server } = require("node:http");
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
    `const { Server } = require("node:http");
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

test("a server the tests start does not keep the test process alive, and stopping it ends tsx and the server", async () => {
  const serverPort = await freePort();
  // Count right after the spawn, before startServer's first await, and again
  // once the server is listening, so a reference taken at either point shows.
  // The process handle of a process an earlier test stopped is still listed
  // after its close event and finishes closing only when the event loop runs,
  // so let one timer turn pass before the first count.
  await new Promise((resolve) => setTimeout(resolve, 0));
  const baseline = heldHandles();
  const starting = startServer(serverPort);
  const added = heldHandles() - baseline;
  const extra = await starting;
  const listening = heldHandles() - baseline;
  try {
    assert.equal(added, 0, "starting the server adds no process or pipe that keeps the test process alive");
    assert.equal(listening, 0, "the listening server holds no process or pipe that keeps the test process alive");
    // Without a group led by tsx, stopServer's signal reaches no process.
    if (process.platform !== "win32") assert.ok(groupRunning(extra.pid), "tsx leads its own process group");
  } finally {
    stopServer(extra);
  }
  if (process.platform === "win32") return;
  for (let i = 0; i < 100 && groupRunning(extra.pid); i++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(groupRunning(extra.pid), false, "tsx and the server it started have exited");
});

test("a server that cannot be spawned fails the start at once instead of hanging", { timeout: 10000 }, async () => {
  // A missing working directory makes the spawn itself fail.
  await assert.rejects(
    startServer(await freePort(), undefined, join(example, "missing")),
    /^Error: server did not start: spawn .+ ENOENT/
  );
});

test("stopping a server process that could not be spawned does nothing instead of throwing", async () => {
  // startServer's error listener rejects before its timer can call
  // stopServer on such a process, so call stopServer on one directly.
  const proc = spawn(process.execPath, [tsx, "handler.ts"], {
    cwd: join(example, "missing"),
    stdio: "ignore",
  });
  await new Promise((resolve) => proc.once("error", resolve));
  assert.equal(proc.pid, undefined, "a process that could not be spawned has no pid");
  assert.doesNotThrow(() => stopServer(proc));
});

test("a ps call that ps rejects is a reason to skip the test that makes it, as a missing ps is", () => {
  // ps on macOS, procps ps and BusyBox ps all reject this option.
  assert.ok(psUnavailable(["--no-such-option"]), "ps --no-such-option gives a reason to skip");
});

test(
  "a process group whose processes have exited counts as running until they are reaped, and stopping it does nothing instead of throwing",
  {
    skip:
      (process.platform === "win32" && "process groups are POSIX only") ||
      psUnavailable(["-o", "stat=", "-p", String(process.pid)]),
  },
  async () => {
    // The holder starts a process that leads a group of its own and exits at
    // once, then blocks its event loop reading its stdin, so that it does not
    // reap the process until the test closes its stdin. The holder reaps it
    // itself: killed, it would leave the process to whichever process adopts
    // it, and in a container whose first process is Node.js, as when docker
    // run starts the tests without --init, that process never reaps it.
    const holder = spawn(
      process.execPath,
      [
        "-e",
        `const { spawn } = require("node:child_process");
const { readSync, writeSync } = require("node:fs");
const child = spawn(process.execPath, ["-e", ""], { detached: true, stdio: "ignore" });
writeSync(1, child.pid + "\\n");
readSync(0, Buffer.alloc(1));
`,
      ],
      { stdio: ["pipe", "pipe", "ignore"] }
    );
    const closed = new Promise((resolve) => holder.once("close", resolve));
    let out = "";
    holder.stdout.on("data", (chunk) => (out += chunk));
    let pid;
    try {
      for (let i = 0; i < 200 && !out.includes("\n"); i++) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      pid = Number(out);
      assert.ok(pid > 0, `the holder started a process: ${JSON.stringify(out)}`);
      const state = () => {
        const ps = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" });
        if (ps.error) throw ps.error;
        return ps.stdout.trim();
      };
      for (let i = 0; i < 200 && !state().startsWith("Z"); i++) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.match(state(), /^Z/, "the process has exited and is not yet reaped");
      assert.equal(groupRunning(pid), true, "the group counts as running until its process is reaped");
      assert.doesNotThrow(() => stopServer({ pid }));
      holder.stdin.end();
      await within(closed, 10000, "the holder did not exit within 10 seconds of its stdin closing");
    } finally {
      holder.kill("SIGKILL");
      await within(closed, 10000, "the holder did not exit within 10 seconds of SIGKILL");
    }
    // The holder reaped the process before it exited, so its group goes away.
    for (let i = 0; i < 100 && groupRunning(pid); i++) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.equal(groupRunning(pid), false, "the group no longer counts as running once its process is reaped");
  }
);

test(
  "interrupting a test run stops the servers it started",
  {
    skip:
      (process.platform === "win32" && "on Windows the servers share the console and receive Ctrl-C themselves") ||
      psUnavailable(["-A", "-o", "pid=,ppid=,pgid="]) ||
      psUnavailable(["-A", "-o", "pgid=,stat="]),
  },
  async () => {
    // Run the stalled-upload test alone in a process group of its own, as a
    // shell runs a job, and once the run has started the main server and the
    // stalled-upload server, send SIGINT to that group, as Ctrl-C does.
    const env = { ...process.env };
    // Left set, the nested run reports to this run instead of running on its own.
    delete env.NODE_TEST_CONTEXT;
    const run = spawn(
      process.execPath,
      ["--test", "--test-name-pattern=^an upload that stalls", fileURLToPath(import.meta.url)],
      { env, stdio: "ignore", detached: true }
    );
    const exited = new Promise((resolve) => run.once("exit", resolve));
    let groups = new Set();
    try {
      for (let i = 0; i < 600 && groups.size < 2; i++) {
        await new Promise((resolve) => setTimeout(resolve, 50));
        groups = descendantGroups(run.pid);
      }
      assert.equal(groups.size, 2, "the run started the main server and the stalled-upload server");
      // A server that has exited counts as stopped while it waits to be reaped.
      const running = () => {
        const live = liveGroups();
        return [...groups].filter((pid) => live.has(pid));
      };
      // A check that cannot see the servers while they run would report them
      // stopped after the interrupt whether or not the run stopped them.
      assert.deepEqual(running(), [...groups], "ps lists both servers as running before the run is interrupted");
      process.kill(-run.pid, "SIGINT");
      await within(exited, 10000, "the interrupted run did not exit within 10 seconds");
      for (let i = 0; i < 100 && running().length > 0; i++) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.deepEqual(running(), [], "no server the interrupted run started is still running");
    } finally {
      // Stop the run and whatever it left running, even when an assertion failed.
      stopServer(run);
      for (const pid of groups) stopServer({ pid });
    }
  }
);

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
