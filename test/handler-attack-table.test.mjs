// Sends each row of test/handler-attack-table.mjs to validated-task-handler
// and checks the status, the body, the response headers and the audit lines
// the row expects. npm test at the repository root installs the example's
// dependencies and runs every test file. To run this file alone:
//   (cd examples/validated-task-handler && npm ci)
//   node --test test/handler-attack-table.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { schemaErrors } from "./a2a-schema.mjs";
import { attackTable, bodyLimits, limits, maxHeaderLines, rateLimit } from "./handler-attack-table.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const example = join(root, "examples/validated-task-handler");
const tsx = join(example, "node_modules/tsx/dist/cli.mjs");
const card = JSON.parse(readFileSync(join(root, "examples/secure-agent-card/agent-card.json"), "utf8"));
const handlerSource = readFileSync(join(example, "handler.ts"), "utf8");

// The number a line of handler.ts matching pattern holds.
function handlerNumber(pattern) {
  const match = handlerSource.match(pattern);
  assert.ok(match, `handler.ts has a line matching ${pattern}`);
  return Number(match[1]);
}

test("the limits the table gives are those handler.ts sets", () => {
  assert.equal(rateLimit.requests, handlerNumber(/points: (\d+), \/\/ requests/));
  assert.equal(rateLimit.seconds, handlerNumber(/duration: (\d+), \/\/ per minute/));
  assert.equal(limits.parts, handlerNumber(/parts: z\.array\(PartSchema\)\.min\(1\)\.max\((\d+)\)/));
  assert.equal(limits.textChars, handlerNumber(/text: z\.string\(\)\.min\(1\)\.max\((\d+)\)/));
  assert.equal(limits.fileBytesChars, handlerNumber(/bytes: z\.string\(\)\.max\((\d+)\)/));
  assert.ok(handlerSource.includes("content: TextPartSchema.shape.text,"), "the content of an agent message has the bounds of a text part");
  assert.equal(limits.agentMessageChars, limits.textChars);
  assert.equal(bodyLimits["/"], handlerNumber(/express\.json\(\{ limit: "(\d+)mb" \}\)/) * 1024 * 1024);
  assert.equal(bodyLimits["/a2a/message"], handlerNumber(/express\.json\(\{ limit: "(\d+)kb" \}\)/) * 1024);
  assert.equal(maxHeaderLines, handlerNumber(/const maxHeaderLines = (\d+);/));
});

test("every row has a tag, a step, a name of its own, a request and the status, code and audit lines it expects", () => {
  const names = new Set();
  for (const row of attackTable) {
    assert.ok(["contract", "transport"].includes(row.tag), `${row.name} is tagged contract or transport`);
    assert.ok(row.step === null || [1, 2, 3, 4, 5, 6].includes(row.step), `${row.name} names a step of docs/input-validation.md or null`);
    assert.ok(typeof row.name === "string" && row.name.length > 0 && !names.has(row.name), `${row.name} is a name no other row has`);
    names.add(row.name);
    assert.equal(typeof row.request, "object", `${row.name} has a request`);
    assert.ok(Number.isInteger(row.expect.status), `${row.name} expects a status`);
    assert.ok(row.expect.code === null || Number.isInteger(row.expect.code), `${row.name} expects a JSON-RPC code or null`);
    assert.ok(Array.isArray(row.expect.audit), `${row.name} expects a list of audit lines`);
  }
});

// Complete JSON lines a server has written to its log so far.
function auditLines(log) {
  return log
    .split("\n")
    .slice(0, -1)
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line));
}

// The server's stdout can arrive after its HTTP response, so poll for count
// audit lines for up to 5 seconds, and resolve with the lines there are.
async function waitForAudit(audited, count) {
  const deadline = Date.now() + 5000;
  while (audited().length < count && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return audited();
}

// A port the example can listen on: one a listen on every interface, as
// handler.ts listens, has taken and released by number.
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

// Servers startServer has started whose output pipes are still open, and the
// temporary directories that are not yet removed, so that an interrupted run
// stops and removes them.
const running = new Set();
const tempDirs = new Set();

function makeTempDir(prefix) {
  const dir = mkdtempSync(join(process.env.A2A_TEST_TMPDIR || tmpdir(), prefix));
  tempDirs.add(dir);
  return dir;
}

function removeTempDir(dir) {
  rmSync(dir, { recursive: true, force: true });
  tempDirs.delete(dir);
}

// Stop tsx and the server it started. On POSIX they share the process group
// the spawn creates, so one signal reaches both; on Windows taskkill ends the
// process tree.
function stopServer(proc) {
  if (proc.pid === undefined) return;
  if (process.platform === "win32") {
    const run = spawnSync("taskkill", ["/pid", String(proc.pid), "/t", "/f"], { stdio: "ignore" });
    if (run.error) throw run.error;
    return;
  }
  try {
    process.kill(-proc.pid, "SIGTERM");
  } catch (err) {
    // macOS answers EPERM for a group whose processes have all exited but are
    // not yet reaped, which leaves nothing to stop.
    if (err.code !== "ESRCH" && err.code !== "EPERM") throw err;
  }
}

// Ctrl-C signals only the terminal's foreground process group, which the
// servers have left, so stop every server still running and remove every
// temporary directory first, then let the signal end this process.
if (process.platform !== "win32") {
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.once(signal, () => {
      try {
        for (const proc of running) stopServer(proc);
        for (const dir of tempDirs) removeTempDir(dir);
      } finally {
        process.kill(process.pid, signal);
      }
    });
  }
}

// A CommonJS file that gives the server Node.js creates a request timeout of
// ms milliseconds, a headers timeout below it, and a short interval between
// the checks that find a connection whose timeout has expired, in place of
// Node's 300 seconds, 60 seconds and 30 seconds.
function timeoutPreload(ms) {
  return `const http = require("node:http");
const createServer = http.createServer;
http.createServer = function (...args) {
  const options = typeof args[0] === "function" ? {} : args.shift();
  return createServer({ ...options, connectionsCheckingInterval: 100, headersTimeout: ${Math.ceil(ms / 2)}, requestTimeout: ${ms} }, ...args);
};
`;
}

// NODE_OPTIONS that keep the existing value and load file before the example
// starts. NODE_OPTIONS is split on spaces, so the path is quoted, and inside
// quotes a backslash escapes the next character.
function requireOptions(file) {
  const quoted = `"${file.replace(/[\\"]/g, "\\$&")}"`;
  return [process.env.NODE_OPTIONS, `--require=${quoted}`].filter(Boolean).join(" ");
}

// A copy of the example in a temporary directory, with the secure-agent-card
// directory beside it as in the repository and the example's node_modules
// linked in, whose processTask throws. Resolves with the temporary directory,
// which the caller removes, and the directory of the copy.
function faultCopy() {
  const top = makeTempDir("a2a-attack-table-");
  const dir = join(top, "validated-task-handler");
  try {
    mkdirSync(dir);
    for (const file of ["package.json", "tsconfig.json"]) copyFileSync(join(example, file), join(dir, file));
    const signature = /(async function processTask\([^)]*\) \{\n)/;
    assert.match(handlerSource, signature, "handler.ts declares processTask");
    writeFileSync(join(dir, "handler.ts"), handlerSource.replace(signature, '$1  throw new Error("processing failed in this test copy");\n'));
    const cards = join(root, "examples/secure-agent-card");
    mkdirSync(join(top, "secure-agent-card"));
    for (const entry of readdirSync(cards, { withFileTypes: true })) {
      if (entry.isFile()) copyFileSync(join(cards, entry.name), join(top, "secure-agent-card", entry.name));
    }
    // Windows creates a junction without the privilege a symbolic link needs;
    // other platforms ignore the type.
    symlinkSync(join(example, "node_modules"), join(dir, "node_modules"), "junction");
  } catch (err) {
    removeTempDir(top);
    throw err;
  }
  return { top, dir };
}

// Start the example on a free port, with the server options a row asks for,
// and resolve with its port and the readers of its log once it is listening.
// A port another process takes between the pick and the listen is picked
// again, three times at most.
async function startServer({ requestTimeout, fault } = {}) {
  assert.ok(existsSync(tsx), "run npm ci in examples/validated-task-handler first");
  const dirs = [];
  let cwd = example;
  if (fault) {
    const copy = faultCopy();
    dirs.push(copy.top);
    cwd = copy.dir;
  }
  const env = { ...process.env };
  delete env.AGENT_URL;
  if (requestTimeout !== undefined) {
    const dir = makeTempDir("a2a-attack-table-preload-");
    dirs.push(dir);
    const file = join(dir, "preload.cjs");
    writeFileSync(file, timeoutPreload(requestTimeout));
    env.NODE_OPTIONS = requireOptions(file);
  }
  const cleanup = () => {
    for (const dir of dirs) removeTempDir(dir);
  };
  for (let attempt = 1; ; attempt++) {
    const port = await freePort();
    const proc = spawn(process.execPath, [tsx, "handler.ts"], {
      cwd,
      env: { ...env, PORT: String(port) },
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    let log = "";
    const closed = new Promise((resolve) => proc.once("close", resolve));
    if (proc.pid !== undefined) {
      running.add(proc);
      closed.then(() => running.delete(proc));
    }
    const outcome = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve("no output"), 30000);
      const settle = (value) => {
        clearTimeout(timer);
        resolve(value);
      };
      for (const stream of [proc.stdout, proc.stderr]) {
        stream.on("data", (chunk) => {
          log += chunk;
          if (log.includes("listening on port")) settle("listening");
        });
      }
      proc.once("exit", () => settle("exited"));
      proc.once("error", (err) => settle(`not spawned: ${err.message}`));
    });
    if (outcome === "listening") {
      return { proc, port, closed, cleanup, log: () => log, audit: () => auditLines(log) };
    }
    if (outcome === "exited" && log.includes("already in use") && attempt < 3) continue;
    stopServer(proc);
    cleanup();
    throw new Error(`server did not start (${outcome}):\n${log}`);
  }
}

// Start a server with options, run fn with it, then stop the server and wait
// until tsx and the server it started have both exited, and fail rather than
// hang if they do not. A process still running would keep the test process
// alive, so it and its pipes are unref'd when the wait fails.
async function withServer(options, fn) {
  const server = await startServer(options);
  try {
    await fn(server);
  } finally {
    try {
      stopServer(server.proc);
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`tsx and the server it started did not exit within 10 seconds:\n${server.log()}`)), 10000);
      });
      try {
        await Promise.race([server.closed, timeout]);
      } catch (err) {
        server.proc.unref();
        server.proc.stdout.unref();
        server.proc.stderr.unref();
        throw err;
      } finally {
        clearTimeout(timer);
      }
    } finally {
      server.cleanup();
    }
  }
}

// The body of a reply sent with Transfer-Encoding: chunked, with the chunks
// joined. Throws, naming the byte of the body it stopped at, for a chunk size
// line that is not hexadecimal, for chunk data not followed by CRLF, and for a
// body that ends before the empty line after its last chunk and trailer fields,
// as a reply cut short does. Every pass of either loop throws, returns or
// advances the offset it reads from, so neither loop runs without end.
function dechunk(body) {
  const chunks = [];
  let at = 0;
  for (;;) {
    const lineEnd = body.indexOf("\r\n", at);
    if (lineEnd === -1) throw new Error(`the chunked body ends at byte ${body.length}, before the CRLF that ends the chunk size line at byte ${at}`);
    // The size in hexadecimal digits, then any chunk extensions after a semicolon.
    const hex = /^([0-9a-f]+)(?:[ \t]*;.*)?$/i.exec(body.toString("latin1", at, lineEnd))?.[1];
    if (hex === undefined) throw new Error(`the chunk size line at byte ${at} is not a hexadecimal size`);
    const size = parseInt(hex, 16);
    at = lineEnd + 2;
    if (size === 0) break;
    if (body.length < at + size + 2) throw new Error(`the chunked body ends at byte ${body.length}, inside the ${size} bytes of chunk data at byte ${at} and the CRLF after them`);
    if (body.toString("latin1", at + size, at + size + 2) !== "\r\n") throw new Error(`the ${size} bytes of chunk data at byte ${at} are not followed by CRLF`);
    chunks.push(body.subarray(at, at + size));
    at += size + 2;
  }
  // The trailer field lines, if any, and the empty line that ends the body.
  for (;;) {
    const lineEnd = body.indexOf("\r\n", at);
    if (lineEnd === -1) throw new Error(`the chunked body ends at byte ${body.length}, before the CRLF that ends it`);
    if (lineEnd === at) return Buffer.concat(chunks);
    at = lineEnd + 2;
  }
}

// The status, header lines and body of the reply in raw, as the server wrote
// them. An empty raw is a connection closed with no reply. Throws for a
// chunked body dechunk cannot read.
function parseReply(raw) {
  if (raw.length === 0) return { status: undefined, headers: [], body: "", raw: "" };
  const end = raw.indexOf("\r\n\r\n");
  const head = (end === -1 ? raw : raw.subarray(0, end)).toString("latin1").split("\r\n");
  const status = Number(head[0].match(/^HTTP\/1\.1 (\d{3})/)?.[1]);
  const headers = head.slice(1);
  let body = end === -1 ? Buffer.alloc(0) : raw.subarray(end + 4);
  if (headers.some((line) => /^transfer-encoding:\s*chunked$/i.test(line))) body = dechunk(body);
  return { status, headers, body: body.toString("utf8"), raw: raw.toString("latin1") };
}

// Send a row's request to the server on port as one HTTP/1.1 request on a
// connection of its own, and resolve with the reply once the connection has
// closed. The header lines are written as Latin-1, as Node.js reads them, so a
// header value outside ASCII reaches the handler as it is written here.
function send(port, request) {
  const { method = "POST", path = "/", authorization, contentType = "application/json", headers = [], declaredLength, closeAfter, awaitServer } = request;
  const body = typeof request.body === "function" ? request.body() : request.body;
  const payload = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  const lines = [`${method} ${path} HTTP/1.1`, "Host: 127.0.0.1"];
  const credentials = authorization === undefined ? ["Bearer demo-token"] : authorization === null ? [] : [].concat(authorization);
  for (const value of credentials) lines.push(`Authorization: ${value}`);
  if (payload !== undefined && contentType !== null) lines.push(`Content-Type: ${contentType}`);
  lines.push(...headers);
  if (payload !== undefined) lines.push(`Content-Length: ${declaredLength ?? payload.length}`);
  lines.push("Connection: close", "", "");
  const head = Buffer.from(lines.join("\r\n"), "latin1");
  return new Promise((resolve, reject) => {
    const chunks = [];
    let failure;
    const socket = connect(port, "127.0.0.1", () => {
      socket.write(head);
      if (payload !== undefined) socket.write(payload);
      if (closeAfter !== undefined) setTimeout(() => socket.end(), closeAfter);
    });
    socket.setTimeout(awaitServer ? 15000 : 60000, () => socket.destroy(new Error("no reply within the time allowed")));
    socket.on("data", (chunk) => chunks.push(chunk));
    // A server that answers before it has read the whole body may close the
    // connection while the body is still being written, which ends the write
    // with an error after the reply has arrived.
    socket.on("error", (err) => (failure = err));
    socket.on("close", () => {
      if (chunks.length === 0 && failure) {
        reject(failure);
        return;
      }
      // When parseReply cannot read the reply, as for a chunked reply cut
      // short, reject with the reply, so the row fails with it in its message.
      const raw = Buffer.concat(chunks);
      try {
        resolve(parseReply(raw));
      } catch (err) {
        reject(new Error(`${err.message}, in the reply:\n${raw.toString("latin1")}`));
      }
    });
  });
}

// The value of the Content-Type header among lines, or undefined.
function contentTypeOf(lines) {
  return lines.find((line) => /^content-type:/i.test(line))?.replace(/^content-type:\s*/i, "");
}

// Send row to server, after the requests it repeats, and check the reply and
// the audit lines against what the row expects.
async function checkRow(row, server) {
  const { request, expect } = row;
  const audited = server.audit;
  let seen = audited().length;
  if (request.repeat) {
    const repeated = { ...request, ...request.repeated };
    delete repeated.repeat;
    delete repeated.repeated;
    for (let i = 1; i <= request.repeat; i++) {
      const res = await send(server.port, repeated);
      assert.equal(res.status, expect.repeatStatus ?? 200, `repeated request ${i} of ${request.repeat}:\n${res.raw}`);
    }
    const written = request.repeat * (expect.repeatAudit ?? 1);
    const lines = await waitForAudit(audited, seen + written);
    assert.equal(lines.length, seen + written, `the ${request.repeat} repeated requests wrote ${written} audit lines:\n${server.log()}`);
    seen = lines.length;
  }
  const res = await send(server.port, request);
  if (!(expect.reply === "optional" && res.status === undefined)) {
    assert.equal(res.status, expect.status, `the status, in the reply:\n${res.raw}`);
    if (expect.body === "none") assert.equal(res.body, "", `a reply with no body:\n${res.raw}`);
    if (expect.contentType) assert.match(contentTypeOf(res.headers) ?? "", expect.contentType, "the Content-Type of the reply");
    for (const line of expect.headerLines ?? []) {
      assert.ok(res.headers.includes(line), `the reply carries the header line ${line}:\n${res.headers.join("\n")}`);
    }
    if (expect.json !== undefined || expect.check || expect.code !== null || expect.v03) {
      let parsed;
      try {
        parsed = JSON.parse(res.body);
      } catch (err) {
        throw new Error(`the body is not JSON (${err.message}):\n${res.raw}`);
      }
      if (expect.json !== undefined) {
        assert.deepEqual(parsed, typeof expect.json === "function" ? expect.json({ card, port: server.port }) : expect.json, "the body");
      }
      if (expect.check) assert.ok(expect.check(parsed), `the body is as the row expects:\n${res.body}`);
      if (expect.code !== null) assert.equal(parsed.error?.code, expect.code, "the JSON-RPC code");
      if (expect.v03) assert.deepEqual(schemaErrors(expect.v03, parsed), [], `the body validates against the A2A v0.3.0 ${expect.v03} schema`);
    }
  }
  if (expect.audit.length > 0) {
    const lines = (await waitForAudit(audited, seen + expect.audit.length)).slice(seen);
    const written = lines.map((line, i) => (expect.audit[i]?.length > 1 ? [line.action, line.details] : [line.action]));
    assert.deepEqual(written, expect.audit, `the audit lines the request wrote:\n${server.log()}`);
  } else {
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(audited().length, seen, `the request wrote no audit line:\n${server.log()}`);
  }
}

test("dechunk joins the chunks of a chunked body, and throws for the body cut short at each byte before its end", () => {
  // Two chunks, the last chunk and the CRLF that ends the body.
  const body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
  assert.equal(dechunk(Buffer.from(body, "latin1")).toString("latin1"), "hello world");
  assert.equal(dechunk(Buffer.from("5;name=value\r\nhello\r\n0\r\nExpires: 0\r\n\r\n", "latin1")).toString("latin1"), "hello", "a chunk extension and a trailer field");
  for (let length = 0; length < body.length; length++) {
    assert.throws(() => dechunk(Buffer.from(body.slice(0, length), "latin1")), new RegExp(`^Error: the chunked body ends at byte ${length}, `), `the first ${length} bytes`);
  }
});

test("dechunk throws for a chunk size line that is not hexadecimal and for chunk data not followed by CRLF", () => {
  assert.throws(() => dechunk(Buffer.from("zz\r\nhello\r\n0\r\n\r\n", "latin1")), { message: "the chunk size line at byte 0 is not a hexadecimal size" });
  assert.throws(() => dechunk(Buffer.from("5\r\nhello\r\n\r\n", "latin1")), { message: "the chunk size line at byte 10 is not a hexadecimal size" });
  assert.throws(() => dechunk(Buffer.from("5\r\nhelloXX0\r\n\r\n", "latin1")), { message: "the 5 bytes of chunk data at byte 3 are not followed by CRLF" });
});

test("a row whose chunked reply is cut short fails with the reply in its message", async () => {
  const reply = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n";
  // A server that answers a request with reply once it has read the request's
  // header lines, and then closes the connection.
  const server = createServer((socket) => {
    let request = "";
    socket.on("data", (chunk) => {
      const answered = request.includes("\r\n\r\n");
      request += chunk.toString("latin1");
      if (!answered && request.includes("\r\n\r\n")) socket.end(reply, "latin1");
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const row = { request: { method: "GET", path: "/" }, expect: { status: 200, code: null, audit: [] } };
    const stub = { port: server.address().port, audit: () => [], log: () => "" };
    await assert.rejects(checkRow(row, stub), {
      message: `the chunked body ends at byte 10, before the CRLF that ends the chunk size line at byte 10, in the reply:\n${reply}`,
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// The requests a row sends, each of which the limiter counts.
const cost = (row) => (row.request.repeat ?? 0) + 1;

// A row that asks for server options, or sends more requests than the limiter
// allows one address, gets a server of its own. The other rows share servers,
// each of which takes as many rows as the limiter allows in one window.
const ownServer = attackTable.filter((row) => row.server || cost(row) > rateLimit.requests);
const batches = [];
let batch = [];
let batchCost = 0;
for (const row of attackTable) {
  if (ownServer.includes(row)) continue;
  if (batchCost + cost(row) > rateLimit.requests) {
    batches.push(batch);
    batch = [];
    batchCost = 0;
  }
  batch.push(row);
  batchCost += cost(row);
}
if (batch.length > 0) batches.push(batch);

for (const [i, rows] of batches.entries()) {
  test(`rows ${rows[0].name} to ${rows.at(-1).name} on server ${i + 1} of ${batches.length}`, async (t) => {
    await withServer({}, async (server) => {
      for (const row of rows) {
        await t.test(`${row.tag}: ${row.name}`, () => checkRow(row, server));
      }
    });
  });
}

for (const row of ownServer) {
  test(`${row.tag}: ${row.name}, on a server of its own`, async () => {
    await withServer(row.server ?? {}, (server) => checkRow(row, server));
  });
}
