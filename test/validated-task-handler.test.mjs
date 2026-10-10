// validated-task-handler checks. npm test at the repository root installs the
// example's dependencies and runs every test file. To run this file alone:
//   (cd examples/validated-task-handler && npm ci)
//   node --test test/validated-task-handler.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

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

test("a body over 1 MB or in an unsupported encoding gets a JSON error and a request_rejected audit line", async () => {
  const cases = [
    { headers: {}, body: JSON.stringify({ text: "a".repeat(1100 * 1024) }), status: 413, reason: "entity.too.large" },
    { headers: { "Content-Encoding": "br2" }, body: "{}", status: 415, reason: "encoding.unsupported" },
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

test("unknown routes get a JSON 404, not the framework's HTML page", async () => {
  for (const path of ["/nope", "/tasks"]) {
    const res = await fetch(`http://127.0.0.1:${port}${path}`);
    assert.equal(res.status, 404, `GET ${path}`);
    assert.match(res.headers.get("content-type") ?? "", /application\/json/, `GET ${path}`);
    assert.deepEqual(await res.json(), { error: "Not found" });
  }
});

test("a PORT that is not a port number exits with one line naming PORT", () => {
  for (const value of ["abc", "65536"]) {
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
