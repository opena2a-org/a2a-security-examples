// Checks that docs/input-validation.md holds, between its two marker lines,
// the table scripts/generate-input-validation.mjs writes from
// test/handler-attack-table.mjs, byte for byte, and that the steps above the
// table name each error it gives and restate none of its statuses and codes.
// npm test at the repository root runs every test file. To run this file
// alone: node --test test/generate-input-validation.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attackTable } from "./handler-attack-table.mjs";
import { answers, beginMarker, endMarker, region, renderTable } from "../scripts/generate-input-validation.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts/generate-input-validation.mjs");
const pageBytes = readFileSync(join(root, "docs/input-validation.md"));
const page = pageBytes.toString("utf8");

// Run the script with args, from the repository root.
function run(args) {
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: "utf8", timeout: 60000 });
}

// The numbers a text gives: each run of digits, with the minus sign before it.
function numbersIn(text) {
  return [...text.matchAll(/-?\d+/g)].map((m) => Number(m[0]));
}

test("docs/input-validation.md holds between its marker lines the table scripts/generate-input-validation.mjs writes from test/handler-attack-table.mjs, byte for byte", () => {
  assert.ok(Buffer.from(page, "utf8").equals(pageBytes), "the page is UTF-8 text, so comparing its text compares its bytes");
  assert.equal(region(page), renderTable(attackTable));
});

test("node scripts/generate-input-validation.mjs --check exits 0 for docs/input-validation.md, and 1 for a copy with another status, a line added to the table or a marker missing or repeated, which the script without --check puts right or leaves alone", () => {
  const checked = run(["--check"]);
  assert.equal(checked.status, 0, `--check exits 0 for docs/input-validation.md:\n${checked.stdout}${checked.stderr}`);
  const table = region(page);
  const row = table.split("\n").find((line) => /^\| \d \| .* \| \d{3} \|/.test(line));
  assert.ok(row, "the table has a row whose status follows the request");
  const otherStatus = row.replace(/ \| (\d{3}) \| /, (_, status) => ` | ${Number(status) + 1} | `);
  const tables = {
    "another status": page.replace(row, otherStatus),
    "a line added to the table": page.replace(`\n${endMarker}\n`, `| 7 | a request | 200 | none | none |\n\n${endMarker}\n`),
  };
  const markers = {
    "no end marker": page.replace(`${endMarker}\n`, ""),
    "the begin marker twice": page.replace(`${beginMarker}\n`, `${beginMarker}\n${beginMarker}\n`),
    "the end marker before the begin marker": page.replace(`${beginMarker}\n`, "").replace(`${endMarker}\n`, `${endMarker}\n${beginMarker}\n`),
  };
  const dir = mkdtempSync(join(tmpdir(), "a2a-input-validation-"));
  try {
    const file = join(dir, "input-validation.md");
    for (const [name, text] of Object.entries({ ...tables, ...markers })) {
      assert.notEqual(text, page, `the copy with ${name} differs from the page`);
      writeFileSync(file, text);
      const res = run(["--check", file]);
      assert.equal(res.status, 1, `--check exits 1 for a copy with ${name}:\n${res.stdout}${res.stderr}`);
      const expected = name in tables ? /run node scripts\/generate-input-validation\.mjs to write it/ : /<!-- (BEGIN|END) table written by/;
      assert.match(res.stderr, expected, `--check says what is wrong with a copy with ${name}`);
    }
    for (const [name, text] of Object.entries(tables)) {
      writeFileSync(file, text);
      const res = run([file]);
      assert.equal(res.status, 0, `the script writes the table into a copy with ${name}:\n${res.stdout}${res.stderr}`);
      assert.equal(readFileSync(file, "utf8"), page, `the script puts back the table of the page into a copy with ${name}`);
    }
    for (const [name, text] of Object.entries(markers)) {
      writeFileSync(file, text);
      const res = run([file]);
      assert.equal(res.status, 1, `the script exits 1 for a copy with ${name}:\n${res.stdout}${res.stderr}`);
      assert.equal(readFileSync(file, "utf8"), text, `the script leaves a copy with ${name} as it is`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the table has a line for each reply a step gives at POST /, in step order, with the first request that gets it, and takes each status, code and error from the rows", () => {
  const row = (name, step, expect, request = {}) => ({ tag: "contract", step, name, request, expect: { audit: [], ...expect } });
  const rpcError = (code, message) => ({ jsonrpc: "2.0", id: 1, error: { code, message } });
  const table = [
    row("a later step first", 5, { status: 400, code: -32602, json: rpcError(-32602, "Rejected") }),
    row("a plain error", 2, { status: 401, code: null, json: { error: "Who are you" } }),
    row("the same reply again", 2, { status: 401, code: null, json: { error: "Who are you" } }),
    row("another error with the same status", 2, { status: 401, code: null, json: { error: "Not you" } }),
    row("another path", 2, { status: 418, code: null, json: { error: "Teapot" } }, { path: "/a2a/message" }),
    row("another method", 2, { status: 405, code: null, json: { error: "No" } }, { method: "GET" }),
    row("no step", null, { status: 200, code: null, check: () => true }),
    row("a bare reply the client may not get", 3, { status: 400, code: null, body: "none", reply: "optional" }),
    row("a name with | and *", 3, { status: 408, code: null, body: "none" }),
    row("an error with a |", 4, { status: 400, code: -32600, json: rpcError(-32600, "a | b") }),
  ];
  assert.equal(
    renderTable(table),
    [
      "",
      "| Step | Example request | HTTP status | JSON-RPC code | Error |",
      "|---|---|---|---|---|",
      "| 2 | a plain error | 401 | none | `Who are you` |",
      "| 2 | another error with the same status | 401 | none | `Not you` |",
      "| 3 | a bare reply the client may not get | 400, or no reply | none | no body |",
      "| 3 | a name with \\| and \\* | 408 | none | no body |",
      "| 4 | an error with a \\| | 400 | `-32600` | `a \\| b` |",
      "| 5 | a later step first | 400 | `-32602` | `Rejected` |",
      "",
      "",
    ].join("\n")
  );
  assert.throws(() => renderTable([row("no error", 1, { status: 429, code: null, check: () => true })]), /the row "no error" expects neither a body with an error nor a reply with no body/);
  assert.throws(() => renderTable([row("an error with a `", 1, { status: 429, code: null, json: { error: "a ` b" } })]), /cannot hold a backtick/);
  assert.throws(() => renderTable([row("two\nlines", 1, { status: 429, code: null, json: { error: "Too many" } })]), /cannot hold a line break/);
});

test("the steps of docs/input-validation.md and the text between them and the table restate no HTTP status or JSON-RPC code the table gives", () => {
  const given = answers(attackTable);
  const statuses = new Set(given.map((answer) => answer.status));
  const codes = new Set(given.filter((answer) => answer.code !== null).map((answer) => answer.code));
  assert.ok(statuses.size > 0 && codes.size > 0, "the table gives statuses and JSON-RPC codes");
  const restated = (text) => numbersIn(text).filter((number) => statuses.has(number) || codes.has(number));
  const first = page.search(/^1\. /m);
  const begin = page.indexOf(beginMarker);
  assert.ok(first !== -1 && first < begin, "the page lists its steps above the table");
  assert.deepEqual(restated(page.slice(first, begin)), [], "the steps and the text above the table give these statuses or codes, which only the table gives");
  // The check finds a status and a code written in the steps.
  assert.deepEqual(restated("6. Processing errors return a generic 500 with the JSON-RPC error `-32603`."), [500, -32603]);
  assert.deepEqual(numbersIn("RFC 6750, section 3.1, 1,000 lines, 431 and `-32602`"), [6750, 3, 1, 1, 0, 431, -32602]);
});

test("each step of docs/input-validation.md names in backticks each error the table gives for it, and says when it gives a bare reply", () => {
  const lines = page.split("\n");
  for (const answer of answers(attackTable)) {
    const step = lines.find((line) => line.startsWith(`${answer.step}. `));
    assert.ok(step, `docs/input-validation.md lists step ${answer.step}`);
    if (answer.error === null) {
      assert.match(step, /\bbare reply\b/, `step ${answer.step} says when it gives a bare reply, as the table does for ${answer.example}`);
    } else {
      assert.ok(step.includes(`\`${answer.error}\``), `step ${answer.step} names the error ${answer.error}, which the table gives for ${answer.example}`);
    }
  }
});
