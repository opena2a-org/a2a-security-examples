// Writes into docs/input-validation.md, between its two marker lines, the
// table of the replies the six steps of that page give at POST /: for each
// error and each reply with no body, the step, a request that gets it, the
// HTTP status and the JSON-RPC code. It reads them from the rows of
// test/handler-attack-table.mjs, which test/handler-attack-table.test.mjs sends
// to the handler, checking each reply for that status, code and body. The page
// explains the steps in words and names their errors, and the table alone
// gives the statuses and codes, so the page cannot give other ones than the
// rows do. Run with:
//   node scripts/generate-input-validation.mjs          writes the table
//   node scripts/generate-input-validation.mjs --check  exits 1 when the page
//                                                       holds another table
// A path after the option names another page to write or check.
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { attackTable } from "../test/handler-attack-table.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export const page = "docs/input-validation.md";

// The lines the table stands between on the page, each on a line of its own.
export const beginMarker = "<!-- BEGIN table written by node scripts/generate-input-validation.mjs from test/handler-attack-table.mjs: edit that file and run the script, not this table -->";
export const endMarker = "<!-- END table written by node scripts/generate-input-validation.mjs -->";

// The error a row's reply gives: the message of a JSON-RPC error, the error of
// a body such as {"error":"Too many requests"}, or null for a reply with no
// body.
function errorOf(row) {
  const { expect } = row;
  if (expect.body === "none") return null;
  const error = expect.json !== null && typeof expect.json === "object" ? expect.json.error : undefined;
  if (typeof error === "string") return error;
  if (typeof error?.message === "string") return error.message;
  throw new Error(`the row "${row.name}" expects neither a body with an error nor a reply with no body, so the table has no error to give for it`);
}

// The replies the steps give at POST /, one for each step, status, code and
// error, in step order and, within a step, in the order of the first row that
// gets each. Each gives the step, the status, the JSON-RPC code or null, the
// error or null for a reply with no body, and the name of that first row. A
// row that names no step, or that sends another method or path, gives none.
export function answers(table) {
  const byReply = new Map();
  for (const row of table) {
    const { method = "POST", path = "/" } = row.request;
    if (row.step === null || method !== "POST" || path !== "/") continue;
    const answer = {
      step: row.step,
      status: row.expect.status,
      code: row.expect.code,
      error: errorOf(row),
      example: row.name,
    };
    const key = JSON.stringify([answer.step, answer.status, answer.code, answer.error]);
    if (!byReply.has(key)) byReply.set(key, answer);
  }
  return [...byReply.values()].sort((a, b) => a.step - b.step);
}

// Text for a table cell, with a backslash before each character that would
// end the cell or start markdown formatting.
function cell(text) {
  if (/[\r\n]/.test(text)) throw new Error(`a table cell cannot hold a line break: ${JSON.stringify(text)}`);
  return text.replace(/[\\`*_[\]<>|]/g, "\\$&");
}

// A code span for a table cell. A code span cannot escape a backtick, and a |
// in one ends the cell unless a backslash comes before it.
function codeSpan(text) {
  if (/[`\r\n]/.test(text)) throw new Error(`a code span in a table cell cannot hold a backtick or a line break: ${JSON.stringify(text)}`);
  return `\`${text.replace(/\|/g, "\\|")}\``;
}

// The text the page holds between its marker lines: a blank line, the table
// and a blank line.
export function renderTable(table) {
  const lines = ["| Step | Example request | HTTP status | JSON-RPC code | Error |", "|---|---|---|---|---|"];
  for (const answer of answers(table)) {
    const code = answer.code === null ? "none" : codeSpan(String(answer.code));
    const error = answer.error === null ? "no body" : codeSpan(answer.error);
    lines.push(`| ${answer.step} | ${cell(answer.example)} | ${answer.status} | ${code} | ${error} |`);
  }
  return `\n${lines.join("\n")}\n\n`;
}

// Where marker is in text, which must hold it once, on a line of its own.
function markerAt(text, marker) {
  const found = [];
  for (let at = text.indexOf(marker); at !== -1; at = text.indexOf(marker, at + 1)) found.push(at);
  if (found.length !== 1) throw new Error(`the page holds the line ${marker} ${found.length} times, not once`);
  const [at] = found;
  if ((at > 0 && text[at - 1] !== "\n") || text[at + marker.length] !== "\n") {
    throw new Error(`the line ${marker} holds other text, or does not end with a line feed`);
  }
  return at;
}

// Where the text between the marker lines of a page starts and ends.
function regionBounds(text) {
  const start = markerAt(text, beginMarker) + beginMarker.length + 1;
  const end = markerAt(text, endMarker);
  if (end < start) throw new Error(`the line ${endMarker} comes before the line ${beginMarker}`);
  return { start, end };
}

// The text between the marker lines of a page.
export function region(text) {
  const { start, end } = regionBounds(text);
  return text.slice(start, end);
}

// The page with the table the rows of table give between its marker lines.
export function withTable(text, table) {
  const { start, end } = regionBounds(text);
  return text.slice(0, start) + renderTable(table) + text.slice(end);
}

function main(args) {
  const check = args.includes("--check");
  const paths = args.filter((arg) => arg !== "--check");
  if (paths.length > 1 || paths.some((arg) => arg.startsWith("-"))) {
    console.error("usage: node scripts/generate-input-validation.mjs [--check] [page]");
    process.exitCode = 1;
    return;
  }
  const [file = join(root, page)] = paths;
  const name = paths[0] ?? page;
  let text;
  let updated;
  try {
    text = readFileSync(file, "utf8");
    updated = withTable(text, attackTable);
  } catch (err) {
    console.error(`${name}: ${err.message}`);
    process.exitCode = 1;
    return;
  }
  if (check) {
    if (updated === text) {
      console.log(`${name} holds the table test/handler-attack-table.mjs gives`);
      return;
    }
    console.error(`${name} holds another table than the one test/handler-attack-table.mjs gives; run node scripts/generate-input-validation.mjs to write it`);
    process.exitCode = 1;
    return;
  }
  if (updated === text) {
    console.log(`${name} already holds the table test/handler-attack-table.mjs gives`);
    return;
  }
  writeFileSync(file, updated);
  console.log(`wrote the table test/handler-attack-table.mjs gives into ${name}`);
}

// Whether node was started with this file, and not with a test that imports
// it. The paths are compared after symbolic links are resolved, since node
// gives this module the resolved path, and a path such as one under /tmp on
// macOS has a link in it.
function startedWithThisFile() {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (startedWithThisFile()) main(process.argv.slice(2));
