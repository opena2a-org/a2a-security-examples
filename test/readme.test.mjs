// README checks. Run with: node --test test/readme.test.mjs (npm test at the
// repository root runs every test file).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(join(root, "README.md"), "utf8");
const lines = readme.split("\n");

// Fenced code blocks in document order, with their info string.
function codeBlocks(text) {
  const blocks = [];
  const fence = /^```(\S*)\n([\s\S]*?)^```$/gm;
  for (const m of text.matchAll(fence)) blocks.push({ lang: m[1], body: m[2] });
  return blocks;
}

test("README stays under the 200-line budget", () => {
  const count = (readme.match(/\n/g) || []).length;
  assert.ok(count < 200, `README.md has ${count} lines; the budget is under 200`);
});

test("lines 1-6 carry the title, a badge, and the OpenA2A family line", () => {
  assert.match(lines[0], /^# \S/, "line 1 is the title");
  assert.match(lines[2], /^\[!\[/, "line 3 is a badge");
  assert.match(lines[4], /^> \*\*\[OpenA2A\]\(https:\/\/github\.com\/opena2a-org\/opena2a\)\*\*:/, "line 5 is the family line");
  assert.equal(lines[1] + lines[3] + lines[5], "", "lines 2, 4 and 6 are blank");
});

test("the clone block is followed by captured output", () => {
  const blocks = codeBlocks(readme);
  const i = blocks.findIndex((b) => b.body.includes("git clone "));
  assert.ok(i >= 0, "a code block runs git clone");
  const cloneLine = lines.findIndex((l) => l.startsWith("git clone "));
  assert.ok(cloneLine >= 0, "a line starts with git clone");
  assert.ok(cloneLine < 30, "first command is within 30 lines");
  const next = blocks[i + 1];
  assert.ok(next && next.lang === "text", "the block after the clone block is a text block of output");
  assert.ok(next.body.trim().length > 0, "the output block is not empty");
});

test("the quick start runs a script the example defines", () => {
  const clone = codeBlocks(readme).find((b) => b.body.includes("git clone "));
  const cd = clone.body.match(/^cd a2a-security-examples\/(\S+)$/m);
  assert.ok(cd, "the clone block changes into an example directory");
  const pkg = JSON.parse(readFileSync(join(root, cd[1], "package.json"), "utf8"));
  for (const [, script] of clone.body.matchAll(/^npm run (\S+)$/gm)) {
    assert.ok(pkg.scripts?.[script], `npm run ${script} is defined in ${cd[1]}/package.json`);
  }
  assert.doesNotMatch(clone.body, /^npm start$/m, "npm start needs npm run build first; the quick start runs from source");
});

test("every relative link points to a file in the repository", () => {
  const links = [...readme.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
  const relative = links.filter((href) => !/^(https?:|mailto:|#)/.test(href));
  assert.ok(relative.length > 0, "README links to files in the repository");
  for (const href of relative) {
    assert.ok(existsSync(join(root, href.split("#")[0])), `${href} exists`);
  }
});

test("the audit sentence names the handler's audit actions and scopes them to authenticated requests", () => {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const actions = [...handler.matchAll(/action: "(\w+)"/g)].map((m) => m[1]);
  assert.ok(actions.length > 0, "handler.ts writes audit entries with an action");
  const sentence = lines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  assert.ok(sentence, "README describes the audit lines");
  for (const action of actions) {
    assert.ok(sentence.includes(`\`${action}\``), `README names the ${action} audit action`);
  }
  assert.doesNotMatch(sentence, /^Every request/, "unauthenticated requests write no audit line");
  assert.match(sentence, /pass authentication/, "README scopes audit lines to authenticated requests");
});

test("the bearer token sentence names every token the handler rejects", () => {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const rejected = [...handler.matchAll(/token !== "([^"]+)"/g)].map((m) => m[1]);
  assert.ok(rejected.length > 0, "isValidToken rejects at least one literal token");
  const sentence = lines.find((l) => /accepts any non-empty bearer token/.test(l));
  assert.ok(sentence, "README describes which bearer tokens the example accepts");
  for (const token of rejected) {
    assert.ok(sentence.includes(`\`${token}\``), `README says the token ${token} is rejected`);
  }
});

test("the audit sentence names a body that is not a JSON object or array, the size limit, an unsupported encoding or charset, a compressed body that does not inflate, and a body cut off by a closed connection", () => {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  assert.ok(limit, "handler.ts sets the JSON body limit in megabytes");
  const sentence = lines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  const rejected = sentence.match(/`request_rejected` for ([^`]*)/)?.[1] ?? "";
  const reasons = [
    "not a JSON object or array",
    `over ${limit[1]} MB`,
    "unsupported encoding or charset",
    "compressed body that does not inflate",
    "connection closed before the whole body arrives",
    "at most a bare HTTP 400 with no body",
  ];
  for (const reason of reasons) {
    assert.ok(rejected.includes(reason), `README says request_rejected covers a body ${reason}`);
  }
});

test("README does not describe the strict JSON parser as accepting any valid JSON", () => {
  // The parser rejects valid JSON such as 123 or "text" that is not an object
  // or array, so "not valid JSON" undersells what gets a 400.
  assert.doesNotMatch(readme, /not valid JSON/);
  assert.doesNotMatch(readme, /no JSON reply because the connection is already gone/);
});

test("step 3 limits the Invalid JSON reply to a non-empty body sent as application/json", () => {
  // The parser reads an empty body as {} and skips a body that is not declared
  // as JSON, so both fail schema validation in step 4, not JSON parsing.
  const step = lines.find((l) => l.startsWith("3. JSON parsing:"));
  assert.ok(step, "README lists JSON parsing as step 3");
  const [claim, exceptions = ""] = step.split('`{"error":"Invalid JSON"}`');
  assert.ok(claim.includes("non-empty body sent as `application/json`"), "step 3 applies to a non-empty body sent as application/json");
  assert.ok(claim.includes("not a JSON object or array"), "step 3 names a body that is not a JSON object or array");
  assert.match(exceptions, /empty body/, "README says an empty body does not get the Invalid JSON reply");
  assert.match(exceptions, /not sent as `application\/json`/, "README says a body with another content type does not get the Invalid JSON reply");
  assert.match(exceptions, /step 4/, "README says which step answers those bodies instead");
});

test("README names the command that runs the tests", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.ok(pkg.scripts?.test, "the root package.json defines npm test");
  assert.match(readme, /`npm test` from the repository root/);
});

test("the license section matches the LICENSE file", () => {
  const license = readFileSync(join(root, "LICENSE"), "utf8");
  assert.match(license, /Apache License\s+Version 2\.0/);
  const section = readme.split(/^## License$/m)[1] ?? "";
  assert.match(section, /Apache 2\.0/, "README names the Apache 2.0 license");
  assert.doesNotMatch(section, /\bMIT\b/, "README does not name a different license");
});
