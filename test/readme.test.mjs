// README checks. Run with: node --test test/readme.test.mjs (npm test at the
// repository root runs every test file).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
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

test("the audit sentence limits the bare 400 to a client that closes the connection and names the 408 for a stalled upload", () => {
  const sentence = lines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  const rejected = sentence.match(/`request_rejected` for ([^`]*)/)?.[1] ?? "";
  assert.match(rejected, /at most a bare HTTP 400 with no body when the client closes it/);
  assert.match(rejected, /a bare HTTP 408 with no body when the upload stalls until Node's request timeout/);
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

test("step 3 says a body the parser cannot read gets Invalid request body, not Invalid JSON, whatever it contains", () => {
  // Reading the body comes before parsing it, so a body such as 123 over the
  // size limit or in an unsupported charset never reaches the Invalid JSON reply.
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  assert.ok(limit, "handler.ts sets the JSON body limit in megabytes");
  const step = lines.find((l) => l.startsWith("3. JSON parsing:"));
  assert.ok(step, "README lists JSON parsing as step 3");
  assert.ok(step.includes('`{"error":"Invalid request body"}`'), "step 3 names the Invalid request body reply");
  assert.match(step, /the parser cannot read[^.]*whatever it contains/, "step 3 says the reply does not depend on what the body contains");
  assert.match(step, new RegExp(`\\b413\\b[^,]*over ${limit[1]} MB`), "step 3 gives 413 for a body over the size limit");
  assert.match(step, /\b415\b[^,]*unsupported encoding or charset/, "step 3 gives 415 for an unsupported encoding or charset");
  assert.match(step, /\b400\b[^,]*compressed body that does not inflate/, "step 3 gives 400 for a compressed body that does not inflate");
  assert.match(step, /bare HTTP 400 with no body when the client closes the connection before the whole body arrives/, "step 3 limits the bare 400 to a client that closes the connection");
  assert.match(step, /bare HTTP 408 with no body when the upload stalls until Node's request timeout/, "step 3 names the bare 408 for a stalled upload");
});

test("README names the command that runs the tests", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.ok(pkg.scripts?.test, "the root package.json defines npm test");
  assert.match(readme, /`npm test` from the repository root/);
});

test("README states the Node.js version npm test needs, as the root package.json engines field sets it", () => {
  // The quick start runs on any Node.js 18, but Node.js 18.0 has no --test
  // option and no after() export from node:test, so npm test needs a later 18.
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const floor = pkg.engines?.node?.match(/^>=(\d+)\.(\d+)(?:\.\d+)?$/);
  assert.ok(floor, "the root package.json sets engines.node to >=X.Y");
  const sentence = lines.find((l) => l.includes("`npm test` from the repository root"));
  assert.ok(sentence, "README names the command that runs the tests");
  assert.ok(
    sentence.includes(`Node.js ${floor[1]}.${floor[2]} or later`),
    `README says npm test needs Node.js ${floor[1]}.${floor[2]} or later`
  );
});

// The Node.js 18 minor release that added each name a test file imports from
// node:test, from the "Added in" lines of
// https://nodejs.org/docs/latest-v18.x/api/test.html. node --test itself
// arrived in 18.1.
const nodeTestAddedIn = { test: 0, before: 8, after: 8 };

// The lowest Node.js 18 minor release that has node --test and every name the
// test files import from node:test.
function lowestMinorThatCanRunTheTests() {
  let minor = 1;
  for (const file of readdirSync(join(root, "test")).filter((name) => name.endsWith(".mjs"))) {
    const text = readFileSync(join(root, "test", file), "utf8");
    for (const [, names] of text.matchAll(/^import \{([^}]*)\} from "node:test"/gm)) {
      for (const name of names.split(",").map((n) => n.trim()).filter(Boolean)) {
        assert.ok(name in nodeTestAddedIn, `test/${file} imports ${name} from node:test; add the release that added it`);
        minor = Math.max(minor, nodeTestAddedIn[name]);
      }
    }
  }
  return minor;
}

test("README says the Node.js version for npm test is the lowest release tested, not a measured minimum", () => {
  // npm test cannot run on a release without node --test or without a name the
  // test files import from node:test, and passes on 18.17. No release between
  // the two has been run, so the floor may be higher than the tests need.
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const floor = pkg.engines?.node?.match(/^>=(\d+)\.(\d+)(?:\.\d+)?$/);
  assert.ok(floor, "the root package.json sets engines.node to >=X.Y");
  const sentence = lines.find((l) => l.includes("`npm test` from the repository root"));
  assert.ok(sentence, "README names the command that runs the tests");
  assert.ok(
    sentence.includes(`Node.js ${floor[1]}.${floor[2]} is the lowest release the tests have been run on, not a measured minimum`),
    `README says Node.js ${floor[1]}.${floor[2]} is a tested floor, not a measured minimum`
  );
  const lowest = lowestMinorThatCanRunTheTests();
  assert.ok(
    sentence.includes(`releases before ${floor[1]}.${lowest} have no`),
    `README says why releases before ${floor[1]}.${lowest} cannot run the tests`
  );
  assert.ok(
    sentence.includes(`releases ${floor[1]}.${lowest} to ${floor[1]}.${floor[2] - 1} are untested`),
    "README says which releases below the floor are untested, leaving out releases that cannot run the tests"
  );
});

test("the license section matches the LICENSE file", () => {
  const license = readFileSync(join(root, "LICENSE"), "utf8");
  assert.match(license, /Apache License\s+Version 2\.0/);
  const section = readme.split(/^## License$/m)[1] ?? "";
  assert.match(section, /Apache 2\.0/, "README names the Apache 2.0 license");
  assert.doesNotMatch(section, /\bMIT\b/, "README does not name a different license");
});
