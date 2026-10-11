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
  const sentence = lines.find((l) => /The example accepts any bearer token/.test(l));
  assert.ok(sentence, "README describes which bearer tokens the example accepts");
  for (const token of rejected) {
    assert.ok(sentence.includes(`\`${token}\``), `README says the token ${token} is rejected`);
  }
});

// The pattern handler.ts matches the Authorization header against.
function credentialsPattern() {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const source = handler.match(/authHeader\.match\(\/(.+)\/([a-z]*)\)/);
  assert.ok(source, "handler.ts matches the Authorization header against a pattern");
  return new RegExp(source[1], source[2]);
}

// The pattern handler.ts reads the Bearer scheme of an Authorization header with.
function bearerSchemePattern() {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const source = handler.match(/const bearerScheme = \/(.+)\/([a-z]*);/);
  assert.ok(source, "handler.ts reads the scheme of the Authorization header with a pattern");
  return new RegExp(source[1], source[2]);
}

// A header as the handler receives it: Node.js decodes header bytes as
// Latin-1, so each UTF-8 byte of a character outside ASCII is a character.
function received(header) {
  return Buffer.from(header, "utf8").toString("latin1");
}

test("step 1 gives 401 for a missing header or another scheme, and 400 for a Bearer header that is not followed by one token", () => {
  // RFC 6750, section 3.1: a request with no bearer credentials gets 401 and a
  // malformed one gets 400. The handler answers 400 to a header such as Bearer
  // demo token, which names the Bearer scheme but holds two tokens.
  const scheme = bearerSchemePattern();
  const credentials = credentialsPattern();
  const step = lines.find((l) => l.startsWith("1. Bearer authentication:"));
  assert.ok(step, "README lists bearer authentication as step 1");
  assert.doesNotMatch(step, /401 without a token/, "a header with a token in it can get 401 too");
  const [rejected, invalid = ""] = step.split("; an invalid token ");
  assert.match(rejected, /one or more spaces and one token/, "step 1 says what follows Bearer in a header that passes");
  const other = rejected.match(/A request without the header, or whose header names another scheme, such as ([^.]+), gets 401\./);
  assert.ok(other, "step 1 gives 401 for a missing header and for one that names another scheme");
  const named = [...other[1].matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  assert.ok(named.length > 0, "step 1 gives a header that names another scheme");
  for (const header of named) {
    assert.doesNotMatch(received(header), scheme, `handler.ts reads ${header} as another scheme`);
  }
  assert.match(rejected, /As RFC 6750, section 3\.1, suggests, a request that sends the header more than once gets 400, and so does one whose header names the `Bearer` scheme in any other form: /, "step 1 gives 400 for a malformed Bearer header");
  const examples = [...rejected.matchAll(/`(Bearer [^`]+)`/g)].map((m) => m[1]);
  assert.ok(examples.length >= 2, "step 1 gives Bearer headers that have a token in them and get 400");
  for (const header of examples) {
    assert.match(received(header), scheme, `handler.ts reads ${header} as the Bearer scheme`);
    assert.doesNotMatch(received(header), credentials, `handler.ts answers 400 to ${header}`);
  }
  // The header the quick start sends is one the handler's pattern accepts.
  const sent = readme.match(/-H "Authorization: ([^"]+)"/);
  assert.ok(sent, "the quick start sends an Authorization header");
  assert.match(sent[1], credentials, `handler.ts reads a token from ${sent[1]}`);
  assert.match(invalid, /^gets 401\./, "step 1 gives 401 for an invalid token");
  assert.doesNotMatch(step, /\b403\b/, "step 1 gives no 403");
});

test("step 1 names each form of a Bearer header that gets 400, with a header of each form that the handler answers 400 to", () => {
  // test/validated-task-handler.test.mjs sends headers of each form.
  const scheme = bearerSchemePattern();
  const credentials = credentialsPattern();
  const { made, ending } = tokenCharacters(credentials);
  const step = lines.find((l) => l.startsWith("1. Bearer authentication:"));
  const [rejected] = step.split("; an invalid token ");
  const forms = rejected.match(/names the `Bearer` scheme in any other form: (.+)$/);
  assert.ok(forms, "step 1 gives 400 for a header that names the Bearer scheme in any form but Bearer, one or more spaces and one token");
  const token = (header) => received(header).replace(/^Bearer +/, "");
  const kinds = {
    "no token": (header) => header === "Bearer",
    "a tab, comma, colon or other character a scheme name cannot hold in place of the spaces": (header) => /^Bearer[^ ]/.test(header),
    "more than one token": (header) => /^Bearer +[^ ]+ +[^ ]/.test(header),
    "a token that starts with `=` or has a character other than `=` after an `=`": (header) => /^(=|[^ ]*=[^=])/.test(token(header)),
    "a character outside that set": (header) => [...token(header)].some((c) => !made.includes(c) && !ending.includes(c)),
  };
  for (const [kind, isKind] of Object.entries(kinds)) {
    const start = forms[1].indexOf(`with ${kind} (`);
    assert.ok(start >= 0, `step 1 gives 400 for a Bearer header with ${kind}, and an example`);
    const listed = forms[1].slice(start + `with ${kind} (`.length).split(")")[0];
    const examples = [...listed.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    assert.ok(examples.length > 0, `step 1 gives a Bearer header with ${kind}`);
    for (const header of examples) {
      assert.ok(isKind(header), `${header} is a Bearer header with ${kind}`);
      assert.match(received(header), scheme, `handler.ts reads ${header} as the Bearer scheme`);
      assert.doesNotMatch(received(header), credentials, `handler.ts answers 400 to ${header}`);
    }
  }
  // Of the characters a header value can hold (RFC 9110, section 5.5: tab,
  // the visible ASCII characters and the bytes 0x80 to 0xFF), each one a
  // scheme name can hold (section 5.6.2) makes Bearer the start of another
  // scheme name, and each other one in place of the spaces gets 400.
  const tchar = /^[!#$%&'*+.^_`|~0-9A-Za-z-]$/;
  const decoded = Array.from({ length: 256 }, (_, byte) => String.fromCharCode(byte));
  const sendable = decoded.filter((c) => c === "\t" || (c > " " && c < "\x7f") || c >= "\x80");
  for (const c of sendable) {
    const header = `Bearer${c}demo-token`;
    if (tchar.test(c)) {
      assert.doesNotMatch(header, scheme, `handler.ts reads ${JSON.stringify(header)} as another scheme`);
    } else {
      assert.match(header, scheme, `handler.ts reads ${JSON.stringify(header)} as the Bearer scheme`);
      assert.doesNotMatch(header, credentials, `handler.ts answers 400 to ${JSON.stringify(header)}`);
    }
  }
  for (const c of ["\t", ",", ":"]) {
    assert.ok(!tchar.test(c), `a scheme name cannot hold ${JSON.stringify(c)}`);
  }
  // The 401 sentence gives a header whose scheme name only starts with Bearer.
  const other = rejected.match(/whose header names another scheme, such as ([^.]+), gets 401\./);
  assert.ok(other, "step 1 gives 401 for a header that names another scheme");
  const named = [...other[1].matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  assert.ok(named.some((header) => /^Bearer[^ ]/.test(header)), "step 1 gives a header whose scheme name starts with Bearer as another scheme");
});

test("step 1 says Bearer in any letter case and one or more spaces, and the handler's pattern takes both", () => {
  const credentials = credentialsPattern();
  const step = lines.find((l) => l.startsWith("1. Bearer authentication:"));
  assert.match(step, /`Bearer` \(in any letter case\) followed by one or more spaces and one token/, "step 1 says the scheme is read in any letter case and followed by one or more spaces");
  for (const header of ["bearer demo-token", "BEARER demo-token"]) {
    assert.match(header, credentials, `handler.ts reads a token from ${header}, so the scheme is read in any letter case`);
  }
  assert.match("Bearer   demo-token", credentials, "handler.ts reads a token after three spaces, so one or more spaces follow the scheme");
  assert.doesNotMatch("Bearerdemo-token", credentials, "handler.ts reads no token when no space follows the scheme");
});

test("step 1 gives 400 for a request with more than one Authorization header, which the handler counts", () => {
  // req.headers holds the first Authorization line of a request and none of
  // the later ones, so the handler can only see a second line in rawHeaders.
  // test/validated-task-handler.test.mjs sends such requests.
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  assert.match(handler, /req\.rawHeaders/, "handler.ts counts the Authorization header lines of a request");
  const step = lines.find((l) => l.startsWith("1. Bearer authentication:"));
  assert.match(step.split("; an invalid token ")[0], /a request that sends the header more than once gets 400/, "step 1 gives 400 for a header sent more than once");
});

test("step 1 names the challenges the handler's 400 and 401 responses carry and the header line count at which it answers 431", () => {
  // test/validated-task-handler.test.mjs sends requests that get these answers.
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const step = lines.find((l) => l.startsWith("1. Bearer authentication:"));
  const challenge = handler.match(/const bearerChallenge = '([^']+)';/);
  assert.ok(challenge, "handler.ts sets the challenge its 401 responses carry");
  // RFC 6750, section 3: the Bearer scheme is followed by one or more auth-params.
  assert.match(challenge[1], /^Bearer [a-z_]+="[^"]*"/, "the challenge has an auth-param after Bearer");
  assert.match(handler, /status\(401\)\.set\("WWW-Authenticate", bearerChallenge\)/, "handler.ts sets the challenge on a 401 response");
  assert.ok(step.includes(`Each 401 carries the challenge \`WWW-Authenticate: ${challenge[1]}\``), "step 1 names the challenge");
  const invalid = handler.match(/status\(401\)\.set\("WWW-Authenticate", `\$\{bearerChallenge\}([^`]+)`\)\.json\(\{ error: "Invalid or expired token" \}\)/);
  assert.ok(invalid, "handler.ts adds an error code to the challenge for an invalid token");
  assert.ok(step.includes(`the one for an invalid token adds the error code from RFC 6750, section 3.1: \`WWW-Authenticate: ${challenge[1]}${invalid[1]}\``), "step 1 names the challenge for an invalid token");
  const malformed = handler.match(/status\(400\)\.set\("WWW-Authenticate", `\$\{bearerChallenge\}([^`]+)`\)/);
  assert.ok(malformed, "handler.ts adds an error code to the challenge for a malformed Authorization header");
  assert.ok(step.includes(`Each 400 in this step adds the error code for a malformed request: \`WWW-Authenticate: ${challenge[1]}${malformed[1]}\``), "step 1 names the challenge for a malformed Authorization header");
  const limit = handler.match(/const maxHeaderLines = (\d+);/);
  assert.ok(limit, "handler.ts sets the number of header lines at which a request gets 431");
  const count = Number(limit[1]).toLocaleString("en-US");
  assert.ok(step.includes(`a request with ${count} or more header lines gets 431`), `step 1 gives 431 for ${count} or more header lines`);
  const sentence = lines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  assert.match(sentence, /rejected with HTTP 401 or 431, requests whose `Authorization` header gets 400, and requests for the agent card write no audit line/, "README says a 431, and a 400 for the Authorization header, write no audit line");
});

// The characters the pattern takes in a bearer token, of the 256 a header byte
// decodes to: those a token is made of, and those that can only end one.
function tokenCharacters(credentials) {
  const decoded = Array.from({ length: 256 }, (_, byte) => String.fromCharCode(byte));
  const made = decoded.filter((c) => credentials.test(`Bearer ${c}`));
  const ending = decoded.filter((c) => !made.includes(c) && credentials.test(`Bearer a${c}`));
  return { made, ending };
}

test("the bearer token sentence and step 1 name the characters the handler takes in a token, and step 1 gives a token outside them", () => {
  const credentials = credentialsPattern();
  const { made, ending } = tokenCharacters(credentials);
  const alphanumeric = made.filter((c) => /[A-Za-z0-9]/.test(c));
  assert.equal(alphanumeric.length, 62, "handler.ts takes every ASCII letter and digit in a token");
  const marks = made.filter((c) => !alphanumeric.includes(c));
  const named = (text) => [...text.matchAll(/`([^`]+)`/g)].map((m) => m[1]).sort();
  const sentences = {
    "the bearer token sentence": lines.find((l) => /The example accepts any bearer token/.test(l)),
    "step 1": lines.find((l) => l.startsWith("1. Bearer authentication:")),
  };
  for (const [where, sentence] of Object.entries(sentences)) {
    assert.ok(sentence, `README has ${where}`);
    const set = sentence.match(/\(one or more ASCII letters, digits, ([^)]+), then any number of ([^)]+)\)/);
    assert.ok(set, `${where} names the characters of a bearer token`);
    assert.deepEqual(named(set[1]), [...marks].sort(), `${where} names every character handler.ts takes in a token besides letters and digits, and no other`);
    assert.deepEqual(named(set[2]), [...ending].sort(), `${where} names every character handler.ts takes only at the end of a token`);
  }
  // A token with a character outside the set gets 400 like any other Bearer
  // header that is not followed by one token, whichever bytes the character is
  // sent as.
  const examples = [...sentences["step 1"].split("; an invalid token ")[0].matchAll(/`Bearer ([^` ]+)`/g)].map((m) => m[1]);
  const outside = examples.filter((token) => [...received(token)].some((c) => !made.includes(c) && !ending.includes(c)));
  assert.ok(outside.length > 0, "step 1 gives a header whose one token has a character outside the set");
  for (const token of outside) {
    assert.doesNotMatch(received(`Bearer ${token}`), credentials, `handler.ts answers 400 to Bearer ${token}`);
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
  const [claim, exceptions = ""] = step.split('`{"code":-32700,"message":"Invalid JSON"}`');
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
  assert.ok(step.includes('`{"code":-32600,"message":"Invalid request body"}`'), "step 3 names the Invalid request body reply");
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
const nodeTestMajor = 18;
const nodeTestAddedIn = { test: 0, before: 8, after: 8 };

const identifier = /(?:[\p{ID_Start}$_]|\\u[\da-fA-F]{4}|\\u\{[\da-fA-F]+\})(?:[\p{ID_Continue}$\u{200C}\u{200D}]|\\u[\da-fA-F]{4}|\\u\{[\da-fA-F]+\})*/uy;
const keywordsBeforeExpression = new Set(["await", "case", "default", "delete", "do", "else", "extends", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield"]);

// The text of a name or string with its escape sequences replaced by the
// characters they stand for.
function decodeEscapes(raw) {
  const simple = { b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", 0: "\0" };
  return raw.replace(/\\(?:u\{([\da-fA-F]+)\}|u([\da-fA-F]{4})|x([\da-fA-F]{2})|(\r\n|[\s\S]))/g, (_, braced, four, two, other) =>
    other === undefined ? String.fromCodePoint(parseInt(braced ?? four ?? two, 16)) : simple[other] ?? (/^(?:\r\n|[\n\r\u{2028}\u{2029}])$/u.test(other) ? "" : other)
  );
}

// The index of the first line terminator at or after start.
function lineEnd(source, start) {
  const terminator = /[\n\r\u{2028}\u{2029}]/gu;
  terminator.lastIndex = start;
  return terminator.exec(source)?.index ?? source.length;
}

// The index after the slash that closes the regular expression literal
// starting at start, or -1 if the line ends first.
function regularExpressionEnd(source, start) {
  let inClass = false;
  for (let k = start + 1; k < source.length; k++) {
    const c = source[k];
    if ("\n\r\u{2028}\u{2029}".includes(c)) return -1;
    if (c === "\\") k++;
    else if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) return k + 1;
  }
  return -1;
}

// The tokens of a module, read in one pass: names and strings with their escape
// sequences decoded, one token with no value for each number and regular
// expression, one template token where a template ends, and punctuators one
// character each except ++, --, the ... of a spread or rest element and the ${
// that starts a template substitution. A byte order mark, a hashbang line,
// whitespace, comments and the text of a template give no token. A slash is
// read as division after a name other than a keyword in
// keywordsBeforeExpression (a keyword after a . is a property name and one
// after a # is a private name, while one after ... is a keyword, except of,
// which is a keyword only directly inside the parentheses after for or
// for await, after a token a slash divides after or after }, and not as the
// name a const, let or var declares right after the opening parenthesis),
// after ) or ], after a number, string, template or regular expression, and
// after a ++ or -- that follows one of these on the same line (a line break
// before a ++ or --, in a comment or not, makes it a prefix operator). So a
// slash right after the ) of if (...), for (...) or while (...) is read as
// division, though it starts a regular expression there. Any other slash
// starts a regular expression if one closes on the same line, and is read as
// a punctuator if not.
function moduleTokens(text) {
  const source = text.replace(/^\u{FEFF}/u, "");
  const tokens = [];
  const slashDivides = (token) =>
    token !== undefined &&
    (token.type === "name" ? !token.beforeExpression : token.type !== "punct" || token.value === ")" || token.value === "]" || token.postfix);
  // For each template substitution open at this point, the { opened inside it
  // and not yet closed.
  const substitutions = [];
  // For each (, [ or { open at this point, whether it is the ( after for or
  // for await. A for after a . or # is a property or private name, not the
  // keyword.
  const brackets = [];
  const keywordFor = (token) => token?.raw === "for" && !token.property;
  const templateText = (start) => {
    for (let k = start; k < source.length; k++) {
      if (source[k] === "\\") k++;
      else if (source[k] === "`") {
        tokens.push({ type: "template" });
        return k + 1;
      } else if (source.startsWith("${", k)) {
        substitutions.push(0);
        tokens.push({ type: "punct", value: "${" });
        return k + 2;
      }
    }
    return source.length;
  };
  let i = source.startsWith("#!") ? lineEnd(source, 0) : 0;
  // The index after the last token read.
  let previousEnd = i;
  while (i < source.length) {
    const c = source[i];
    const previous = tokens.at(-1);
    const regularExpression = c === "/" && !slashDivides(previous) ? regularExpressionEnd(source, i) : -1;
    identifier.lastIndex = i;
    const name = identifier.exec(source);
    if (/\s/.test(c)) i++;
    else if (source.startsWith("//", i)) i = lineEnd(source, i);
    else if (source.startsWith("/*", i)) {
      const end = source.indexOf("*/", i + 2);
      i = end < 0 ? source.length : end + 2;
    } else if (c === "`") i = templateText(i + 1);
    else if (c === "}" && substitutions.at(-1) === 0) {
      substitutions.pop();
      i = templateText(i + 1);
    } else if (c === '"' || c === "'") {
      let k = i + 1;
      while (k < source.length && source[k] !== c && source[k] !== "\n" && source[k] !== "\r") {
        k += source[k] !== "\\" ? 1 : source.startsWith("\r\n", k + 1) ? 3 : 2;
      }
      tokens.push({ type: "string", value: decodeEscapes(source.slice(i + 1, k)) });
      i = k + 1;
    } else if (regularExpression >= 0) {
      const flags = /[\p{ID_Continue}$]*/uy;
      flags.lastIndex = regularExpression;
      flags.exec(source);
      tokens.push({ type: "regex" });
      i = flags.lastIndex;
    } else if (name) {
      const property = previous?.type === "punct" && (previous.value === "." || previous.value === "#");
      // of is a variable name unless it comes directly inside the parentheses
      // after for or for await and follows the end of an operand or of a
      // pattern, as in for (x of ...) or for (const { a } of ...), other than
      // as the name a const, let or var right after the ( declares, as in
      // for (const of of ...).
      const forHead = brackets.at(-1) === true;
      const declared = ["const", "let", "var"].includes(previous?.raw) && tokens.at(-2)?.type === "punct" && tokens.at(-2).value === "(";
      const keyword = forHead && !declared && (slashDivides(previous) || (previous?.type === "punct" && previous.value === "}"));
      const of = name[0] === "of" && !keyword;
      tokens.push({ type: "name", raw: name[0], value: decodeEscapes(name[0]), property, beforeExpression: !property && !of && keywordsBeforeExpression.has(name[0]) });
      i += name[0].length;
    } else if (/\d/.test(c) || (c === "." && /\d/.test(source[i + 1] ?? ""))) {
      const number = /\.?\d[\w.]*/y;
      number.lastIndex = i;
      number.exec(source);
      tokens.push({ type: "number" });
      i = number.lastIndex;
    } else if (source.startsWith("++", i) || source.startsWith("--", i)) {
      const lineBreak = /[\n\r\u{2028}\u{2029}]/u.test(source.slice(previousEnd, i));
      tokens.push({ type: "punct", value: c + c, postfix: !lineBreak && slashDivides(previous) });
      i += 2;
    } else if (source.startsWith("...", i)) {
      tokens.push({ type: "punct", value: "..." });
      i += 3;
    } else {
      if (substitutions.length > 0 && c === "{") substitutions[substitutions.length - 1]++;
      if (substitutions.length > 0 && c === "}") substitutions[substitutions.length - 1]--;
      if ("([{".includes(c)) brackets.push(c === "(" && (keywordFor(previous) || (previous?.raw === "await" && keywordFor(tokens.at(-2)))));
      if (")]}".includes(c)) brackets.pop();
      tokens.push({ type: "punct", value: c });
      i++;
    }
    if (tokens.at(-1) !== previous) previousEnd = i;
  }
  return tokens;
}

// The names a module's import declarations take from node:test, in any layout:
// either quote, a default import, renamed names, a name written as a string or
// with Unicode escapes, and line breaks or comments anywhere in the
// declaration. The default export is test(). A namespace import gives "*", as
// it does not show which names the file uses. Import text inside a comment,
// string or template is not a declaration, nor is import text inside a slash
// pair that moduleTokens() reads as a regular expression. moduleTokens() reads
// a slash right after the ) of if (...), for (...) or while (...) as division,
// so import text inside a regular expression there is read as a declaration.
// The reader does not handle import(), require or an import with a phase
// keyword such as import defer.
function namesImportedFromNodeTest(text) {
  const tokens = moduleTokens(text);
  // Keywords are matched on the text as written, as a keyword written with an
  // escape sequence is not a keyword.
  const is = (token, type, written) => token?.type === type && (written === undefined || (token.raw ?? token.value) === written);
  const names = [];
  for (let i = 0; i < tokens.length; i++) {
    if (!is(tokens[i], "name", "import")) continue;
    const found = [];
    let j = i + 1;
    if (is(tokens[j], "name")) {
      found.push("test");
      j += is(tokens[j + 1], "punct", ",") ? 2 : 1;
    }
    if (is(tokens[j], "punct", "*")) {
      if (!is(tokens[j + 1], "name", "as") || !is(tokens[j + 2], "name")) continue;
      found.push("*");
      j += 3;
    } else if (is(tokens[j], "punct", "{")) {
      for (j++; is(tokens[j], "name") || is(tokens[j], "string"); ) {
        found.push(tokens[j].value === "default" ? "test" : tokens[j].value);
        j += is(tokens[j + 1], "name", "as") ? 3 : 1;
        if (is(tokens[j], "punct", ",")) j++;
      }
      if (!is(tokens[j], "punct", "}")) continue;
      j++;
    }
    if (is(tokens[j], "name", "from") && is(tokens[j + 1], "string") && tokens[j + 1].value === "node:test") names.push(...found);
  }
  return names;
}

// The path and text of each test file.
function testFiles() {
  return readdirSync(join(root, "test"))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => ({ path: `test/${name}`, text: readFileSync(join(root, "test", name), "utf8") }));
}

// The lowest Node.js 18 minor release that has node --test and every name
// namesImportedFromNodeTest() finds in the given files, each a path and a text
// as testFiles() gives them. A name a file takes from node:test in a form the
// reader does not handle is not counted.
function lowestMinorThatCanRunTheTests(files) {
  let minor = 1;
  for (const { path, text } of files) {
    for (const name of namesImportedFromNodeTest(text)) {
      assert.notEqual(name, "*", `${path} imports node:test as a namespace; import the names it uses instead`);
      assert.ok(Object.hasOwn(nodeTestAddedIn, name), `${path} imports ${name} from node:test; add the release that added it`);
      minor = Math.max(minor, nodeTestAddedIn[name]);
    }
  }
  return minor;
}

test("the node:test import reader finds names with either quote, a default import, renamed names and a list over several lines, and marks a namespace import", () => {
  assert.deepEqual(namesImportedFromNodeTest('import { test, before, after } from "node:test";\n'), ["test", "before", "after"]);
  assert.deepEqual(namesImportedFromNodeTest("import { describe } from 'node:test';\n"), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('import test, { mock } from "node:test";\n'), ["test", "mock"]);
  assert.deepEqual(namesImportedFromNodeTest("import run from 'node:test';\n"), ["test"]);
  assert.deepEqual(namesImportedFromNodeTest('import {\n  it as check,\n  default as t,\n} from "node:test";\n'), ["it", "test"]);
  assert.deepEqual(namesImportedFromNodeTest('import * as nt from "node:test";\n'), ["*"]);
  assert.deepEqual(namesImportedFromNodeTest('import assert from "node:assert/strict";\nimport { test } from "node:test2";\n'), []);
});

test("the node:test import reader reads a name with letters outside ASCII, Unicode escapes or quotes, a file that starts with a byte order mark, and a declaration with no space, an indent or a comment", () => {
  assert.deepEqual(namesImportedFromNodeTest('import * as né from "node:test";\n'), ["*"]);
  assert.deepEqual(namesImportedFromNodeTest('import тест from "node:test";\n'), ["test"]);
  assert.deepEqual(namesImportedFromNodeTest('import tést, { describe } from "node:test";\n'), ["test", "describe"]);
  assert.deepEqual(namesImportedFromNodeTest('import t\\u0065st from "node:test";\n'), ["test"]);
  assert.deepEqual(namesImportedFromNodeTest('import { d\\u0065scribe, \\u{61}fter } from "node:t\\x65st";\n'), ["describe", "after"]);
  assert.deepEqual(namesImportedFromNodeTest('import { "test" as t, \'default\' as run } from "node:test";\n'), ["test", "test"]);
  assert.deepEqual(namesImportedFromNodeTest('\u{FEFF}import { describe } from "node:test";\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest("import{test}from\"node:test\";import*as nt from'node:test';\n"), ["test", "*"]);
  assert.deepEqual(namesImportedFromNodeTest('  import { test, /* after, */ before } // it\n  from "node:test";\n'), ["test", "before"]);
});

test("the node:test import reader does not read import text inside a comment, string, template or a regular expression after =, or an import keyword written with an escape sequence, as a declaration", () => {
  assert.deepEqual(namesImportedFromNodeTest('/*\nimport { describe } from "node:test";\n*/\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('// import { describe } from "node:test";\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const s = `\nimport { describe } from "node:test";\n`;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const s = `${`\nimport { describe } from "node:test";\n`}`;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const s = "\\\nimport { describe } from \'node:test\';";\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const s = "\\\r\nimport { describe } from \'node:test\';";\r\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const re = /import { describe } from "node:test"/;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('const m = await import("node:test");\nconsole.log(import.meta.url);\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('\\u0069mport { describe } from "node:test";\n'), []);
});

test("the node:test import reader finds a declaration after a regular expression, template, string, division or hashbang line that holds a quote or a backtick", () => {
  const declaration = 'import { after } from "node:test";\n';
  for (const before of [
    'const quote = /["\'`]/;\n',
    'const quote = /[`\'"]/;\n',
    "const re = /[/]`/;\n",
    "const re = /\\/`/;\n",
    "const t = typeof /`/;\n",
    "const s = `\\``;\n",
    "const s = `${x}`;\n",
    'const s = `${ {a: 1}.a.replace(/`/g, "") }`;\n',
    'const half = (a + b) / 2, slash = "/"; ',
    'const half = a[0] / 2, slash = "/"; ',
    // A slash after the ) of an if is read as division, so the quote after it
    // starts a string, which ends at the line break.
    'if (x) /"/.test(s);\n',
    "#!/usr/bin/env node `\n",
    "\u{FEFF}#!/usr/bin/env node `\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
});

test("the node:test import reader reads a slash after export default as a regular expression, and a slash after a postfix ++ or --, a property named default or the ) of if (...), for (...) or while (...) as division", () => {
  assert.deepEqual(namesImportedFromNodeTest('export default /import { describe } from "node:test"/;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('a++ / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('a[0]-- / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('n = 1 + ++/import { describe } from "node:test"/.lastIndex;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('mod.default / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
  // Each slash here starts a regular expression, but the reader reads it as
  // division, so it reads the import text inside as a declaration.
  assert.deepEqual(namesImportedFromNodeTest('if (x) /import { describe } from "node:test"/.test(s);\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('for (;;) /import { describe } from "node:test"/.test(s);\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('while (x) /import { describe } from "node:test"/.test(s);\n'), ["describe"]);
});

test("the node:test import reader reads a slash after a private name such as #default as division, a slash after a keyword that follows a spread as a regular expression, and a ++ or -- after a line break as a prefix operator", () => {
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  assert.deepEqual(namesImportedFromNodeTest("x = this.#default / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("x = this?.#void / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("f(...void /`/);\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("a = [...typeof /`/];\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest('x\n++/import { describe } from "node:test"/.lastIndex;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('a[0] /* note\n */ --/import { describe } from "node:test"/.lastIndex;\n'), []);
  assert.deepEqual(namesImportedFromNodeTest('a /* note */ ++ / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
});

test("the node:test import reader reads a ++ or -- after a carriage return, U+2028 or U+2029 as a prefix operator, and one on the same line as its operand as postfix when a line break comes earlier in the file", () => {
  for (const lineBreak of ["\r", "\u{2028}", "\u{2029}"]) {
    assert.deepEqual(namesImportedFromNodeTest("x" + lineBreak + '++/import { describe } from "node:test"/.lastIndex;\n'), [], JSON.stringify(lineBreak));
    assert.deepEqual(namesImportedFromNodeTest("a[0]" + lineBreak + '--/import { describe } from "node:test"/.lastIndex;\n'), [], JSON.stringify(lineBreak));
  }
  assert.deepEqual(namesImportedFromNodeTest('z = 0;\nx++ / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('z = 0;\r\na[0]-- / 2; import { describe } from "node:test"; x / 3;\n'), ["describe"]);
});

test("the node:test import reader reads a slash after a variable named of as division, and a slash after the of of a for...of loop as a regular expression", () => {
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  assert.deepEqual(namesImportedFromNodeTest("x = of / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("a = [...of / 2, `/`];\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("y = typeof of / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (const x of /`/g.exec(s)) f(x);\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (const [x] of /`/g.exec(s)) f(x);\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (const { x } of /`/g.exec(s)) f(x);\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (o.of of /`/g.exec(s)) f(o);\n" + declaration), ["after"]);
  // An of right after const, let or var is the variable the loop declares, and
  // the of after it is the keyword.
  for (const before of [
    "for (const of of /`/g.exec(s)) f(of);\n",
    "for (let of of /`/g.exec(s)) f(of);\n",
    "for (var of of /`/g.exec(s)) f(of);\n",
    "for await (const of of /`/g.exec(s)) f(of);\n",
    "for (o.let of /`/g.exec(s)) f(o);\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
});

test("the node:test import reader reads an of after the end of an operand directly inside the parentheses after for or for await as the for...of keyword, and an of that a const, let or var declares there as a variable", () => {
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  // Of these, only (x), f(x) and 1..x parse as the left-hand side of a
  // for...of loop. The reader does not check that, and reads an of after the
  // end of any operand there as the keyword, so the slash after it starts a
  // regular expression.
  for (const target of ["(x)", "f(x)", "1..x", '"a"', "`a`", "/a/", "x++", "x--"]) {
    const before = "for (" + target + " of /`/g.exec(s)) g();\n";
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
  assert.deepEqual(namesImportedFromNodeTest("for await (const x of /`/g.exec(s)) f(x);\n" + declaration), ["after"]);
  for (const kind of ["const", "let", "var"]) {
    const before = "for (" + kind + " of of /`/g.exec(s)) f(of);\n";
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
});

test("the node:test import reader reads an of outside the parentheses after for as a variable, as after a line break that ends a statement or after the ) of if (...)", () => {
  // Read as the keyword, the of would make the slash after it start a regular
  // expression that closes at the slash in the template, and the backtick after
  // it would open a template that hides the declaration.
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  for (const operand of ["y", "f(y)", "a[0]", "1", '"a"', "`a`", "/a/", "y++", "y--"]) {
    const before = `x = ${operand}\nof / 2, t = \`/\`;\n`;
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
  assert.deepEqual(namesImportedFromNodeTest("if (x) {}\nof / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("function g() {}\nof / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("if (x) of / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (x of y) of / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("for (x of [() => { y\nof / 2, t = `/`; }]) ;\n" + declaration), ["after"]);
});

test("the node:test import reader reads an of inside the parentheses after a property or private name called for as a variable", () => {
  // A for after a . or # is not the keyword, so the ( after it does not open
  // the head of a for...of loop. Read as the keyword, the of would make the
  // slash after it start a regular expression that closes at the slash in the
  // template, and the backtick after it would open a template that hides the
  // declaration.
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  for (const before of [
    "obj.for(x of / 2), t = `/`;\n",
    "obj?.for(x of / 2), t = `/`;\n",
    "obj.for await (x of / 2), t = `/`;\n",
    "class C { #for() {} m() { this.#for(x of / 2), t = `/`; } }\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
});

test("the node:test import reader reads a slash after a number, string, template or regular expression as division", () => {
  // Read as the start of a regular expression, the slash after the operand
  // would close at the slash in the template, and the backtick after it would
  // open a template that hides the declaration.
  const declaration = 'import { after } from "node:test";\n';
  for (const before of [
    "const n = 1 / 2, t = `/`;\n",
    'const n = "a" / 2, t = `/`;\n',
    "const n = `a` / 2, t = `/`;\n",
    "const n = /a/ / 2, t = `/`;\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
});

test("the node:test import reader reads a long run of spaces in linear time", () => {
  // A pattern with adjacent \s* quantifiers took more than a second on 2,000
  // spaces after "import a" and grew with the cube of the length.
  const start = performance.now();
  assert.deepEqual(namesImportedFromNodeTest("import a" + " ".repeat(4000)), []);
  const ms = performance.now() - start;
  assert.ok(ms < 1000, `reading 4,000 spaces took ${Math.round(ms)} ms`);
});

test("the lowest release that can run the tests comes from the files it is given, and a name the release table does not list fails", () => {
  const file = (text) => [{ path: "test/a.mjs", text }];
  assert.equal(lowestMinorThatCanRunTheTests([...file("import { test } from 'node:test';\n"), ...file("import { after } from 'node:test';\n")]), 8);
  assert.equal(lowestMinorThatCanRunTheTests(file('// import { after } from "node:test";\nimport run from "node:test";\n')), 1);
  assert.throws(() => lowestMinorThatCanRunTheTests(file('import { toString } from "node:test";\n')), /test\/a\.mjs imports toString from node:test; add the release that added it/);
  assert.throws(() => lowestMinorThatCanRunTheTests(file('import * as nt from "node:test";\n')), /test\/a\.mjs imports node:test as a namespace/);
});

// Checks the npm test sentence against an engines.node value of >=X.Y and the
// test files, as testFiles() gives them. The releases that cannot run the tests
// come from nodeTestAddedIn and the names the files import, so the floor must be
// a Node.js 18 release above the lowest one that can run them.
function checkTestedFloorSentence(engines, sentence, files) {
  const floor = engines?.match(/^>=(\d+)\.(\d+)(?:\.\d+)?$/);
  assert.ok(floor, "the root package.json sets engines.node to >=X.Y");
  const [major, minor] = [Number(floor[1]), Number(floor[2])];
  assert.ok(
    sentence.includes(`Node.js ${major}.${minor} is the lowest release the tests have been run on, not a measured minimum`),
    `README says Node.js ${major}.${minor} is a tested floor, not a measured minimum`
  );
  assert.equal(
    major,
    nodeTestMajor,
    `engines.node names Node.js ${major}, but nodeTestAddedIn lists Node.js ${nodeTestMajor} minor releases; give the Node.js ${major} releases before checking the README against them`
  );
  const lowest = lowestMinorThatCanRunTheTests(files);
  const admitted = minor === lowest - 1 ? `${major}.${minor}` : `${major}.${minor} to ${major}.${lowest - 1}`;
  assert.ok(
    minor >= lowest,
    `engines.node names Node.js ${major}.${minor}, below ${major}.${lowest}, the lowest release that can run the tests, so it admits Node.js ${admitted}, which cannot run them`
  );
  assert.ok(
    minor > lowest,
    `engines.node names Node.js ${major}.${minor}, which is not above ${major}.${lowest}, the lowest release that can run the tests, so no release below the floor is untested`
  );
  assert.ok(
    sentence.includes(`releases before ${major}.${lowest} have no`),
    `README says why releases before ${major}.${lowest} cannot run the tests`
  );
  assert.ok(
    sentence.includes(`releases ${major}.${lowest} to ${major}.${minor - 1} are untested`),
    "README says which releases below the floor are untested, leaving out releases that cannot run the tests"
  );
}

test("README says the Node.js version for npm test is the lowest release tested, not a measured minimum", () => {
  // npm test cannot run on a release without node --test or without a name the
  // test files import from node:test, and passes on 18.17. No release between
  // the two has been run, so the floor may be higher than the tests need.
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const sentence = lines.find((l) => l.includes("`npm test` from the repository root"));
  assert.ok(sentence, "README names the command that runs the tests");
  checkTestedFloorSentence(pkg.engines?.node, sentence, testFiles());
});

test("the tested-floor check does not pair Node.js 18 release numbers with another major or an empty range", () => {
  // The release numbers in nodeTestAddedIn are Node.js 18 minor releases. With
  // engines.node at >=20.0.0 they must not turn into "releases before 20.8" and
  // "releases 20.8 to 20.-1", and a floor at 18.8 leaves no release between the
  // two to call untested.
  const tail = "have no `after` in `node:test`, which the tests import";
  const files = [{ path: "test/a.mjs", text: 'import { test, after } from "node:test";\n' }];
  assert.throws(
    () => checkTestedFloorSentence(">=20.0.0", `releases before 20.8 ${tail}. Node.js 20.0 is the lowest release the tests have been run on, not a measured minimum: releases 20.8 to 20.-1 are untested.`, files),
    /lists Node\.js 18 minor releases/
  );
  assert.throws(
    () => checkTestedFloorSentence(">=18.8.0", `releases before 18.8 ${tail}. Node.js 18.8 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.7 are untested.`, files),
    /is not above 18\.8/
  );
});

test("the tested-floor check reads the test files it is given and says a floor below the lowest release that can run the tests admits releases that cannot run them", () => {
  const tail = "have no `after` in `node:test`, which the tests import";
  const files = [{ path: "test/a.mjs", text: 'import { test, after } from "node:test";\n' }];
  assert.throws(
    () => checkTestedFloorSentence(">=18.1.0", `releases before 18.8 ${tail}. Node.js 18.1 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.0 are untested.`, files),
    /names Node\.js 18\.1, below 18\.8, the lowest release that can run the tests, so it admits Node\.js 18\.1 to 18\.7, which cannot run them/
  );
  assert.throws(
    () => checkTestedFloorSentence(">=18.7.0", `releases before 18.8 ${tail}. Node.js 18.7 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.6 are untested.`, files),
    /so it admits Node\.js 18\.7, which cannot run them/
  );
  assert.throws(
    () => checkTestedFloorSentence(">=18.17.0", `releases before 18.8 ${tail}. Node.js 18.17 is the lowest release the tests have been run on, not a measured minimum: releases 18.8 to 18.16 are untested.`, [{ path: "test/a.mjs", text: "import { describe } from 'node:test';\n" }]),
    /test\/a\.mjs imports describe from node:test; add the release that added it/
  );
});

// The payloads of the a2a-attack category with the intensity each needs and
// its description, as hackmyagent 0.33.2 lists them for
//   npx hackmyagent attack --local --category a2a-attack --intensity aggressive --json
// An intensity sends the payloads of the lower ones too, and the attack
// command runs at active unless --intensity is given: without the option the
// same command lists the first eight.
const a2aAttackPayloads = [
  ["A2A Agent Discovery", "passive", "Discovers available agents and their capabilities"],
  ["A2A Trust Probe", "passive", "Probes agent trust boundaries and authentication"],
  ["A2A Identity Spoofing - Admin", "active", "Claims to be an admin agent to gain elevated access"],
  ["A2A Identity Spoofing - Orchestrator", "active", "Claims to be the orchestrator to control workers"],
  ["A2A Delegation Abuse - Elevated Privileges", "active", "Requests task execution with elevated privileges"],
  ["A2A Delegation Abuse - Cross-boundary", "active", "Attempts to delegate tasks outside authorized scope"],
  ["A2A Embedded Prompt Injection", "active", "Embeds prompt injection attack in A2A message content"],
  ["A2A Data Exfiltration via Message", "active", "Attempts to extract system information through A2A responses"],
  ["A2A Chain Attack", "aggressive", "Chains multiple A2A agents to escalate privileges"],
  ["A2A Message Replay Probe", "aggressive", "Tests if agents accept replayed/stale messages"],
];

// The tests on https://agentpwn.com/attacks/a2a-attack. Checked 2026-10-11.
const a2aAttackPages = ["Agent Impersonation", "Delegation Abuse", "Worm Propagation"];

// Attack names an earlier attack table and handler header gave. None is a
// payload of the a2a-attack category or a test on the linked page.
const unlistedAttacks = /agent card spoofing|task injection|skill enumeration|response poisoning|credential harvesting/i;

// The part of the README between the attack heading and the next heading.
function attackSection(text) {
  return (text.split(/^## Testing against real attacks$/m)[1] ?? "").split(/^##+ /m)[0];
}

// What the attack section says against the payload list: the rows of its
// table, the version the list was read from and the number of payloads the
// command sends.
function checkAttackSection(section, payloads) {
  const number = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];
  const command = codeBlocks(section).find((b) => b.body.includes("hackmyagent attack "));
  assert.ok(command, "the section has a hackmyagent attack command");
  assert.match(command.body, /--category a2a-attack\b/, "the command runs the a2a-attack category");
  assert.doesNotMatch(command.body, /--intensity\b/, "the command runs at the default intensity, active");
  const rows = section.split("\n").filter((l) => l.startsWith("|")).slice(2);
  const cells = rows.map((row) => row.split("|").slice(1, -1).map((cell) => cell.trim()));
  assert.deepEqual(cells, payloads, "the table lists each payload of the a2a-attack category with its intensity and description");
  assert.match(section, /`a2a-attack` category of hackmyagent 0\.33\.2\b/, "README names the scanner version the table was read from");
  const sent = payloads.filter(([, intensity]) => intensity !== "aggressive").length;
  assert.ok(
    section.includes(`the default \`active\` intensity the command sends the ${number[sent]} \`passive\` and \`active\` payloads`),
    `README says the command sends the ${number[sent]} passive and active payloads`
  );
  assert.ok(
    section.includes(`add \`--intensity aggressive\` to send all ${number[payloads.length]}`),
    `README says --intensity aggressive sends all ${number[payloads.length]}`
  );
}

test("the attack table lists the payloads of the scanner's a2a-attack category, and the sentence above the command counts those it sends", () => {
  checkAttackSection(attackSection(readme), a2aAttackPayloads);
});

test("the attack table check fails for a table with an attack the category lacks, a missing payload or another intensity, and for a sentence that miscounts the payloads the command sends", () => {
  const section = attackSection(readme);
  assert.throws(
    () => checkAttackSection(section.replace("| A2A Trust Probe | passive |", "| Response poisoning | passive |"), a2aAttackPayloads),
    /the table lists each payload/
  );
  assert.throws(
    () => checkAttackSection(section.replace(/^\| A2A Chain Attack \|.*\n/m, ""), a2aAttackPayloads),
    /the table lists each payload/
  );
  assert.throws(
    () => checkAttackSection(section.replace("| A2A Message Replay Probe | aggressive |", "| A2A Message Replay Probe | active |"), a2aAttackPayloads),
    /the table lists each payload/
  );
  const noneAggressive = a2aAttackPayloads.map(([name, intensity, description]) => [name, intensity.replace("aggressive", "active"), description]);
  assert.throws(
    () => checkAttackSection(section.replace(/\| aggressive \|/g, "| active |"), noneAggressive),
    /README says the command sends the ten passive and active payloads/
  );
});

test("README and the handler's header name the tests on the linked attack page, and no attack that the page and the scanner's category both lack", () => {
  const handler = readFileSync(join(root, "examples/validated-task-handler/handler.ts"), "utf8");
  const header = handler.match(/^\/\*\*[\s\S]*?\*\//)?.[0] ?? "";
  const link = "https://agentpwn.com/attacks/a2a-attack";
  const sentence = attackSection(readme).split("\n").find((l) => l.includes(`](${link})`));
  assert.ok(sentence, "the attack section links the attack page");
  assert.ok(header.includes(link), "the handler's header links the attack page");
  // A comment wraps, so join its lines before looking for a name in it.
  const flat = (text) => text.replace(/[\s*]+/g, " ").toLowerCase();
  for (const page of a2aAttackPages) {
    assert.ok(sentence.includes(page), `README names the ${page} test`);
    assert.ok(flat(header).includes(page.toLowerCase()), `the handler's header names the ${page} test`);
  }
  assert.doesNotMatch(flat(readme), unlistedAttacks, "README.md names an attack the page and the category lack");
  assert.doesNotMatch(flat(handler), unlistedAttacks, "handler.ts names an attack the page and the category lack");
});

test("the license section matches the LICENSE file", () => {
  const license = readFileSync(join(root, "LICENSE"), "utf8");
  assert.match(license, /Apache License\s+Version 2\.0/);
  const section = readme.split(/^## License$/m)[1] ?? "";
  assert.match(section, /Apache 2\.0/, "README names the Apache 2.0 license");
  assert.doesNotMatch(section, /\bMIT\b/, "README does not name a different license");
});
