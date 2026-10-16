// README checks. Run with: node --test test/readme.test.mjs (npm test at the
// repository root runs every test file).
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// The text with "\n" line endings in place of "\r\n" ones, so the checks below
// hold on a checkout with "\r\n" ones, as core.autocrlf=true gives.
function lfLineEndings(text) {
  return text.replace(/\r\n/g, "\n");
}

// The text of a file in the repository with "\n" line endings.
function readText(path) {
  return lfLineEndings(readFileSync(join(root, path), "utf8"));
}

const readme = readText("README.md");
const lines = readme.split("\n");

// The pages under docs/ that hold what the README links instead of saying.
const docsPages = ["docs/validated-task-handler.md", "docs/input-validation.md", "docs/secure-agent-card.md", "docs/testing-against-real-attacks.md"];
const handlerPage = readText("docs/validated-task-handler.md");
const handlerPageLines = handlerPage.split("\n");
const inputValidation = readText("docs/input-validation.md");
const inputValidationLines = inputValidation.split("\n");
const cardPage = readText("docs/secure-agent-card.md");
const attackPage = readText("docs/testing-against-real-attacks.md");

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
  assert.match(lines[4], /^> \*\*\[OpenA2A\]\(https:\/\/github\.com\/opena2a-org\)\*\*:/, "line 5 is the family line");
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

// The label above an output block in the README: the command whose output the
// block shows, ", trimmed" when the block leaves lines of it out, and the file
// under docs/captures/ that holds all of it. The .json file of the same name
// says how the output was taken.
const captureLabel = /What `([^`]+)` prints(, trimmed)? \(\[full output\]\((docs\/captures\/[a-z0-9-]+)\.txt\)\):$/;

// A version number or a date, as the README length check counts them.
const versionOrDate = /v?[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}/;

// Fenced code blocks in document order, each with the text between it and the
// block before it.
function blocksWithLead(text) {
  const blocks = [];
  let end = 0;
  for (const m of text.matchAll(/^```(\S*)\n([\s\S]*?)^```$/gm)) {
    blocks.push({ lang: m[1], body: m[2], lead: text.slice(end, m.index) });
    end = m.index + m[0].length;
  }
  return blocks;
}

// The commands of a command block, with a line that ends in a backslash joined
// to the next one by a space.
function shellCommands(body) {
  return body.replace(/[ \t]*\\\n[ \t]*/g, " ").split("\n").filter((line) => line.length > 0);
}

test("each output block in the README is labelled with its command and links its full output under docs/captures/, which holds the block's lines in order, with a .json file that names the command the README runs and the run it came from", () => {
  const blocks = blocksWithLead(readme);
  const outputs = blocks.filter((b) => b.lang === "text");
  assert.ok(outputs.length > 0, "README shows output blocks");
  for (const block of outputs) {
    const first = JSON.stringify(block.body.split("\n")[0]);
    const label = block.lead.trim().match(captureLabel);
    assert.ok(label, `the text above the output block that starts ${first} ends with What \`<command>\` prints[, trimmed] ([full output](docs/captures/<name>.txt)):`);
    const [, command, trimmed, name] = label;
    const shown = block.body.replace(/\n$/, "").split("\n");
    const full = readText(`${name}.txt`).replace(/\n$/, "").split("\n");
    const at = full.findIndex((_, k) => shown.every((line, j) => full[k + j] === line));
    assert.ok(at >= 0, `the output block that starts ${first} is a run of lines of ${name}.txt`);
    if (trimmed) assert.ok(shown.length < full.length, `the label above ${first} says trimmed, and the block shows every line of ${name}.txt`);
    else assert.equal(shown.length, full.length, `the output block that starts ${first} leaves out lines of ${name}.txt, and its label does not say trimmed`);
    for (const line of shown) assert.doesNotMatch(line, versionOrDate, `the output block that starts ${first} shows a version or a date; start the excerpt below that line or end it above`);
    const sidecar = JSON.parse(readText(`${name}.json`));
    assert.equal(sidecar.outputs?.capture, `${name}.txt`, `${name}.json names ${name}.txt as its capture`);
    assert.ok(sidecar.command === command || sidecar.command?.startsWith(`${command} `), `${name}.json runs ${command}, as the label says`);
    assert.match(sidecar.run?.commit ?? "", /^[0-9a-f]{40}$/, `${name}.json names the commit the run cloned`);
    assert.match(sidecar.run?.capturedAt ?? "", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, `${name}.json says when the run took it`);
    // The command block above the output holds the command as one of its
    // lines, after the lines the run ran before it, or is the command, with
    // the message text that the paragraph above the output names, if it names
    // one, in place of the block's.
    const source = blocks.slice(0, blocks.indexOf(block)).reverse().find((b) => b.lang === "bash");
    assert.ok(source, `a command block comes before the output block that starts ${first}`);
    const commands = shellCommands(source.body);
    if (commands.length > 1) {
      const k = commands.indexOf(sidecar.command);
      assert.ok(k >= 0, `${name}.json runs ${sidecar.command}, a line of the command block above its output`);
      assert.deepEqual(sidecar.before, commands.slice(0, k), `${name}.json ran the lines of the command block above ${sidecar.command} before it`);
    } else {
      const named = block.lead.match(/with the text `([^`]+)`/);
      const expected = named ? commands[0].replace(/"text":"[^"]*"/, () => `"text":${JSON.stringify(named[1])}`) : commands[0];
      assert.equal(sidecar.command, expected, `${name}.json runs the command the README gives for it`);
    }
  }
});

test("the capture label check reads a label, its trimmed mark and its file, and the commands of a block with lines joined by a backslash", () => {
  assert.deepEqual([..."What `npm run dev` prints, trimmed ([full output](docs/captures/npm-run-dev.txt)):".match(captureLabel)].slice(1), ["npm run dev", ", trimmed", "docs/captures/npm-run-dev"]);
  assert.deepEqual([..."The handler rejects it. What `curl` prints ([full output](docs/captures/message-send.txt)):".match(captureLabel)].slice(1), ["curl", undefined, "docs/captures/message-send"]);
  assert.equal("What `curl` prints ([full output](docs/message-send.txt)):".match(captureLabel), null, "a file outside docs/captures/ is not a capture");
  assert.equal("What `curl` prints ([full output](docs/captures/message-send.txt)).".match(captureLabel), null, "a label ends with a colon");
  assert.deepEqual(shellCommands("curl -s \\\n  -H \"A: b\" \\\n  -d 'x'\n"), ["curl -s -H \"A: b\" -d 'x'"]);
  assert.deepEqual(shellCommands("git clone x\ncd y\nnpm install\n"), ["git clone x", "cd y", "npm install"]);
  assert.match("> a2a-validated-task-handler@1.0.0 dev", versionOrDate);
  assert.match("{\"timestamp\":\"2026-10-16T00:27:08.433Z\"}", versionOrDate);
  assert.doesNotMatch("{\"id\":\"b07fef79-46bb-48da-9b78-3d1c381a9595\"}", versionOrDate);
});

test("the A2A specification releases the README header names are the ones the tests check against, agent-card.json declares and handler.ts answers", () => {
  const header = lines.find((line) => line.startsWith("Example code and configuration for "));
  assert.ok(header, "the README has a header description");
  const linked = [...header.matchAll(/\[v(\d+\.\d+\.\d+)\]\(https:\/\/github\.com\/a2aproject\/A2A\/releases\/tag\/v([^)\s]+)\)/g)];
  assert.ok(linked.length > 0, "the header description links the A2A specification releases the examples target");
  for (const [, text, tag] of linked) assert.equal(tag, text, `the link to v${text} is at the tag of that release`);
  const releases = linked.map((m) => m[1]).sort();
  const checked = readdirSync(join(root, "test/schema")).map((f) => f.match(/^a2a-v(\d+\.\d+\.\d+)\.(?:json|proto)$/)?.[1]).filter(Boolean).sort();
  assert.deepEqual(releases, checked, "the header names the releases whose schema or protocol definition the tests check against under test/schema/");
  const majorMinor = (release) => release.split(".").slice(0, 2).join(".");
  const card = JSON.parse(readText("examples/secure-agent-card/agent-card.json"));
  assert.ok(releases.includes(card.protocolVersion), `agent-card.json declares protocolVersion ${card.protocolVersion}, a release the header names`);
  assert.deepEqual(card.supportedInterfaces.map((i) => i.protocolVersion).sort(), releases.map(majorMinor).sort(), "agent-card.json lists an interface for each release the header names, by Major.Minor");
  // The JSON-RPC method the header says the handler answers for each version,
  // and the one each entry of the VERSIONS map in handler.ts parses.
  const named = Object.fromEntries([...header.matchAll(/`([^`\s]+)` of v(\d+\.\d+)(?:\.\d+)?\b/g)].map(([, method, version]) => [version, method]));
  const handler = readText("examples/validated-task-handler/handler.ts");
  const answered = Object.fromEntries([...handler.matchAll(/\[\s*"(\d+\.\d+)",\s*\{\s*parse: \(body\) => parseRequest\(body, "([^"]+)"/g)].map(([, version, method]) => [version, method]));
  assert.deepEqual(Object.keys(named).sort(), releases.map(majorMinor).sort(), "the header names a JSON-RPC method for each release it links");
  assert.deepEqual(named, answered, "handler.ts answers, for each version, the JSON-RPC method the header names");
  assert.ok(header.endsWith("at `/.well-known/agent-card.json`."), "the header says the agent card is served at /.well-known/agent-card.json");
  assert.match(handler, /app\.get\(\["\/\.well-known\/agent-card\.json"/, "handler.ts serves its agent card at /.well-known/agent-card.json");
});

test("every relative link points to a file in the repository", () => {
  const links = [...readme.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
  const relative = links.filter((href) => !/^(https?:|mailto:|#)/.test(href));
  assert.ok(relative.length > 0, "README links to files in the repository");
  for (const href of relative) {
    assert.ok(existsSync(join(root, href.split("#")[0])), `${href} exists`);
  }
  for (const page of docsPages) {
    assert.ok(readme.includes(`](${page})`), `README links ${page}`);
    const pageLinks = [...readText(page).matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
    for (const href of pageLinks.filter((h) => !/^(https?:|mailto:|#)/.test(h))) {
      assert.ok(existsSync(join(root, dirname(page), href.split("#")[0])), `${href} in ${page} exists`);
    }
  }
});

test("the agent card excerpt matches agent-card.json", () => {
  const card = JSON.parse(readFileSync(join(root, "examples/secure-agent-card/agent-card.json"), "utf8"));
  const section = readme.indexOf("## Secure agent card");
  assert.ok(section >= 0, "README has the Secure agent card section");
  const [block] = codeBlocks(readme.slice(section));
  assert.equal(block?.lang, "json", "the section's first code block is the JSON excerpt");
  const excerpt = JSON.parse(block.body);
  assert.ok(Object.keys(excerpt).length > 0, "the excerpt has fields");
  for (const [key, value] of Object.entries(excerpt)) {
    assert.deepEqual(value, card[key], `the excerpt's ${key} is the file's`);
  }
  // docs/secure-agent-card.md shows the excerpt with the card's version fields.
  const [full] = codeBlocks(cardPage);
  assert.equal(full?.lang, "json", "the first code block of docs/secure-agent-card.md is the JSON excerpt");
  const fullExcerpt = JSON.parse(full.body);
  assert.ok("protocolVersion" in fullExcerpt && "version" in fullExcerpt, "the excerpt in docs/secure-agent-card.md has the card's version fields");
  for (const [key, value] of Object.entries(fullExcerpt)) {
    assert.deepEqual(value, card[key], `the excerpt's ${key} in docs/secure-agent-card.md is the file's`);
  }
});

test("the audit sentence names the handler's audit actions, including the one for a request that fails authentication", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const actions = [...handler.matchAll(/action: "(\w+)"/g)].map((m) => m[1]);
  assert.ok(actions.length > 0, "handler.ts writes audit entries with an action");
  assert.ok(actions.includes("auth_failed"), "handler.ts writes an audit entry for a request that fails authentication");
  const sentence = handlerPageLines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  assert.ok(sentence, "docs/validated-task-handler.md describes the audit lines");
  for (const action of actions) {
    assert.ok(sentence.includes(`\`${action}\``), `docs/validated-task-handler.md names the ${action} audit action`);
  }
  assert.doesNotMatch(sentence, /^Every request/, "a 431 and a request for the agent card write no audit line");
  assert.doesNotMatch(sentence, /pass authentication/, "a request that fails authentication writes an audit line too");
  assert.match(sentence, /`auth_failed` for a request that fails authentication, with the status it gets and a reason but never the header or the token/, "docs/validated-task-handler.md says what the auth_failed line records and that it leaves out the token");
});

// The keys of the options object handler.ts creates the limiter with, in
// order. Null when there is no such object, or when a line of it is neither a
// comment nor one key: value pair with the key quoted or not, such as a spread,
// a shorthand property, a key with no value after it on its line, a value that
// a block comment, string or template continues on the next line, a value that
// ends with a token it goes on after, such as the ? of a conditional or an as,
// so that the next line continues it, a value that leaves a bracket, a template
// substitution or type arguments open at the end of its line, as the next line
// continues it and the first }); line, where the options are taken to end, can
// be inside the value, a value with a closing bracket that the line does not
// open, as when the options object closes before the }); line, or a second
// pair after a comma, as the options such a line gives cannot be read from it.
// A comma or a // inside a string, template or regular expression in a value,
// the regular expression a value starts with among them, does not end the
// value, nor does a comma inside brackets, a template substitution or the type
// arguments of a TypeScript type that the same line closes, as in
// x as Record<string, number>. Null too when a value holds a slash that
// slashMayBeMisread() finds moduleTokens() may misread, even if the line sets
// one option: a bracket or comma after that slash may be read outside a
// regular expression when it is inside one, or inside one when it is outside,
// so a comma that ends the value can be hidden.
function limiterOptionKeys(handler) {
  const options = handler.match(/new RateLimiterMemory\(\{\n([\s\S]*?)\n\}\);/);
  if (!options) return null;
  const keys = [];
  for (const line of options[1].split("\n")) {
    if (/^\s*(\/\/.*|\/\*(?:[^*]|\*(?!\/))*\*\/\s*)?$/.test(line)) continue;
    const pair = line.match(/^\s*(["']?)(\w+)\1\s*:(.*)$/);
    if (!pair) return null;
    // moduleTokens() marks a value that a block comment, string or template
    // continues on the next line as unclosed, and that next line is not a key:
    // value pair, though it may read as one. Otherwise moduleTokens() gives no
    // token for a comment and one token for a string, a regular expression or
    // a template without a substitution. A template with one gives the tokens
    // of each substitution too, and a comma among them, inside brackets or
    // inside type arguments is part of the value when the line closes what it
    // is inside: a later token then has fewer brackets and substitutions, or
    // fewer type arguments, open than the comma has. Any other comma token
    // ends the value, so the key has no value on its line when there is no
    // token or the first one is a comma, and such a comma before the last
    // token is followed by more than a comment. A closing bracket that no
    // earlier token on the line opens has as many brackets and substitutions
    // open as the token before it, or none as the first token.
    // A value goes on after its last token when that leaves a bracket, a
    // substitution or type arguments open, and otherwise unless it is a
    // comma, a } or a token a slash divides after, as one that ends an operand
    // is, so the next line continues a value that ends with an operator such
    // as the ? of a conditional, and the : after a key on that line can be the
    // conditional's. A TypeScript non-null assertion and the > that ends the
    // type arguments of a type after as or satisfies end an operand too, as in
    // settings.duration! or 60 as Duration<60>, while a ! or > that is an
    // operator does not; moduleTokens() marks the first two. A value goes on
    // after an as or satisfies that follows another token, though a slash
    // divides after either name: TypeScript reads it as an operator after a
    // token that ends an operand, and moduleTokens() does not mark each such
    // token, as the ++ of a!++ as or the } of function () {} as.
    const value = moduleTokens(pair[3], { expression: true });
    if (value.some((token, i) => slashMayBeMisread(value, i))) return null;
    const unopened = value.some((token, i) => token.type === "punct" && [")", "]", "}"].includes(token.value) && token.open === (value[i - 1]?.open ?? 0));
    const comma = value.findIndex((token, i) => token.type === "punct" && token.value === "," && value.slice(i + 1).every((later) => later.open >= token.open && later.typeArguments >= token.typeArguments));
    const last = value.at(-1);
    const endsWithAs = value.length > 1 && last.type === "name" && !last.property && ["as", "satisfies"].includes(last.raw);
    const goesOn = last !== undefined && (last.open > 0 || last.typeArguments > 0 || endsWithAs || (!slashDivides(last) && !last.nonNull && !last.endsTypeArguments && !(last.type === "punct" && ["}", ","].includes(last.value))));
    if (value.unclosed || unopened || goesOn || value.length === 0 || comma === 0 || (comma >= 0 && comma < value.length - 1)) return null;
    keys.push(pair[2]);
  }
  return keys;
}

// Whether the token at index i of the tokens moduleTokens() gives for a line
// is a slash it may have misread: one read as division right after a ) that
// closes the parentheses after if, for, for await or while, where a slash
// starts a regular expression, or a ) whose ( the line does not hold, which
// may close such parentheses, or right after a ++ or -- read as postfix right
// after either ), where the ++ or -- is a prefix operator and the slash starts
// its operand when the ) closes such parentheses, and a regular expression
// right after a } that moduleTokens() does not mark as the end of a block,
// where a slash divides when the } ends an object literal or a function, or
// right after a ! or a run of them that follows such a } or a token a slash
// divides after, where in TypeScript each ! is a non-null assertion when the
// token before them ends an operand and a slash then divides, as in a! / 2, or
// right after a ++ or -- that follows such a ! or run of them, where in
// TypeScript the ++ or -- is then a postfix operator and a slash divides, as
// in a!++ / 2, or right after a > that moduleTokens() marks as the end of the
// type arguments of a TypeScript type, or a run of ! after it, where a slash
// divides too, as in 60 as D<1> / 2. A regular expression right after a > that
// ends type arguments and has no such mark, as in a!++ as D<1> / 2, is not
// such a slash, so a comma that ends the value can be hidden there. A ! right
// after the ) that closes the parentheses after if, for, for await or while
// negates, as a statement starts there, so when the line holds the ( of that )
// a regular expression right after the ! or a run of them is read as one and
// is not such a slash. A statement starts right after the } of a block too,
// so a regular expression right after a } that moduleTokens() marks as the end
// of a block, right after a ! or a run of them that follows that }, each of
// which negates, or right after a ++ or -- that follows them, which is a
// prefix operator, is read as one and is not such a slash. moduleTokens() does
// not mark the } of every block, though: the } of a function declaration, as
// in function g() {} !/x/, is not told from the } that ends a function
// expression, so a regular expression after it is such a slash.
function slashMayBeMisread(tokens, i) {
  const is = (token, type, value) => token?.type === type && (value === undefined || token.value === value);
  const keyword = (token, ...raw) => is(token, "name") && !token.property && raw.includes(token.raw);
  // Whether the ) at index close closes the parentheses after if, for,
  // for await or while, or null when its ( is not found. In a line whose
  // brackets and substitutions match, every token inside the parentheses has
  // more of them open than the ) has, so the ( is the token after the last
  // one before the ) that does not. In any other line that token may be
  // another one. One that is not a ( gives null, as in (a] ) / 2, where the ]
  // closes the ( in its place, so the walk stops at the ] and the token after
  // it is the ) itself; another ( is read as the ( of this ).
  const afterKeyword = (close) => {
    let before = close - 1;
    while (before >= 0 && tokens[before].open > tokens[close].open) before--;
    if (!is(tokens[before + 1], "punct", "(")) return null;
    return keyword(tokens[before], "if", "for", "while") || (keyword(tokens[before], "await") && keyword(tokens[before - 1], "for"));
  };
  if (is(tokens[i], "regex")) {
    // moduleTokens() reads a ++ or -- right after a ! as a prefix operator, so
    // a regular expression can follow it. A ++ or -- with no ! before it is a
    // prefix operator, right after a } too, and a slash after it does start a
    // regular expression.
    const last = is(tokens[i - 1], "punct", "++") || is(tokens[i - 1], "punct", "--") ? i - 2 : i - 1;
    let before = last;
    while (is(tokens[before], "punct", "!")) before--;
    if (tokens[before]?.block === true) return false;
    if (before === last) return last === i - 1 && (is(tokens[before], "punct", "}") || tokens[before]?.endsTypeArguments === true);
    // moduleTokens() reads a slash right after a ) as division, so a ) found
    // here has a ! between it and the regular expression.
    if (is(tokens[before], "punct", ")") && afterKeyword(before) === true) return false;
    return is(tokens[before], "punct", "}") || slashDivides(tokens[before]) || tokens[before]?.endsTypeArguments === true;
  }
  const close = tokens[i - 1]?.postfix ? i - 2 : i - 1;
  if (!is(tokens[i], "punct", "/") || !is(tokens[close], "punct", ")")) return false;
  // A ) whose ( is not found may close the parentheses after one of these.
  return afterKeyword(close) !== false;
}

test("the limiter options reader reads a key in either quote, skips a comment and reads a value holding a comma or a // in a string, template or regular expression, and reads neither a spread, a shorthand property, a method, a computed key, a key with no value on its line, a value that a block comment, string, template or an operator at its end continues on the next line, a value with a closing bracket it does not open nor a pair after another on one line, even after a value holding a // or a comma in a string, a template, a regular expression, a template substitution or brackets, nor a value holding a slash that moduleTokens() may misread", () => {
  const add = (...lines) => ["const rateLimiter = new RateLimiterMemory({", "  points: 30, // requests", "  duration: 60, // per minute", ...lines, "});", ""].join("\n");
  assert.deepEqual(limiterOptionKeys(add()), ["points", "duration"]);
  assert.deepEqual(limiterOptionKeys(add('  "blockDuration": 300,')), ["points", "duration", "blockDuration"]);
  assert.deepEqual(limiterOptionKeys(add("  'blockDuration' : 300")), ["points", "duration", "blockDuration"]);
  assert.deepEqual(limiterOptionKeys(add("  // blockDuration: 300,")), ["points", "duration"]);
  assert.deepEqual(limiterOptionKeys(add("  /* blockDuration: 300, */")), ["points", "duration"]);
  assert.deepEqual(limiterOptionKeys(add("")), ["points", "duration"]);
  assert.deepEqual(limiterOptionKeys(add('  keyPrefix: "a, // b", // c')), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `${f(a, b)}`, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: f(a, b), // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `${a}, ${[b, { c, d }].length}`, // e")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `a, // b`, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `a, b`, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: x(/a, b/), // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  blockDuration: (a + b) / 2, // c")), ["points", "duration", "blockDuration"]);
  assert.deepEqual(limiterOptionKeys(add("  blockDuration: f(a, b) / a.if(b) / [c][0] / 2, // d")), ["points", "duration", "blockDuration"]);
  // Only the await of for await comes before the parentheses of a loop, so a
  // slash right after the ) of await (...) divides.
  assert.deepEqual(limiterOptionKeys(add("  blockDuration: await (b) / 2 + 4 / 2,")), ["points", "duration", "blockDuration"]);
  // The comma here is inside no bracket, so only reading the regular
  // expression keeps it in the value.
  assert.deepEqual(limiterOptionKeys(add('  keyPrefix: "" + /a, b/.source, // c')), ["points", "duration", "keyPrefix"]);
  // A value that starts with a regular expression or a comment is read too.
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: /a/.source, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: /a, [//] b/.source, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: /a\\/\\/b/.source")), ["points", "duration", "keyPrefix"]);
  // Only the character class keeps the first of these open past its first
  // slash, and only the escape the second.
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: /[//], b/.source, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: /a\\/, b/.source, // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  blockDuration: /* seconds */ 300,")), ["points", "duration", "blockDuration"]);
  // A comma directly inside a substitution, with no bracket around it, is
  // part of the value whether or not a comma follows the template.
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `${a, b}` // c")), ["points", "duration", "keyPrefix"]);
  assert.deepEqual(limiterOptionKeys(add("  keyPrefix: `${a, b}`, // c")), ["points", "duration", "keyPrefix"]);
  // A value with a name, a string, a template, a number, an opening bracket
  // or a minus sign right after the ) of if (...), for (...), for await (...)
  // or while (...) is read.
  for (const line of [
    "  keyPrefix: (() => { if (a) return 'x'; return 'k'; })(),",
    "  keyPrefix: (() => { for (const x of a) return x; return 'k'; })(),",
    "  keyPrefix: (async () => { for await (const x of a) return x; return 'k'; })(),",
    "  keyPrefix: (() => { while (a) return 'x'; return 'k'; })(),",
    "  keyPrefix: (() => { if (a) 'x'.trim(); return 'k'; })(),",
    "  keyPrefix: (() => { if (a) `x`.trim(); return 'k'; })(),",
    "  keyPrefix: (() => { while (a) 1; return 'k'; })(),",
    "  keyPrefix: (() => { if (a) { return 'x'; } return 'k'; })(),",
    "  keyPrefix: (() => { while (a) (b)(); return 'k'; })(),",
    "  keyPrefix: (() => { for (const x of a) [x].pop(); return 'k'; })(),",
    "  keyPrefix: (async () => { for await (const x of a) -x; return 'k'; })(),",
    // So is a postfix ++ or -- and a slash right after another ). Read as a
    // prefix operator, the ++ or -- would make that slash start a regular
    // expression that ends after c, and the ) after 2 would close no bracket.
    "  keyPrefix: (() => { if (a) (b)++ / (c / 2); return 'k'; })(), // d",
    "  keyPrefix: (() => { while (a) (b)-- / (c / 2); return 'k'; })(), // d",
    // A ! that follows no operand negates, and a slash right after it starts
    // a regular expression.
    "  keyPrefix: !/x/.test(s) ? 'a' : 'b',",
    "  keyPrefix: a && !!/x/.test(s) ? 'a' : 'b',",
    "  keyPrefix: typeof !/x/ === 'boolean' ? 'a' : 'b',",
    // A ++ or -- right after such a !, at the start of a value or right after
    // a } is a prefix operator, and a slash right after it starts a regular
    // expression.
    "  keyPrefix: !++/x/.lastIndex ? 'a' : 'b',",
    "  keyPrefix: a && !--/x/.lastIndex ? 'a' : 'b',",
    "  keyPrefix: ++/x/.lastIndex ? 'a' : 'b',",
    "  keyPrefix: (() => { if (a) { b(); } ++/x/.lastIndex; return 'k'; })(),",
    // So does a ! or a run of them right after the ) of if (...), for (...),
    // for await (...) or while (...), the while that ends a do statement
    // among them, as a statement starts there and no operand comes before it.
    "  keyPrefix: (() => { if (a) !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { if (a) !!/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { while (a) !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { for (;0;) !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (async () => { for await (const x of []) !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { do ; while (0) !/x/.test(s); return 'k'; })(),",
    // A regular expression right after the } of a block after if (...),
    // while (...), else or finally is read as one too, as a statement starts
    // there, and so is one right after a ! or a run of them after that }, each
    // of which negates, or right after a ++ or -- that follows them, which is
    // a prefix operator.
    "  keyPrefix: (() => { if (a) { } /x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { if (a) { } !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { if (a) {} else { b(); } !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { try { b(); } finally { } !!/x/.test(s); return 'k'; })(),",
    "  keyPrefix: (() => { if (a) { b(); } !++/x/.lastIndex; return 'k'; })(),",
    "  keyPrefix: (() => { while (a) { b(); } !--/x/.lastIndex; return 'k'; })(),",
    // A <= right after the name of a type after an as compares, so the > after
    // it here is an operator and the slash right after that > starts a regular
    // expression.
    "  keyPrefix: a as D <= b > /x/.test(s) ? 'a' : 'b',",
  ]) {
    assert.deepEqual(limiterOptionKeys(add(line)), ["points", "duration", "keyPrefix"], `${line.trim()} is read as one key: value pair`);
  }
  // A value that ends with the end of an operand or with a } ends on its line.
  for (const line of ["  keyPrefix: f(a)", "  keyPrefix: a[0]", "  keyPrefix: n++", "  keyPrefix: this", "  keyPrefix: () => {}", "  keyPrefix: a ? b : c"]) {
    assert.deepEqual(limiterOptionKeys(add(line)), ["points", "duration", "keyPrefix"], `${line.trim()} is read as one key: value pair`);
  }
  for (const line of [
    "  ...{ blockDuration: 300 },",
    "  ...extraOptions,",
    "  blockDuration,",
    "  blockDuration() { return 300; },",
    '  ["blockDuration"]: 300,',
    '  keyPrefix: "rl", blockDuration: 300,',
    "  /* a */ blockDuration: 300, /* b */",
    "  points: 30 /* , */, blockDuration: 300,",
    '  duration: "//", blockDuration: 300,',
    '  duration: "//".length * 30, blockDuration: 300,',
    "  keyPrefix: `//`, blockDuration: 300,",
    "  keyPrefix: f(a, b), blockDuration: 300,",
    "  keyPrefix: `${f(a, b)}`, blockDuration: 300,",
    "  keyPrefix: `${a}${b}`, blockDuration: 300,",
    "  keyPrefix: `${`${a}`}`, blockDuration: 300,",
    "  keyPrefix: /,/.source, blockDuration: 300,",
    "  keyPrefix: /[//]/.source, blockDuration: 300,",
    "  keyPrefix: /* a */ /a/.source, blockDuration: 300,",
    "  blockDuration:",
    "  blockDuration: ,",
    "  blockDuration: // 300,",
    "  blockDuration: /* 300 */",
    "  blockDuration: /* 300 */,",
    // A bracket or a substitution the line does not close, and a closing
    // bracket it does not open, hide no comma.
    "  keyPrefix: f(a, [b, blockDuration: 300,",
    "  keyPrefix: `${a, blockDuration: 300,",
    "  duration: 60 }), blockDuration: 300,",
    "  duration: 60, blockDuration: 300 }),",
    // moduleTokens() reads a regular expression right after the ) of
    // if (...), for (...), for await (...) or while (...) as division, as it
    // does right after a ) whose ( the line does not hold, and a slash that
    // divides right after a } as a regular expression, so a bracket or comma
    // it reads there may hide a comma.
    "  keyPrefix: (() => { if (1) /[(]/.test(''); return 'k'; })(), blockDuration: (() => { if (1) /[)]/.test(''); return 300; })(),",
    "  keyPrefix: (() => { while (0) /[(]/; })(), blockDuration: (() => { while (0) /[)]/; })(),",
    "  keyPrefix: (() => { for (;0;) /[(]/; })(), blockDuration: (() => { for (;0;) /[)]/; })(),",
    "  keyPrefix: (async () => { for await (const x of []) /[(]/; })(), blockDuration: (async () => { for await (const x of []) /[)]/; })(),",
    "  keyPrefix: {} / 2, blockDuration: 300 / 1,",
    // It reads a ++ or -- right after such a ) on the same line as a postfix
    // operator, and so the regular expression after it as division too.
    "  keyPrefix: (() => { if (1) ++/[(]/.lastIndex; return 'k'; })(), blockDuration: (() => { if (1) ++/[)]/.lastIndex; return 300; })(),",
    "  keyPrefix: (() => { if (1) --/[(]/.lastIndex; return 'k'; })(), blockDuration: (() => { if (1) --/[)]/.lastIndex; return 300; })(),",
    "  keyPrefix: (() => { while (0) ++/[(]/.lastIndex; })(), blockDuration: (() => { while (0) ++/[)]/.lastIndex; })(),",
    "  keyPrefix: (() => { for (;0;) --/[(]/.lastIndex; })(), blockDuration: (() => { for (;0;) --/[)]/.lastIndex; })(),",
    "  keyPrefix: (async () => { for await (const x of []) ++/[(]/.lastIndex; })(), blockDuration: (async () => { for await (const x of []) ++/[)]/.lastIndex; })(),",
    "  keyPrefix: (() => { do ; while (0) --/[(]/.lastIndex; })(), blockDuration: (() => { do ; while (0) --/[)]/.lastIndex; })(),",
    // In TypeScript a ! right after an operand, or a run of them, is a
    // non-null assertion and a slash after it divides, but moduleTokens()
    // reads that slash as the start of a regular expression.
    "  blockDuration: a! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a.b! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: f()! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a[0]! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a!! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  keyPrefix: {}! / 2, blockDuration: 300 / 1,",
    // A ++ or -- right after such a ! is a postfix operator there and a slash
    // after it divides too, but moduleTokens() reads it as a prefix operator
    // and that slash as the start of a regular expression.
    "  blockDuration: a!++ / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a!-- / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a.b!++ / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a[0]!-- / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a!!++ / 2, keyPrefix: 'rl' + 4 / 2,",
    "  keyPrefix: {}!++ / 2, blockDuration: 300 / 1,",
    // So does a slash right after the > that ends the type arguments of a
    // type after as or satisfies, or right after a ! that follows that >.
    "  blockDuration: 60 as D<1> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: 60 satisfies ns.D<B<1>> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: 60 as D<() => 1> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a! as D<1> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: 60 as D<1>! / 2, keyPrefix: 'rl' + 4 / 2,",
    // That holds for a type after the } of an object literal, a later type in
    // a union or intersection and a typeof query too.
    "  keyPrefix: {} as D<1> / 2, blockDuration: 300 / 1,",
    "  blockDuration: { a: 60 } satisfies D<1> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: 60 as A | D<1> / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: x as typeof f<1> / 2, keyPrefix: 'rl' + 4 / 2,",
    // A ! right after the ) of await (...) is a non-null assertion too, as
    // only the await of for await comes before the parentheses of a loop.
    "  blockDuration: await (b)! / 2, keyPrefix: 'rl' + 4 / 2,",
    // A ! right after the ) of a call to a property named if or while is a
    // non-null assertion too, as that ) ends an operand.
    "  blockDuration: a.if(b)! / 2, keyPrefix: 'rl' + 4 / 2,",
    "  blockDuration: a.while(b)!! / 2, keyPrefix: 'rl' + 4 / 2,",
    // So may be a ! right after a ) whose ( is not found, as that ) may end an
    // operand. Here the ) closes the { in its place, so no closing bracket
    // goes unopened.
    "  keyPrefix: { a )! / 2, blockDuration: 300 / 1,",
    // A ! that negates right after the ) of if (...) hides no comma: the
    // regular expression after it is read as one, so the second pair is found.
    "  keyPrefix: (() => { if (a) !/[(]/.test(s); return 'k'; })(), blockDuration: (() => { if (a) !/[)]/.test(s); return 300; })(),",
    // The same holds when the line sets one option.
    "  keyPrefix: (() => { if (1) /x/; return 'k'; })(), // c",
    "  keyPrefix: (() => { if (1) ++/x/.lastIndex; return 'k'; })(), // c",
    "  blockDuration: a!++ / 2 + 4 / 2, // c",
    "  keyPrefix: a) / 2,",
    // A ! right after the } of a function declaration negates, as one right
    // after the } of a block after if (...) does, but that } is not told from
    // the } that ends a function expression, after which a ! is a non-null
    // assertion and a slash divides, so neither value is read.
    "  keyPrefix: (() => { function g() {} !/x/.test(s); return 'k'; })(),",
    "  keyPrefix: function () {}! / 2, blockDuration: 300 / 1,",
    // Here the ] or } closes the ( in its place and the ) closes nothing, so
    // no ( is found for the ) before the slash and the slash may be misread.
    "  blockDuration: (a] ) / 2, // c",
    "  blockDuration: (a} ) / 2, // c",
    // Here the ) closes the { or [ in its place, so no closing bracket goes
    // unopened, and only slashMayBeMisread() finding a { or [ where it looks
    // for the ( of the ) gives null.
    "  keyPrefix: { a ) / 2,",
    "  keyPrefix: [ a ) / 2,",
    // The same holds with a ++ or -- between that ) and the slash, which is
    // postfix unless the ) closes the parentheses after if, for, for await or
    // while.
    "  keyPrefix: { a )++ / 2,",
    // A closing bracket the line does not open ends the options object
    // before the }); line, and the limiter gets the object after it.
    "  duration: 60 } && { blockDuration: 300, // per minute",
    "  duration: /* s */ 60 } && { blockDuration: 300, // per minute",
    // A ), ] or } the line does not open, after another token or as the first
    // token of the value, closes a bracket that an earlier line opens, if any,
    // so the line does not set one option.
    "  duration: 60) && 1,",
    "  duration: 60] && 1,",
    "  duration: ) && 1,",
    "  duration: ] && 1,",
    "  duration: } && 1,",
    // A value that ends with a token it goes on after, such as the ? of a
    // conditional, which the next line continues. Each next line reads as a
    // key: value pair, and the : in it is the conditional's.
    ["  keyPrefix: x ?", "  duration: 60, // per minute"],
    ["  keyPrefix: f(a ?", "  duration: 60), // c"],
    ["  keyPrefix: [a ?", "  duration: 60], // c"],
    // A value that a block comment, string or template continues on the next
    // line. That line reads as a key: value pair in the first four of these,
    // and as a comment in the last.
    ["  points: 30, /* requests", "  duration: 60 */ // per minute"],
    ["  points: x && `", "  duration: 60` && 30, // requests"],
    ["  points: /x/.source && `", "  duration: 60` && 30, // requests"],
    ['  points: "a\\', '  duration: 60" && 30, // requests'],
    ["  keyPrefix: `a", "  // b`,"],
  ]) {
    const added = [line].flat();
    assert.equal(limiterOptionKeys(add(...added)), null, `${added.map((l) => l.trim()).join(" then ")} is read as neither a comment nor one key: value pair`);
  }
  assert.equal(limiterOptionKeys(add().replace("new RateLimiterMemory({", "new RateLimiterMemory(extraOptions, {")), null, "a limiter created without an options object on its own lines has no options read");
});

test("the limiter options reader reads a last value that ends with a TypeScript non-null assertion or with the type arguments of a type after as or satisfies, a comma among them, after the } of an object literal, of a later type in a union or intersection and of a typeof query too, and no value that ends with a !, >, as or satisfies the next line continues or that leaves a bracket or type arguments open", () => {
  const options = (...lines) => ["const rateLimiter = new RateLimiterMemory({", "  points: 30, // requests", ...lines, "});", ""].join("\n");
  for (const line of [
    "  duration: settings.duration!",
    "  duration: f(a)[0]!",
    "  duration: settings.duration!!",
    "  duration: 60 as Duration<60>",
    "  duration: 60 satisfies Duration<60>",
    "  duration: 60 as unknown as ns.Duration<Seconds<60>>",
    "  duration: 60 as Duration<() => void>",
    "  duration: 60 as Duration<{ a: 1 }>",
    "  duration: settings.duration! as Duration<60>",
    // A comma inside type arguments is part of the value. A ! right after the
    // } of an object literal is a non-null assertion, and the type arguments
    // of a type after an as or satisfies that follows that }, of a later type
    // in a union or intersection and of a typeof query end an operand too.
    "  duration: x as Record<string, number>",
    "  duration: { a: 60 } satisfies Record<string, number>",
    "  duration: {} as D<1>",
    "  duration: {}!",
    "  duration: 60 as A | D<1>",
    "  duration: 60 as A<1> & D<2> | E<3>",
    "  duration: x as typeof f<number>",
    "  duration: x as A | typeof ns.f<number>",
  ]) {
    assert.deepEqual(limiterOptionKeys(options(line)), ["points", "duration"], `${line.trim()} is read as one key: value pair`);
  }
  for (const line of [
    // A ! that follows no operand, a > that ends no type arguments and the >
    // of a => inside them are operators that the next line continues, and the
    // : on it is the conditional's.
    ["  keyPrefix: x ? !", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a < b >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as A >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as A<1> >", "  duration: 60, // per minute"],
    "  keyPrefix: a as F<() =>",
    // TypeScript reads a < right after one of these names as a comparison
    // when the name is the one after an as or satisfies, so the > after it is
    // an operator that the next line continues too, and a ! right after that >
    // follows no operand.
    ...["any", "bigint", "boolean", "false", "function", "never", "null", "number", "object", "string", "symbol", "this", "true", "undefined", "unknown", "void"].flatMap((type) => ["as", "satisfies"].map((operator) => [`  keyPrefix: x ? a ${operator} ${type} < b >`, "  duration: 60, // per minute"])),
    ["  keyPrefix: x ? a as number < b > !", "  duration: 60, // per minute"],
    // TypeScript reads a <= right after the name of a type after an as or
    // satisfies as a comparison whatever that name is, so the > after it in
    // these values is an operator that the next line continues too, and a !
    // right after that > follows no operand.
    ["  keyPrefix: x ? a as D <= b >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a satisfies D <= b >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as ns.D <= b >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as D <= b && c >", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as D <= b > !", "  duration: 60, // per minute"],
    ["  keyPrefix: x ? a as number < b as D <= c >", "  duration: 60, // per minute"],
    // TypeScript reads a < right after number or one of the 15 other names as
    // a comparison when the name starts a later type in a union too, so the >
    // after it is an operator as well.
    ["  keyPrefix: x ? a as A | number < b >", "  duration: 60, // per minute"],
    // An as or satisfies at the end of a value is an operator that the next
    // line continues, whether moduleTokens() marks it or not, and the : on that
    // line is the conditional's.
    ["  keyPrefix: x ? a as", "  'duration': 60,"],
    ["  keyPrefix: x ? a satisfies", "  'duration': 60,"],
    ["  keyPrefix: x ? a!++ as", "  'duration': 60,"],
    ["  keyPrefix: x ? function () {} as", "  'duration': 60,"],
    // The next line continues a value that leaves a bracket or type arguments
    // open, and a }); line there does not end the options.
    ["  duration: (() => { g({ a: 1", "}); return 60; })(), blockDuration: 300,"],
    "  duration: x as Record<string,",
  ]) {
    const added = [line].flat();
    assert.equal(limiterOptionKeys(options(...added)), null, `${added.map((l) => l.trim()).join(" then ")} is read as neither a comment nor one key: value pair`);
  }
});

test("step 1 is the rate limit, which every request that reaches it counts toward before the handler authenticates it", () => {
  // test/validated-task-handler.test.mjs sends requests that fail
  // authentication until the next request gets 429, and requests answered 431
  // that the limiter does not count.
  const handler = readText("examples/validated-task-handler/handler.ts");
  assert.match(handler, /app\.post\("\/", rateLimit, authenticate, /, "handler.ts runs the rate limiter before authentication");
  const points = handler.match(/points: (\d+), \/\/ requests/);
  const duration = handler.match(/duration: 60, \/\/ per minute/);
  assert.ok(points && duration, "handler.ts allows a number of requests per minute");
  // Another option, such as a blockDuration, would change when a client's
  // count starts again from what step 1 says.
  assert.deepEqual(limiterOptionKeys(handler), ["points", "duration"], "handler.ts creates the limiter with an options object of key: value pairs and comments, and gives it no option but points and duration");
  const step = inputValidationLines.find((l) => l.startsWith("1. "));
  assert.ok(step, "docs/input-validation.md lists a step 1");
  assert.ok(step.startsWith(`1. Rate limit of ${points[1]} requests per minute per client IP: 429. Every request that reaches the limiter counts, including one that then fails authentication; a request answered 431 for too many header lines (see step 2) is not counted.`), "README lists the rate limit as step 1 and says a request that fails authentication counts and one answered 431 does not");
  assert.doesNotMatch(step, /Every request counts/, "step 1 does not say that every request counts, as one answered 431 never reaches the limiter");
  assert.ok(step.includes("The limiter counts a client's requests for 60 seconds from its first one and starts again with its first request after those 60 seconds have ended"), "step 1 says the 60 seconds start with a client's first request and the count starts again after they have ended");
});

test("step 1 says that clients behind a reverse proxy share one count unless the deployment sets trust proxy to the proxies' addresses, and never to true, and handler.ts sets no trust proxy", () => {
  // test/validated-task-handler.test.mjs sends requests from 127.0.0.1 with a
  // different X-Forwarded-For value each until the next request gets 429,
  // which fails only when trust proxy trusts 127.0.0.1, as true, 1 or
  // "loopback" do. A setting that names a proxy's address, as step 1 shows,
  // passes it, so this test checks that handler.ts sets no trust proxy at all.
  const handler = readText("examples/validated-task-handler/handler.ts");
  assert.deepEqual(trustProxyCalls(handler), [], "handler.ts calls neither set(\"trust proxy\", ...) nor enable(\"trust proxy\"), so req.ip is the address a request came from");
  assert.match(handler, /const clientIp = req\.ip \|\| "unknown";\n  try \{\n    await rateLimiter\.consume\(clientIp\);/, "handler.ts keys the limiter on req.ip");
  const step = inputValidationLines.find((l) => l.startsWith("1. "));
  assert.ok(step.includes("It keys on the client IP Express gives as `req.ip`, which behind a reverse proxy is the proxy's address, so every client behind the proxy shares one count"), "step 1 says clients behind a reverse proxy share one count");
  assert.ok(step.includes("A deployment behind a proxy sets Express's `trust proxy` to the proxies it runs, so that `req.ip` is the client's address."), "step 1 says a deployment behind a proxy sets trust proxy");
  assert.ok(step.includes('as in `app.set("trust proxy", "10.0.0.2")` for one proxy at 10.0.0.2'), "step 1 shows the setting with a proxy's address");
  assert.ok(step.includes("never sets it to `true`: Express then gives as `req.ip` the leftmost `X-Forwarded-For` address, which the client chooses"), "step 1 says not to set trust proxy to true, and why");
});

test("a checkout gets \"\\n\" line endings, and this file reads each file it checks through readText, which gives \"\\n\" line endings, or JSON.parse, which allows \"\\r\\n\"", () => {
  // core.autocrlf=true checks text files out with "\r\n" line endings unless
  // .gitattributes says otherwise, and the line splits and patterns in this
  // file expect "\n".
  assert.ok(readText(".gitattributes").split("\n").includes("* text=auto eol=lf"), ".gitattributes checks text files out with \"\\n\" line endings");
  assert.equal(lfLineEndings("a\r\nb\r\n"), "a\nb\n", "lfLineEndings turns \"\\r\\n\" into \"\\n\"");
  const file = readText("test/readme.test.mjs");
  const helper = file.match(/^function readText\(path\) \{\n[\s\S]*?\n\}$/m);
  assert.match(helper?.[0] ?? "", /^function readText\(path\) \{\n  return lfLineEndings\(readFileSync\(join\(root, path\), "utf8"\)\);\n\}$/, "readText gives a file's text through lfLineEndings");
  // The file with readText blanked by spaces, so that a read is on the same
  // line as in the file.
  const source = file.slice(0, helper.index) + helper[0].replace(/[^\n]/g, " ") + file.slice(helper.index + helper[0].length);
  const reads = [...source.matchAll(/(JSON\.parse\()?readFileSync\(/g)];
  assert.ok(reads.length > 0, "this file reads package.json files");
  for (const read of reads) {
    const line = source.slice(0, read.index).split("\n").length;
    assert.ok(read[1], `the read on line ${line} parses JSON, which allows "\\r\\n", or goes through readText`);
  }
});

test("step 2 puts the 431 for too many header lines before step 1, as the handler checks the header lines before the route that runs the limiter", () => {
  // test/validated-task-handler.test.mjs sends more requests answered 431 than
  // the limiter allows and then a request that is accepted.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const headerLines = handler.indexOf("app.use(limitHeaderLines);");
  const route = handler.indexOf('app.post("/", rateLimit, ');
  assert.ok(headerLines >= 0 && route >= 0, "handler.ts registers limitHeaderLines and a POST / route that runs the limiter");
  assert.ok(headerLines < route, "handler.ts registers limitHeaderLines before the POST / route that runs the limiter");
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  const limit = Number(handler.match(/const maxHeaderLines = (\d+);/)[1]).toLocaleString("en-US");
  assert.ok(step.includes(`Before step 1, a request with ${limit} or more header lines gets 431`), "step 2 says a request with too many header lines gets 431 before step 1");
});

test("the bearer token sentence names every token the handler rejects", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const rejected = [...handler.matchAll(/token !== "([^"]+)"/g)].map((m) => m[1]);
  assert.ok(rejected.length > 0, "isValidToken rejects at least one literal token");
  for (const [where, text] of [["README.md", lines], ["docs/validated-task-handler.md", handlerPageLines]]) {
    const sentence = text.find((l) => /The example accepts any bearer token/.test(l));
    assert.ok(sentence, `${where} describes which bearer tokens the example accepts`);
    for (const token of rejected) {
      assert.ok(sentence.includes(`\`${token}\``), `${where} says the token ${token} is rejected`);
    }
  }
});

// The pattern handler.ts matches the Authorization header against.
function credentialsPattern() {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const source = handler.match(/authHeader\.match\(\/(.+)\/([a-z]*)\)/);
  assert.ok(source, "handler.ts matches the Authorization header against a pattern");
  return new RegExp(source[1], source[2]);
}

// The pattern handler.ts reads the Bearer scheme of an Authorization header with.
function bearerSchemePattern() {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const source = handler.match(/const bearerScheme = \/(.+)\/([a-z]*);/);
  assert.ok(source, "handler.ts reads the scheme of the Authorization header with a pattern");
  return new RegExp(source[1], source[2]);
}

// A header as the handler receives it: Node.js decodes header bytes as
// Latin-1, so each UTF-8 byte of a character outside ASCII is a character.
function received(header) {
  return Buffer.from(header, "utf8").toString("latin1");
}

// The headers the 401 sentence of step 2 gives as examples of another scheme,
// or null when step 2 has no such sentence. The capture runs lazily to the
// comma before "gets 401", as a scheme name and a token can each hold a period,
// and must be a list of backticked headers joined by ", " or " or ", so a claim
// the handler does not make cannot stand between "such as" and "gets 401".
function otherSchemeExamples(rejected) {
  const other = rejected.match(/A request without the header, or whose header names another scheme, such as (.+?), gets 401\./);
  if (!other) return null;
  assert.match(other[1], /^`[^`]+`(?:(?:, | or )`[^`]+`)*$/, `step 2 gives only backticked headers joined by ", " or " or " between "such as" and ", gets 401.", not: ${other[1]}`);
  return [...other[1].matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

test("step 2 gives 401 for a missing header or another scheme, and 400 for a Bearer header that is not followed by one token", () => {
  // RFC 6750, section 3.1: a request with no bearer credentials gets 401 and a
  // malformed one gets 400. The handler answers 400 to a header such as Bearer
  // demo token, which names the Bearer scheme but holds two tokens.
  const scheme = bearerSchemePattern();
  const credentials = credentialsPattern();
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  assert.ok(step, "docs/input-validation.md lists bearer authentication as step 2");
  assert.doesNotMatch(step, /401 without a token/, "a header with a token in it can get 401 too");
  const [rejected, invalid = ""] = step.split("; an invalid token ");
  assert.match(rejected, /one or more spaces and one token/, "step 2 says what follows Bearer in a header that passes");
  const named = otherSchemeExamples(rejected);
  assert.ok(named, "step 2 gives 401 for a missing header and for one that names another scheme");
  assert.ok(named.length > 0, "step 2 gives a header that names another scheme");
  for (const header of named) {
    assert.doesNotMatch(received(header), scheme, `handler.ts reads ${header} as another scheme`);
  }
  assert.match(rejected, /As RFC 6750, section 3\.1, suggests, a request that sends the header more than once gets 400, and so does one whose header names the `Bearer` scheme in any other form: /, "step 2 gives 400 for a malformed Bearer header");
  const examples = [...rejected.matchAll(/`(Bearer [^`]+)`/g)].map((m) => m[1]);
  assert.ok(examples.length >= 2, "step 2 gives Bearer headers that have a token in them and get 400");
  for (const header of examples) {
    assert.match(received(header), scheme, `handler.ts reads ${header} as the Bearer scheme`);
    assert.doesNotMatch(received(header), credentials, `handler.ts answers 400 to ${header}`);
  }
  // The header the quick start sends is one the handler's pattern accepts.
  const sent = readme.match(/-H "Authorization: ([^"]+)"/);
  assert.ok(sent, "the quick start sends an Authorization header");
  assert.match(sent[1], credentials, `handler.ts reads a token from ${sent[1]}`);
  assert.match(invalid, /^gets 401\./, "step 2 gives 401 for an invalid token");
  assert.doesNotMatch(step, /\b403\b/, "step 2 gives no 403");
});

test("step 2 names each form of a Bearer header that gets 400, with a header of each form that the handler answers 400 to", () => {
  // test/validated-task-handler.test.mjs sends headers of each form.
  const scheme = bearerSchemePattern();
  const credentials = credentialsPattern();
  const { made, ending } = tokenCharacters(credentials);
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  const [rejected] = step.split("; an invalid token ");
  const forms = rejected.match(/names the `Bearer` scheme in any other form: (.+)$/);
  assert.ok(forms, "step 2 gives 400 for a header that names the Bearer scheme in any form but Bearer, one or more spaces and one token");
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
    assert.ok(start >= 0, `step 2 gives 400 for a Bearer header with ${kind}, and an example`);
    const listed = forms[1].slice(start + `with ${kind} (`.length).split(")")[0];
    const examples = [...listed.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    assert.ok(examples.length > 0, `step 2 gives a Bearer header with ${kind}`);
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
  const named = otherSchemeExamples(rejected);
  assert.ok(named, "step 2 gives 401 for a header that names another scheme");
  assert.ok(named.some((header) => /^Bearer[^ ]/.test(header)), "step 2 gives a header whose scheme name starts with Bearer as another scheme");
});

test("the 401 examples of step 2 are read whole when a header holds a period, and end at the first comma before gets 401", () => {
  // The handler answers 401 to these headers, so step 2 could give them.
  const scheme = bearerSchemePattern();
  const headers = ["Bearerx demo.token", "Bearer.x demo-token"];
  const later = "Digest demo";
  for (const header of [...headers, later]) {
    assert.doesNotMatch(received(header), scheme, `handler.ts reads ${header} as another scheme`);
  }
  const sentence = `A request without the header, or whose header names another scheme, such as \`${headers[0]}\` or \`${headers[1]}\`, gets 401.`;
  assert.deepEqual(otherSchemeExamples(sentence), headers, "the checks of step 2 read each 401 example whole");
  // A later clause that also ends with ", gets 401." gives no example of the
  // 401 sentence, so a capture that runs past the first one fails here.
  const followed = `${sentence} A request whose header names a scheme such as \`${later}\`, gets 401.`;
  assert.deepEqual(otherSchemeExamples(followed), headers, "the checks of step 2 read the 401 examples of the first clause only");
});

test("the 401 examples of step 2 are only backticked headers joined by \", \" or \" or \"", () => {
  const sentence = (list) => `A request without the header, or whose header names another scheme, such as ${list}, gets 401.`;
  assert.deepEqual(otherSchemeExamples(sentence("`Basic demo`")), ["Basic demo"]);
  assert.deepEqual(otherSchemeExamples(sentence("`Basic demo`, `Bearerx demo.token` or `Token x`")), ["Basic demo", "Bearerx demo.token", "Token x"]);
  const claims = [
    "`Basic demo` or `Bearerx demo-token`. A request with any token at all",
    "`Basic demo` or `Bearerx demo-token` and also a request with any token at all",
    "`Basic demo` and any other header",
    "`Basic demo` and any token or `Bearerx demo-token`",
    "any header",
  ];
  for (const list of claims) {
    assert.throws(() => otherSchemeExamples(sentence(list)), /step 2 gives only backticked headers/, `the checks of step 2 reject: ${list}`);
  }
});

test("step 2 says Bearer in any letter case and one or more spaces, and the handler's pattern takes both", () => {
  const credentials = credentialsPattern();
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  assert.match(step, /`Bearer` \(in any letter case\) followed by one or more spaces and one token/, "step 2 says the scheme is read in any letter case and followed by one or more spaces");
  for (const header of ["bearer demo-token", "BEARER demo-token"]) {
    assert.match(header, credentials, `handler.ts reads a token from ${header}, so the scheme is read in any letter case`);
  }
  assert.match("Bearer   demo-token", credentials, "handler.ts reads a token after three spaces, so one or more spaces follow the scheme");
  assert.doesNotMatch("Bearerdemo-token", credentials, "handler.ts reads no token when no space follows the scheme");
});

test("step 2 gives 400 for a request with more than one Authorization header, which the handler counts", () => {
  // req.headers holds the first Authorization line of a request and none of
  // the later ones, so the handler can only see a second line in rawHeaders.
  // test/validated-task-handler.test.mjs sends such requests.
  const handler = readText("examples/validated-task-handler/handler.ts");
  assert.match(handler, /req\.rawHeaders/, "handler.ts counts the Authorization header lines of a request");
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  assert.match(step.split("; an invalid token ")[0], /a request that sends the header more than once gets 400/, "step 2 gives 400 for a header sent more than once");
});

test("step 2 gives 400 to a header sent more than once whatever scheme it names, as the handler counts the lines before it reads the scheme", () => {
  // A single header that names another scheme gets 401, so step 2 says which
  // answer two such lines get. test/validated-task-handler.test.mjs sends them.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const counted = handler.indexOf("authorizationLines(req) > 1");
  const read = handler.indexOf("bearerScheme.test(authHeader)");
  assert.ok(counted !== -1 && read !== -1, "handler.ts counts the Authorization header lines and reads the scheme");
  assert.ok(counted < read, "handler.ts counts the Authorization header lines before it reads the scheme");
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  const repeated = step.split("; an invalid token ")[0].match(/, and so do two `Authorization: ([^`]+)` lines: the handler counts the header lines before it reads the scheme, so a repeated header gets 400 whatever scheme it names$/);
  assert.ok(repeated, "step 2 gives 400 to two Authorization lines that name another scheme");
  assert.doesNotMatch(received(repeated[1]), bearerSchemePattern(), `handler.ts reads ${repeated[1]} as another scheme, which gets 401 when sent once`);
});

test("step 2 names the challenges the handler's 400 and 401 responses carry and the header line count at which it answers 431", () => {
  // test/validated-task-handler.test.mjs sends requests that get these answers.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const step = inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:"));
  const challenge = handler.match(/const bearerChallenge = '([^']+)';/);
  assert.ok(challenge, "handler.ts sets the challenge its 401 responses carry");
  // RFC 6750, section 3: the Bearer scheme is followed by one or more auth-params.
  assert.match(challenge[1], /^Bearer [a-z_]+="[^"]*"/, "the challenge has an auth-param after Bearer");
  assert.match(handler, /status\(401\)\.set\("WWW-Authenticate", bearerChallenge\)/, "handler.ts sets the challenge on a 401 response");
  assert.ok(step.includes(`Each 401 carries the challenge \`WWW-Authenticate: ${challenge[1]}\``), "step 2 names the challenge");
  const invalid = handler.match(/status\(401\)\.set\("WWW-Authenticate", `\$\{bearerChallenge\}([^`]+)`\)\.json\(\{ error: "Invalid or expired token" \}\)/);
  assert.ok(invalid, "handler.ts adds an error code to the challenge for an invalid token");
  assert.ok(step.includes(`the one for an invalid token adds the error code from RFC 6750, section 3.1: \`WWW-Authenticate: ${challenge[1]}${invalid[1]}\``), "step 2 names the challenge for an invalid token");
  const malformed = handler.match(/status\(400\)\.set\("WWW-Authenticate", `\$\{bearerChallenge\}([^`]+)`\)/);
  assert.ok(malformed, "handler.ts adds an error code to the challenge for a malformed Authorization header");
  assert.ok(step.includes(`Each 400 in this step adds the error code for a malformed request: \`WWW-Authenticate: ${challenge[1]}${malformed[1]}\``), "step 2 names the challenge for a malformed Authorization header");
  const limit = handler.match(/const maxHeaderLines = (\d+);/);
  assert.ok(limit, "handler.ts sets the number of header lines at which a request gets 431");
  const count = Number(limit[1]).toLocaleString("en-US");
  assert.ok(step.includes(`a request with ${count} or more header lines gets 431`), `step 2 gives 431 for ${count} or more header lines`);
  const sentence = handlerPageLines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  assert.match(sentence, /Requests rejected with HTTP 431 and requests for the agent card write no audit line\./, "docs/validated-task-handler.md says a 431 writes no audit line");
});

// The characters the pattern takes in a bearer token, of the 256 a header byte
// decodes to: those a token is made of, and those that can only end one.
function tokenCharacters(credentials) {
  const decoded = Array.from({ length: 256 }, (_, byte) => String.fromCharCode(byte));
  const made = decoded.filter((c) => credentials.test(`Bearer ${c}`));
  const ending = decoded.filter((c) => !made.includes(c) && credentials.test(`Bearer a${c}`));
  return { made, ending };
}

test("the bearer token sentence and step 2 name the characters the handler takes in a token, and step 2 gives a token outside them", () => {
  const credentials = credentialsPattern();
  const { made, ending } = tokenCharacters(credentials);
  const alphanumeric = made.filter((c) => /[A-Za-z0-9]/.test(c));
  assert.equal(alphanumeric.length, 62, "handler.ts takes every ASCII letter and digit in a token");
  const marks = made.filter((c) => !alphanumeric.includes(c));
  const named = (text) => [...text.matchAll(/`([^`]+)`/g)].map((m) => m[1]).sort();
  const sentences = {
    "the bearer token sentence": handlerPageLines.find((l) => /The example accepts any bearer token/.test(l)),
    "step 2": inputValidationLines.find((l) => l.startsWith("2. Bearer authentication:")),
  };
  for (const [where, sentence] of Object.entries(sentences)) {
    assert.ok(sentence, `docs/ has ${where}`);
    const set = sentence.match(/\(one or more ASCII letters, digits, ([^)]+), then any number of ([^)]+)\)/);
    assert.ok(set, `${where} names the characters of a bearer token`);
    assert.deepEqual(named(set[1]), [...marks].sort(), `${where} names every character handler.ts takes in a token besides letters and digits, and no other`);
    assert.deepEqual(named(set[2]), [...ending].sort(), `${where} names every character handler.ts takes only at the end of a token`);
  }
  // A token with a character outside the set gets 400 like any other Bearer
  // header that is not followed by one token, whichever bytes the character is
  // sent as.
  const examples = [...sentences["step 2"].split("; an invalid token ")[0].matchAll(/`Bearer ([^` ]+)`/g)].map((m) => m[1]);
  const outside = examples.filter((token) => [...received(token)].some((c) => !made.includes(c) && !ending.includes(c)));
  assert.ok(outside.length > 0, "step 2 gives a header whose one token has a character outside the set");
  for (const token of outside) {
    assert.doesNotMatch(received(`Bearer ${token}`), credentials, `handler.ts answers 400 to Bearer ${token}`);
  }
});

test("the audit sentence names a body that is not a JSON object or array, the size limit, an unsupported encoding or charset, a compressed body that does not inflate, and a body cut off by a closed connection", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  assert.ok(limit, "handler.ts sets the JSON body limit in megabytes");
  const sentence = handlerPageLines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
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
    assert.ok(rejected.includes(reason), `docs/validated-task-handler.md says request_rejected covers a body ${reason}`);
  }
});

test("the audit sentence limits the bare 400 to a client that closes the connection and names the 408 for a stalled upload", () => {
  const sentence = handlerPageLines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  const rejected = sentence.match(/`request_rejected` for ([^`]*)/)?.[1] ?? "";
  assert.match(rejected, /at most a bare HTTP 400 with no body when the client closes it/);
  assert.match(rejected, /a bare HTTP 408 with no body when the upload stalls until Node's request timeout/);
});

test("README and its docs pages do not describe the strict JSON parser as accepting any valid JSON", () => {
  // The parser rejects valid JSON such as 123 or "text" that is not an object
  // or array, so "not valid JSON" undersells what gets a 400.
  for (const text of [readme, ...docsPages.map(readText)]) {
    assert.doesNotMatch(text, /not valid JSON/);
    assert.doesNotMatch(text, /no JSON reply because the connection is already gone/);
  }
});

test("step 3 limits the Invalid JSON reply to a non-empty body sent as application/json", () => {
  // The parser reads an empty body as {} and skips a body that is not declared
  // as JSON, so both fail schema validation in step 4, not JSON parsing.
  const step = inputValidationLines.find((l) => l.startsWith("3. JSON parsing:"));
  assert.ok(step, "docs/input-validation.md lists JSON parsing as step 3");
  const [claim, exceptions = ""] = step.split('`{"code":-32700,"message":"Invalid JSON"}`');
  assert.ok(claim.includes("non-empty body sent as `application/json`"), "step 3 applies to a non-empty body sent as application/json");
  assert.ok(claim.includes("not a JSON object or array"), "step 3 names a body that is not a JSON object or array");
  assert.match(exceptions, /empty body/, "docs/input-validation.md says an empty body does not get the Invalid JSON reply");
  assert.match(exceptions, /not sent as `application\/json`/, "docs/input-validation.md says a body with another content type does not get the Invalid JSON reply");
  assert.match(exceptions, /step 4/, "docs/input-validation.md says which step answers those bodies instead");
});

test("step 3 says a body the parser cannot read gets Invalid request body, not Invalid JSON, whatever it contains", () => {
  // Reading the body comes before parsing it, so a body such as 123 over the
  // size limit or in an unsupported charset never reaches the Invalid JSON reply.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  assert.ok(limit, "handler.ts sets the JSON body limit in megabytes");
  const step = inputValidationLines.find((l) => l.startsWith("3. JSON parsing:"));
  assert.ok(step, "docs/input-validation.md lists JSON parsing as step 3");
  assert.ok(step.includes('`{"code":-32600,"message":"Invalid request body"}`'), "step 3 names the Invalid request body reply");
  assert.match(step, /the parser cannot read[^.]*whatever it contains/, "step 3 says the reply does not depend on what the body contains");
  assert.match(step, new RegExp(`\\b413\\b[^,]*over ${limit[1]} MB`), "step 3 gives 413 for a body over the size limit");
  assert.match(step, /\b415\b[^,]*unsupported encoding or charset/, "step 3 gives 415 for an unsupported encoding or charset");
  assert.match(step, /\b400\b[^,]*compressed body that does not inflate/, "step 3 gives 400 for a compressed body that does not inflate");
  assert.match(step, /bare HTTP 400 with no body when the client closes the connection before the whole body arrives/, "step 3 limits the bare 400 to a client that closes the connection");
  assert.match(step, /bare HTTP 408 with no body when the upload stalls until Node's request timeout/, "step 3 names the bare 408 for a stalled upload");
});

test("step 3 says the body limit leaves room for the file parts step 4 allows when their bytes are written without JSON escapes", () => {
  // JSON can write a base64 character as a six-byte \uXXXX escape, and a
  // message the schema accepts whose file bytes are written that way can be
  // over the limit.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  const parts = handler.match(/parts: z\.array\(PartSchema\)\.min\(1\)\.max\((\d+)\)/);
  const bytes = handler.match(/bytes: z\.string\(\)\.max\((\d+)\)/);
  assert.ok(limit && parts && bytes, "handler.ts sets the JSON body limit, the most parts and the longest bytes");
  const [limitBytes, mostParts, longest] = [Number(limit[1]) * 1024 * 1024, Number(parts[1]), Number(bytes[1])];
  assert.ok(mostParts * longest < limitBytes, "the bytes of the most file parts are under the limit with one byte for each character");
  assert.ok(mostParts * longest * 6 > limitBytes, "they are over the limit with each character written as a six-byte escape");
  const step = inputValidationLines.find((l) => l.startsWith("3. JSON parsing:"));
  assert.ok(step, "docs/input-validation.md lists JSON parsing as step 3");
  assert.ok(
    step.includes(`over ${limit[1]} MB (room for ${mostParts} file parts of ${longest.toLocaleString("en-US")} base64 characters written without JSON escapes, the most step 4 allows)`),
    "step 3 says the limit leaves room for the file parts when their bytes are written without JSON escapes"
  );
});

test("the audit sentence and the attack page give the body limit of POST /a2a/message as handler.ts sets it, with the characters the route reads and the bytes they take", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const limit = handler.match(/express\.json\(\{ limit: "(\d+)mb" \}\)/);
  assert.ok(limit, "handler.ts sets the JSON body limit in megabytes");
  const routeLimit = handler.match(/const (\w+) = express\.json\(\{ limit: "(\d+)kb" \}\);/);
  assert.ok(routeLimit, "handler.ts sets a second JSON body limit in kilobytes");
  assert.ok(handler.includes(`app.post("/a2a/message", rateLimit, authenticate, ${routeLimit[1]}, `), "POST /a2a/message uses the parser with the second limit");
  const sentence = handlerPageLines.find((l) => /\baudit lines?\b/.test(l) && !l.startsWith("|"));
  assert.ok(sentence.startsWith("Requests to `POST /` and to `POST /a2a/message` "), "the audit sentence names POST /a2a/message second");
  const rejected = sentence.match(/`request_rejected` for ([^`]*)/)?.[1] ?? "";
  assert.ok(rejected.includes(`over ${limit[1]} MB, or over ${routeLimit[2]} KB at the second route,`), "docs/validated-task-handler.md says request_rejected covers a body over the limit of each route");
  // The longest from, to and content the route takes, and the bytes they take
  // when each character is written as a \uXXXX escape, the longest form JSON
  // has for one.
  assert.match(handler, /^  content: TextPartSchema\.shape\.text,$/m, "content has the bounds of a text part");
  const longest = [/^  from: z\.string\(\)\.min\(1\)\.max\((\d+)\),$/m, /^  to: z\.string\(\)\.min\(1\)\.max\((\d+)\),$/m, /^  text: z\.string\(\)\.min\(1\)\.max\((\d+)\),$/m];
  const characters = longest.reduce((sum, pattern) => sum + Number(handler.match(pattern)?.[1]), 0);
  assert.ok(Number.isInteger(characters), "handler.ts sets the longest from, to and text");
  const bytes = characters * 6;
  assert.ok(bytes < Number(routeLimit[2]) * 1024, `${bytes} bytes fit the limit of ${routeLimit[2]} KB`);
  const count = (number) => number.toLocaleString("en-US");
  assert.ok(attackPage.includes(`413 for a body over ${routeLimit[2]} KB, not ${limit[1]} MB`), "docs/testing-against-real-attacks.md gives the body limit of POST /a2a/message beside the limit of POST /");
  assert.ok(
    attackPage.includes(`the ${count(characters)} characters it reads take at most ${count(bytes)} bytes, each written as a six-byte \`\\uXXXX\` escape`),
    `docs/testing-against-real-attacks.md says the ${count(characters)} characters the route reads take at most ${count(bytes)} bytes`
  );
});

test("step 4 says the bytes of a file part must be base64, as the handler's schema checks, and each declaration in the schema excerpt is in handler.ts", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const bytes = handler.match(/^    bytes: z\.string\(\)\.max\((\d+)\)\.pipe\(z\.string\(\)\.refine\(isBase64, "[^"]+"\)\),/m);
  assert.ok(bytes, "the schema checks the length of bytes, then that they are base64");
  const step = inputValidationLines.find((l) => l.startsWith("4. Schema validation"));
  assert.ok(step, "docs/input-validation.md lists schema validation as step 4");
  assert.ok(step.includes(`up to ${Number(bytes[1]).toLocaleString("en-US")} characters of \`bytes\`, which must be base64 as RFC 4648, section 4, defines it`), "step 4 gives the longest bytes and says they must be base64");
  const section = inputValidation.split(/^# Input validation$/m)[1] ?? "";
  const excerpt = codeBlocks(section).find((b) => b.lang === "typescript");
  assert.ok(excerpt, "the Input validation section has a TypeScript excerpt");
  const declarations = excerpt.body.trim().split("\n\n");
  assert.ok(declarations.some((d) => d.startsWith("const FilePartSchema = ")), "the excerpt declares FilePartSchema");
  for (const declaration of declarations) {
    assert.ok(handler.includes(declaration), `handler.ts declares ${declaration.split("\n")[0]} as the excerpt does`);
  }
});

// The text of each part of a TypeScript source that may start a statement at
// its top level, read with moduleTokens(). A part starts with a token outside
// any bracket and template substitution that begins the source, follows a line
// break, as a statement may end at one, or follows a ;. It also starts with a
// word a declaration or import starts with, such as const, export or import,
// that follows a } outside any bracket, as after the } of a function or class
// body: in a valid module, no such word comes next on the line after the } of
// an object literal, a pattern or the names an import lists. A part ends with
// the last token before the next part or the next line break, a line break
// being each character the TypeScript scanner reads as one: line feed,
// carriage return, U+2028 and U+2029. So a part may follow white space, a
// comment or another statement on its line, as const a = 1; does in
// /* c */ const a = 1; and const b = 2; in a(); const b = 2;, and none starts
// inside a comment, string or template. A source that ends inside a bracket,
// comment, string or template fails the check, as a bracket the reader does
// not close would hide each statement after it.
function topLevelParts(source) {
  const starters = new Set(["abstract", "async", "await", "class", "const", "declare", "enum", "export", "function", "import", "interface", "let", "namespace", "type", "using", "var"]);
  const tokens = moduleTokens(source);
  assert.ok(!tokens.unclosed && (tokens.at(-1)?.open ?? 0) === 0, "the check reads the source to its end with each bracket, comment, string and template closed");
  // The text the indexes of the tokens count in.
  const text = source.replace(/^\u{FEFF}/u, "");
  const lineBreak = (before, after) => /[\n\r\u{2028}\u{2029}]/u.test(text.slice(before.end, after.start));
  const starts = (k) => {
    const [previous, token] = [tokens[k - 1], tokens[k]];
    if (previous === undefined) return true;
    if (previous.open !== 0) return false;
    const after = (value) => previous.type === "punct" && previous.value === value;
    return lineBreak(previous, token) || after(";") || (after("}") && token.type === "name" && starters.has(token.raw));
  };
  const parts = [];
  for (let k = 0; k < tokens.length; k++) {
    if (!starts(k)) continue;
    let last = k;
    while (last + 1 < tokens.length && !starts(last + 1) && !lineBreak(tokens[last], tokens[last + 1])) last++;
    parts.push(text.slice(tokens[k].start, tokens[last].end));
  }
  return parts;
}

// A regular expression class of the characters the TypeScript scanner reads as
// white space within a line: space, tab, vertical tab, form feed, U+0085, the
// no-break space and the other Unicode space separators, U+200B and U+FEFF.
const whiteClass = "[ \\t\\v\\f\\u0085\\u00a0\\u1680\\u2000-\\u200b\\u202f\\u205f\\u3000\\ufeff]";

// The names a TypeScript source declares at its top level, exported or not:
// constants, variables, functions, async functions, classes, types,
// interfaces, enums, const enums and namespaces, each also after declare or
// abstract, and the names of using and await using declarations. The words of
// a declaration may be separated by a run of the characters in whiteClass, as
// in export\tconst x or using  u. A declaration is read where it starts a part
// topLevelParts gives, as after a line break such as U+2028 or after another
// statement on its line. A declaration that does not start with its name, such
// as const { a } = b or declare global {}, fails the check, so that none is
// passed over.
function topLevelDeclarations(source) {
  const space = `${whiteClass}+`;
  const exported = `(?:export${space}(?:default${space})?)?`;
  const keywords = `const|let|var|async${space}function|function|class|type|interface|enum|namespace`;
  // using is a declaration only when a name follows it, as in using u = f():
  // it is otherwise an identifier, as in using(x), using = 1, await using; or
  // using in x.
  const using = `(?:await${space})?using${space}(?!${whiteClass}|(?:in|instanceof)\\b)(?=[\\w$]|[^\\x00-\\x7f])`;
  const declaration = new RegExp(`^${exported}(?:(?:declare|abstract)${space}|(?:${keywords})\\b|${using})`);
  // const enum comes before const, which would read enum as the name.
  const named = new RegExp(`^${exported}(?:declare${space})?(?:abstract${space})?(?:const${space}enum|(?:await${space})?using|${keywords})\\b\\*?${space}(\\w+)`);
  return topLevelParts(source).filter((part) => declaration.test(part)).map((part) => {
    const name = part.match(named);
    assert.ok(name, `the check reads the name this declaration starts with: ${part}`);
    return name[1];
  });
}

// The names a TypeScript source imports, each with the module it comes from.
// An import declaration is read where it starts a part topLevelParts gives, as
// after a line break such as U+2028 or after another statement on its line,
// and its import keyword may be followed by a run of the characters in
// whiteClass or by a character that cannot continue a name, as in
// import\t{ z } or import{ z }. A part on which import is followed by ( or .,
// as in import("./x") or import.meta, is an expression and is passed over. An
// import declaration that is not on one line with its module in double quotes
// and a ; after it, as when import ends its line, fails the check, so that
// none is passed over.
function importedNames(source) {
  const keyword = new RegExp(`^import(?:${whiteClass}|[^\\w$\\\\\\u0080-\\uffff]|$)`);
  const expression = new RegExp(`^import${whiteClass}*[(.]`);
  const sideEffect = new RegExp(`^import${whiteClass}*"[^"]+";$`);
  const imports = topLevelParts(source).filter((part) => keyword.test(part) && !expression.test(part) && !sideEffect.test(part));
  return imports.flatMap((part) => {
    const declaration = part.match(new RegExp(`^import${whiteClass}*(.+) from "([^"]+)";$`));
    assert.ok(declaration, `the check reads this import declaration: ${part}`);
    const [, clause, module] = declaration;
    // The name a module's code uses is the last word of each item: b in a as b,
    // ns in * as ns, and X in type X, whether type comes before one item or,
    // as in import type X, before all of them. The words of an item are split
    // at runs of the characters in whiteClass, which include U+0085 and U+200B
    // that String.prototype.trim and \s do not match.
    const white = new RegExp(`${whiteClass}+`);
    const items = clause.replace(/[{}]/g, "").split(",").map((item) => item.split(white).filter((word) => word !== "")).filter((words) => words.length > 0);
    return items.map((words) => ({ name: words.pop(), module }));
  });
}

// Check that each name handler declares at its top level or imports, and the
// TypeScript excerpt of section uses without declaring it, is one the prose of
// section says handler.ts declares, or imports from the module it comes from.
function checkExcerptNames(handler, section) {
  const excerpt = codeBlocks(section).find((b) => b.lang === "typescript");
  assert.ok(excerpt, "the Input validation section has a TypeScript excerpt");
  const own = topLevelDeclarations(excerpt.body);
  const prose = section.replace(/^```[\s\S]*?^```$/gm, "").split("\n");
  const used = (name) => !own.includes(name) && new RegExp(`\\b${name.replace(/\$/g, "\\$")}\\b`).test(excerpt.body);
  const declared = topLevelDeclarations(handler);
  const imported = importedNames(handler);
  assert.ok(declared.includes("FilePartSchema") && own.includes("FilePartSchema"), "the check reads the declarations of handler.ts and of the excerpt");
  assert.ok(imported.some(({ name, module }) => name === "z" && module === "zod"), "the check reads the imports of handler.ts");
  for (const name of declared.filter(used)) {
    assert.ok(
      prose.some((line) => line.includes(`\`${name}\``) && line.includes("handler.ts declares")),
      `the excerpt uses ${name}, which handler.ts declares, and the section does not say so`
    );
  }
  for (const { name, module } of imported.filter(({ name }) => used(name))) {
    assert.ok(
      prose.some((line) => line.includes(`\`${name}\`, which handler.ts imports from \`${module}\``)),
      `the excerpt uses ${name}, which handler.ts imports from ${module}, and the section does not say so`
    );
  }
}

test("each name handler.ts declares at its top level or imports that the schema excerpt uses is declared in the excerpt, or the Input validation section says handler.ts declares it or imports it from its module", () => {
  // A reader who pastes the excerpt into a file of their own otherwise meets a
  // name the excerpt never declares and nothing says where it is.
  const handler = readText("examples/validated-task-handler/handler.ts");
  const section = (inputValidation.split(/^# Input validation$/m)[1] ?? "").split(/^## /m)[0];
  checkExcerptNames(handler, section);
  // The check fails for a section that names z and not the module handler.ts
  // imports it from.
  assert.throws(
    () => checkExcerptNames(handler, section.replace("`z`, which handler.ts imports from `zod`", "`z`")),
    /the excerpt uses z, which handler\.ts imports from zod, and the section does not say so/
  );
});

test("the excerpt check reads the top-level declarations and the imports of a TypeScript source, and fails for one it cannot read", () => {
  const declarations = [
    "const a = 1;",
    "export const b = 2;",
    "function c() {",
    "  const nested = 3;",
    "}",
    "async function d() {}",
    "function* e() {}",
    "type F = string;",
    "interface G {}",
    "export default class H {}",
    "let i = 4;",
    "var j = 5;",
    "enum K { X }",
    "class L {}",
    "const enum M { X }",
    "declare const n: number;",
    "abstract class O {}",
    "export declare abstract class P {}",
    "declare const enum Q { X }",
    "namespace R {}",
    "using s = f();",
    "await using t = g();",
    // using with no name after it is an identifier, not a declaration.
    "using(s);",
    "using[0] = 1;",
    "using = 2;",
    "await using;",
    "using in x;",
    "using instanceof X;",
    "export { a };",
  ];
  assert.deepEqual(topLevelDeclarations(declarations.join("\n")), ["a", "b", "c", "d", "e", "F", "G", "H", "i", "j", "K", "L", "M", "n", "O", "P", "Q", "R", "s", "t"]);
  assert.throws(() => topLevelDeclarations("const { a } = b;"), /the check reads the name this declaration starts with: const \{ a \} = b;/);
  assert.throws(() => topLevelDeclarations("declare global {}"), /the check reads the name this declaration starts with: declare global \{\}/);
  assert.throws(() => topLevelDeclarations("await using $s = f();"), /the check reads the name this declaration starts with: await using \$s = f\(\);/);
  const imports = [
    'import express from "express";',
    'import { z, ZodIssue as Issue } from "zod";',
    'import * as path from "path";',
    'import fs, { type Stats } from "fs";',
    'import os, * as ns from "os";',
    'import type { Server } from "http";',
    'import type Config from "./config";',
    'import "./setup";',
  ];
  assert.deepEqual(importedNames(imports.join("\n")), [
    { name: "express", module: "express" },
    { name: "z", module: "zod" },
    { name: "Issue", module: "zod" },
    { name: "path", module: "path" },
    { name: "fs", module: "fs" },
    { name: "Stats", module: "fs" },
    { name: "os", module: "os" },
    { name: "ns", module: "os" },
    { name: "Server", module: "http" },
    { name: "Config", module: "./config" },
  ]);
  assert.throws(() => importedNames('import {\n  z,\n} from "zod";'), /the check reads this import declaration: import \{/);
});

test("the excerpt check reads a top-level declaration whose words a run of spaces and tabs separates", () => {
  const declarations = [
    "export  const a = 1;",
    "export\tdefault  class B {}",
    "using  c = f();",
    "await\tusing d = g();",
    "declare\tconst e: number;",
    "export  declare  abstract\tclass F {}",
    "async  function g() {}",
    "const \t enum H { X }",
    "function*\ti() {}",
    "const\tj = 2;",
    // using with no name after it is an identifier, not a declaration.
    "using\t\tin x;",
    "await  using;",
  ];
  assert.deepEqual(topLevelDeclarations(declarations.join("\n")), ["a", "B", "c", "d", "e", "F", "g", "H", "i", "j"]);
  assert.throws(() => topLevelDeclarations("export  const { a } = b;"), /the check reads the name this declaration starts with: export {2}const \{ a \} = b;/);
});

test("the excerpt check reads a top-level declaration whose words a vertical tab, form feed, no-break space or another character TypeScript reads as white space separates", () => {
  // The characters other than space and tab that the TypeScript scanner reads
  // as white space within a line.
  const white = [0x0b, 0x0c, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x200b, 0x202f, 0x205f, 0x3000, 0xfeff];
  for (const c of white) {
    const w = String.fromCodePoint(c);
    const declarations = [
      `export${w}const a = 1;`,
      `export${w}default${w}class B {}`,
      `using${w}c = f();`,
      `await${w}using${w}${w}d = g();`,
      `const enum${w}E { X }`,
      `declare${w}abstract${w}class F {}`,
      // using with no name after it is an identifier, not a declaration.
      `using${w}${w};`,
      `using${w}in x;`,
    ];
    const code = `U+${c.toString(16).toUpperCase().padStart(4, "0")}`;
    assert.deepEqual(topLevelDeclarations(declarations.join("\n")), ["a", "B", "c", "d", "E", "F"], `the check reads the declarations whose words ${code} separates`);
    assert.throws(() => topLevelDeclarations(`export${w}const { a } = b;`), /the check reads the name this declaration starts with: export.const \{ a \} = b;/, `the check fails for a declaration after export${code} that does not start with its name`);
  }
});

test("the excerpt check reads a top-level declaration or import that follows a carriage return, U+2028 or U+2029, each of which TypeScript reads as a line break", () => {
  const breaks = [["CR", "\r"], ["CR LF", "\r\n"], ["U+2028", String.fromCharCode(0x2028)], ["U+2029", String.fromCharCode(0x2029)]];
  for (const [code, br] of breaks) {
    assert.deepEqual(topLevelDeclarations(`const a = 1;${br}const b = 2;`), ["a", "b"], `the check reads the declaration after ${code}`);
    assert.deepEqual(topLevelDeclarations(`export${br}const a = 1;`), ["a"], `the check reads the declaration after export and ${code}`);
    assert.throws(() => topLevelDeclarations(`const a = 1;${br}const { b } = c;${br}`), /the check reads the name this declaration starts with: const \{ b \} = c;$/, `the check fails for a declaration between two ${code} breaks that does not start with its name`);
    assert.deepEqual(importedNames(`const a = 1;${br}import { z } from "zod";${br}`), [{ name: "z", module: "zod" }], `the check reads the import between two ${code} breaks`);
  }
});

test("the excerpt check reads an import whose import keyword a tab, another character TypeScript reads as white space, a brace or * follows, and fails for one whose import keyword ends its line", () => {
  // Space and the characters other than it that the TypeScript scanner reads
  // as white space within a line.
  const white = [0x20, 0x09, 0x0b, 0x0c, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x200b, 0x202f, 0x205f, 0x3000, 0xfeff];
  for (const c of white) {
    const w = String.fromCodePoint(c);
    const code = `U+${c.toString(16).toUpperCase().padStart(4, "0")}`;
    const imports = [
      `import${w}{ z } from "zod";`,
      `import${w}${w}express from "express";`,
      `import${w}* as ns from "os";`,
      `import${w}"./setup";`,
      // import followed by ( is an import call, not a declaration.
      `import${w}("./x");`,
    ];
    assert.deepEqual(importedNames(imports.join("\n")), [
      { name: "z", module: "zod" },
      { name: "express", module: "express" },
      { name: "ns", module: "os" },
    ], `the check reads the imports whose import keyword ${code} follows`);
    assert.throws(() => importedNames(`import${w}{\n  z,\n} from "zod";`), /the check reads this import declaration: import.\{$/, `the check fails for an import after import${code} that is not on one line`);
  }
  const imports = [
    'import{ z } from "zod";',
    'import*as ns from "os";',
    'import"./setup";',
    // import followed by ( or . is an expression, and a name that starts with
    // import is not the import keyword.
    'import("./x");',
    "import.meta.url;",
    "important = 1;",
    "imports.push(x);",
  ];
  assert.deepEqual(importedNames(imports.join("\n")), [
    { name: "z", module: "zod" },
    { name: "ns", module: "os" },
  ]);
  const breaks = [["LF", "\n"], ["CR", "\r"], ["CR LF", "\r\n"], ["U+2028", String.fromCharCode(0x2028)], ["U+2029", String.fromCharCode(0x2029)]];
  for (const [code, br] of breaks) {
    assert.throws(() => importedNames(`import${br}{ z } from "zod";`), /the check reads this import declaration: import$/, `the check fails for an import whose import keyword ${code} follows`);
  }
});

test("the excerpt check reads a top-level declaration or import that does not begin its line, and none inside a block, comment, string or template", () => {
  assert.deepEqual(topLevelDeclarations("const a = 1; const b = 2;"), ["a", "b"], "the check reads the declaration after another statement");
  assert.deepEqual(topLevelDeclarations("/* c */ const a = 1;"), ["a"], "the check reads the declaration after a comment");
  assert.deepEqual(topLevelDeclarations("  const a = 1;\n\tlet b = 2;"), ["a", "b"], "the check reads the declaration after white space");
  assert.deepEqual(topLevelDeclarations("class A {} export class B {}\nfunction c() {} const d = 1;"), ["A", "B", "c", "d"], "the check reads the declaration after the } of a class or function body");
  assert.deepEqual(topLevelDeclarations("const a = 1; /* b */ export  const c = 2; // const d = 3;"), ["a", "c"], "the check reads the declarations of a line and none in its comments");
  assert.deepEqual(
    importedNames('import { a } from "a"; import { z } from "zod";\nimport "./setup"; import * as path from "path"; const b = 1; import os from "os";'),
    [{ name: "a", module: "a" }, { name: "z", module: "zod" }, { name: "path", module: "path" }, { name: "os", module: "os" }],
    "the check reads each import of a line"
  );
  // A declaration inside a block, comment, string or template is not at the
  // top level.
  const inner = ["function f() { const g = 1; }", 'const s = "; const t = 1;";', "const u = `\nconst v = 1;\n`;", "/*\nconst w = 1;\n*/", "const x = { y: 1 }; if (x) { let z = 2; }"];
  assert.deepEqual(topLevelDeclarations(inner.join("\n")), ["f", "s", "u", "x"]);
  assert.deepEqual(importedNames('const s = "; import { a } from \\"a\\";";\n// import { b } from "b";'), []);
  assert.throws(() => topLevelDeclarations("const a = 1; const { b } = c;"), /the check reads the name this declaration starts with: const \{ b \} = c;$/);
  assert.throws(() => importedNames('const a = 1; import { z } from "zod"'), /the check reads this import declaration: import \{ z \} from "zod"$/);
  // A source the reader cannot close may hide a top-level declaration after
  // the bracket it cannot close.
  for (const source of ["function f() {\nconst a = 1;", "const s = `\nconst a = 1;", "/*\nconst a = 1;", 'const a = 1; const s = "b']) {
    assert.throws(() => topLevelDeclarations(source), /the check reads the source to its end with each bracket, comment, string and template closed/);
    assert.throws(() => importedNames(source), /the check reads the source to its end with each bracket, comment, string and template closed/);
  }
});

test("the excerpt check reads the name of an import whose clause separates words with a tab, U+0085, U+200B or another character TypeScript reads as white space", () => {
  // Space and the characters other than it that the TypeScript scanner reads
  // as white space within a line. String.prototype.trim and \s match neither
  // U+0085 nor U+200B.
  const white = [0x20, 0x09, 0x0b, 0x0c, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x200b, 0x202f, 0x205f, 0x3000, 0xfeff];
  for (const c of white) {
    const w = String.fromCodePoint(c);
    const code = `U+${c.toString(16).toUpperCase().padStart(4, "0")}`;
    const imports = [
      `import * as${w}ns from "os";`,
      `import {${w}z${w}} from "zod";`,
      `import { ZodIssue${w}as${w}${w}Issue } from "zod";`,
      `import fs,${w}{${w}type${w}Stats } from "fs";`,
      `import os,${w}*${w}as${w}m from "os";`,
      `import type${w}{ Server } from "http";`,
      `import type${w}Config from "./config";`,
    ];
    assert.deepEqual(importedNames(imports.join("\n")), [
      { name: "ns", module: "os" },
      { name: "z", module: "zod" },
      { name: "Issue", module: "zod" },
      { name: "fs", module: "fs" },
      { name: "Stats", module: "fs" },
      { name: "os", module: "os" },
      { name: "m", module: "os" },
      { name: "Server", module: "http" },
      { name: "Config", module: "./config" },
    ], `the check reads the names of the imports whose clause ${code} separates words in`);
  }
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
const typesWithoutTypeArguments = new Set(["any", "bigint", "boolean", "false", "function", "never", "null", "number", "object", "string", "symbol", "this", "true", "undefined", "unknown", "void"]);

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

// A function that gives, for an index start of source, the index after the
// slash that closes the regular expression literal starting at start, or -1 if
// the line ends first. A backslash escapes the character after it, except a
// line terminator, which ends the line after a backslash too, as a literal
// cannot hold one, and a slash inside a character class does not close the
// literal. Where a literal that has read up to index k closes depends only on k
// and on whether a class is open there, so both answers for every k are found
// in one pass from the end of source, and a line of slashes that never close,
// as in a run of /[, takes linear time.
function regularExpressionEnds(source) {
  const outside = new Int32Array(source.length + 2).fill(-1);
  const inside = new Int32Array(source.length + 2).fill(-1);
  const lineTerminator = (k) => k < source.length && "\n\r\u{2028}\u{2029}".includes(source[k]);
  for (let k = source.length - 1; k >= 0; k--) {
    const c = source[k];
    if (lineTerminator(k) || (c === "\\" && lineTerminator(k + 1))) continue;
    const next = c === "\\" ? k + 2 : k + 1;
    outside[k] = c === "/" ? k + 1 : c === "[" ? inside[next] : outside[next];
    inside[k] = c === "]" ? outside[next] : inside[next];
  }
  return (start) => outside[start + 1];
}

// Whether moduleTokens() reads a slash right after the token as division, as
// it does after a token that ends an operand other than a } that closes an
// object literal, a TypeScript non-null ! or the > that ends type arguments.
// moduleTokens() says which tokens these are, and which of them a slash on a
// later line does not divide after.
function slashDivides(token) {
  return token !== undefined && (token.type === "name" ? !token.beforeExpression : token.type !== "punct" || token.value === ")" || token.value === "]" || token.postfix);
}

// The tokens of a module, read in one pass: names and strings with their escape
// sequences decoded, one token with no value for each number and regular
// expression, one template token where a template ends, and punctuators one
// character each except ++, --, the ... of a spread or rest element and the ${
// that starts a template substitution. A byte order mark, a hashbang line,
// whitespace, comments and the text of a template give no token. Each token
// has in open the number of (, [ and { not yet closed and of template
// substitutions not yet ended after it: a ( counts itself, a ) does not count
// the ( it closes, and a template token does not count the substitution that
// ends before it. A closing bracket with none open leaves the count of
// brackets at 0.
// A slash is read as division after a name other than a keyword in
// keywordsBeforeExpression (a keyword after a . is a property name and one
// after a # is a private name, while one after ... is a keyword, except of,
// which is a keyword only directly inside the parentheses after for or
// for await, after a token a slash divides after or after }, and not as the
// name a const, let or var declares right after the opening parenthesis),
// after ) or ], after a number, string, template or regular expression, and
// after a ++ or -- that follows one of these on the same line (a line break
// before a ++ or --, in a comment or not, makes it a prefix operator). After
// the name right after the keyword let or var, as in let x, only a slash on
// the same line is read as division: that name is not an operand, so in a
// valid module a slash after it comes after a line break, in a comment or
// not, and starts a regular expression. So a
// slash right after the ) of if (...), for (...), for await (...) or
// while (...), or right after a ++ or -- that follows that ) on the same
// line, is read as division, though it starts a regular expression there, and
// so is a slash on a later line than a name a let or var lists after its
// first, as in let x, y.
// Any other slash starts a regular expression if one closes on the same
// line, and is read as a punctuator if not, though in TypeScript one right
// after the ! of a non-null assertion, as in a! / 2, or right after the > that
// ends the type arguments of a type, as in 60 as D<1> / 2, divides, and so
// does one right after a ++ or -- that follows that !, as in a!++ / 2, which
// is read as a prefix operator.
// A ! has nonNull set to true when TypeScript reads it as a non-null
// assertion: when it follows a token that ends an operand on the same line
// and does not start != or !==. A token ends an operand when a slash divides
// after it, other than a ) that closes the parentheses after if, for,
// for await or while, after which a statement starts, as in if (a) !b, when
// it is a } that closes an object literal, when it is a ! with nonNull set
// and when it is a > with endsTypeArguments set. A line break before a !, in a
// comment or not, makes it a logical not. A ) that closes those parentheses
// has statementHead set to true. A { opens an object literal, or a pattern or
// a TypeScript type literal written in the same way, at the start of the text
// when expression is true, as the text is then read as an expression such as
// the value of a property, and right after (, [, a comma, =, ?, ... or ${, and
// the } that closes it has objectLiteral set to true. A { right
// after a ) with statementHead set or after else, do, try or finally opens a
// block, and the } that closes it has block set to true. Any other { is not
// told, as it may open a block, a function or class body or an object
// literal, as after =>, after the ) of function g() or after a :.
// A > has endsTypeArguments set to true when it ends the type arguments of a
// type after an as or satisfies that follows a token that ends an operand on
// the same line, and such an as or satisfies has typeOperator set to true.
// The type starts with the name after it, or with the name after the typeof
// that comes there, as in x as typeof f<number>. It goes on with a name after
// a . that follows one of these names, and with a | or & and the type after
// it when that | or & comes right after one of these names or the > that ends
// their type arguments, as in 60 as A | D<1>, though a || or && ends the type
// and so do |= and &=. Each of these names has typeName set to true. A <
// right after one of them on that name's line, or a < inside type arguments,
// starts type arguments, and a > inside them that is not the > of a => ends
// them. A < that starts <= starts none, though: TypeScript reads <= as a
// comparison, as in a as D <= b. Nor does a < right after the name a type
// starts with after the as, satisfies, | or &, which has typeStart set to
// true, when that name is any, bigint, boolean, false, function, never, null,
// number, object, string, symbol, this, true, undefined, unknown or void:
// TypeScript reads that < as a comparison, as in a as number < b. The type is
// followed through these names and their type arguments only, so the > that
// ends the type arguments of a type after keyof, readonly or unique, or of a
// type in a union after another kind of type, as in 60 as keyof D<1> and
// 60 as A[] | D<1>, is not marked. Nor is the one after an as or satisfies
// that follows the } of a function or a ++ or -- after a non-null !, as in
// function () {} as D<1> and a!++ as D<1>: TypeScript reads that as or
// satisfies as an operator too, but neither token ends an operand here. Each
// token has in typeArguments the number of type arguments open after it, and
// in start and end the index of its first character and the index after its
// last in the text without a byte order mark at its start: a template token
// and a ${ start at the ` or } after which the text of their template starts.
// The array has unclosed set to true when the text ends inside a block
// comment, a string or the text of a template, as a line of a module does when
// one of these continues on the next line.
function moduleTokens(text, { expression = false } = {}) {
  const source = text.replace(/^\u{FEFF}/u, "");
  const tokens = [];
  const regularExpressionEnd = regularExpressionEnds(source);
  let unclosed = false;
  // For each template substitution open at this point, the { opened inside it
  // and not yet closed.
  const substitutions = [];
  // For each (, [ or { open at this point, what it opens: "for" for the ( after
  // for or for await, "head" for the ( after if or while, "object" for a {
  // that opens an object literal, "block" for a { that opens a block, and ""
  // for any other. A for, if, while, else, do, try or finally after a . or # is
  // a property or private name, not the keyword.
  const brackets = [];
  const keywordFor = (token) => token?.raw === "for" && !token.property;
  const isKeyword = (token, ...raw) => token?.type === "name" && !token.property && raw.includes(token.raw);
  const opens = (c, previous) => {
    if (c === "(") return keywordFor(previous) || (previous?.raw === "await" && keywordFor(tokens.at(-2))) ? "for" : isKeyword(previous, "if", "while") ? "head" : "";
    if (c !== "{") return "";
    if (previous === undefined ? expression : previous.type === "punct" && ["(", "[", ",", "=", "?", "...", "${"].includes(previous.value)) return "object";
    return previous?.statementHead === true || isKeyword(previous, "else", "do", "try", "finally") ? "block" : "";
  };
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
    unclosed = true;
    return source.length;
  };
  let i = source.startsWith("#!") ? lineEnd(source, 0) : 0;
  // The index after the last token read.
  let previousEnd = i;
  // Whether a line break, in a comment or not, comes after the last token
  // read and before index i.
  const lineBreakBefore = () => /[\n\r\u{2028}\u{2029}]/u.test(source.slice(previousEnd, i));
  // Whether TypeScript reads the token as the end of an operand.
  const endsOperand = (token) => (slashDivides(token) && token.statementHead !== true) || token?.objectLiteral === true || token?.nonNull === true || token?.endsTypeArguments === true;
  // The number of type arguments open in a TypeScript type.
  let typeArguments = 0;
  while (i < source.length) {
    const start = i;
    const c = source[i];
    const previous = tokens.at(-1);
    // A slash after the name right after let or var starts a regular
    // expression only on a later line. The line break is looked for below,
    // where a token is read next, so that the text between two tokens is
    // searched once.
    const regularExpression = c === "/" && (!slashDivides(previous) || previous.firstDeclared) ? regularExpressionEnd(i) : -1;
    identifier.lastIndex = i;
    const name = identifier.exec(source);
    if (/\s/.test(c)) i++;
    else if (source.startsWith("//", i)) i = lineEnd(source, i);
    else if (source.startsWith("/*", i)) {
      const end = source.indexOf("*/", i + 2);
      if (end < 0) unclosed = true;
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
      if (k >= source.length) unclosed = true;
      tokens.push({ type: "string", value: decodeEscapes(source.slice(i + 1, k)) });
      i = k + 1;
    } else if (regularExpression >= 0 && (!slashDivides(previous) || lineBreakBefore())) {
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
      const forHead = brackets.at(-1) === "for";
      const declared = ["const", "let", "var"].includes(previous?.raw) && tokens.at(-2)?.type === "punct" && tokens.at(-2).value === "(";
      const keyword = forHead && !declared && (slashDivides(previous) || (previous?.type === "punct" && previous.value === "}"));
      const of = name[0] === "of" && !keyword;
      // The name right after the keyword let or var is the first variable the
      // declaration lists, as in let x. A let or var after a . or # is a
      // property or private name, not the keyword. The name after const is
      // not marked: a const declaration has an initializer, so no slash comes
      // right after its name, and in TypeScript the const of as const
      // declares nothing.
      const firstDeclared = ["let", "var"].includes(previous?.raw) && !previous.property;
      // An as or satisfies starts a TypeScript type, which starts with the
      // name after it, or with the name after the typeof there, and goes on
      // with a name after a . that follows one of these names and with the
      // type after a | or & that continues it.
      const typeOperator = !property && ["as", "satisfies"].includes(name[0]) && endsOperand(previous) && !lineBreakBefore();
      const typeStart = previous?.typeOperator === true || previous?.continuesType === true;
      const typeName = (typeStart && name[0] !== "typeof") || (previous?.typeStart === true && previous.raw === "typeof") || (previous?.type === "punct" && previous.value === "." && tokens.at(-2)?.typeName === true);
      tokens.push({ type: "name", raw: name[0], value: decodeEscapes(name[0]), property, firstDeclared, beforeExpression: !property && !of && keywordsBeforeExpression.has(name[0]), typeOperator, typeStart, typeName });
      i += name[0].length;
    } else if (/\d/.test(c) || (c === "." && /\d/.test(source[i + 1] ?? ""))) {
      const number = /\.?\d[\w.]*/y;
      number.lastIndex = i;
      number.exec(source);
      tokens.push({ type: "number" });
      i = number.lastIndex;
    } else if (source.startsWith("++", i) || source.startsWith("--", i)) {
      tokens.push({ type: "punct", value: c + c, postfix: !lineBreakBefore() && slashDivides(previous) });
      i += 2;
    } else if (source.startsWith("...", i)) {
      tokens.push({ type: "punct", value: "..." });
      i += 3;
    } else {
      if (substitutions.length > 0 && c === "{") substitutions[substitutions.length - 1]++;
      if (substitutions.length > 0 && c === "}") substitutions[substitutions.length - 1]--;
      if ("([{".includes(c)) brackets.push(opens(c, previous));
      const opened = ")]}".includes(c) ? brackets.pop() : undefined;
      // A > right after a = with nothing between them is the > of a =>. A <
      // that starts <= compares, and so does a < right after one of
      // typesWithoutTypeArguments when that name is the one a type starts
      // with.
      let endsTypeArguments = false;
      const compares = previous?.typeStart === true && typesWithoutTypeArguments.has(previous.raw);
      if (c === "<" && source[i + 1] !== "=" && !compares && (typeArguments > 0 || (previous?.typeName && !lineBreakBefore()))) typeArguments++;
      else if (c === ">" && typeArguments > 0 && !(previous.type === "punct" && previous.value === "=" && previousEnd === i)) endsTypeArguments = --typeArguments === 0;
      const nonNull = c === "!" && source[i + 1] !== "=" && endsOperand(previous) && !lineBreakBefore();
      const continuesType = (c === "|" || c === "&") && !["|", "&", "="].includes(source[i + 1]) && (previous?.typeName === true || previous?.endsTypeArguments === true);
      const statementHead = c === ")" && (opened === "for" || opened === "head");
      tokens.push({ type: "punct", value: c, nonNull, endsTypeArguments, continuesType, statementHead, objectLiteral: c === "}" && opened === "object", block: c === "}" && opened === "block" });
      i++;
    }
    if (tokens.at(-1) !== previous) {
      tokens.at(-1).open = brackets.length + substitutions.length;
      tokens.at(-1).typeArguments = typeArguments;
      tokens.at(-1).start = start;
      tokens.at(-1).end = i;
      previousEnd = i;
    }
  }
  tokens.unclosed = unclosed;
  return tokens;
}

// The names a module's import declarations take from node:test, in any layout:
// either quote, a default import, renamed names, a name written as a string or
// with Unicode escapes, and line breaks or comments anywhere in the
// declaration. The default export is test(). A namespace import gives "*", as
// it does not show which names the file uses. Import text inside a comment,
// string or template is not a declaration, nor is import text inside a slash
// pair that moduleTokens() reads as a regular expression. moduleTokens() reads
// a slash right after the ) of if (...), for (...), for await (...) or
// while (...), right after a ++ or -- that follows that ) on the same line,
// or on a later line than a name a let or var lists after its first, as in
// let x, y, as division, so import text inside a regular expression there is
// read as a declaration.
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

// The method names of the calls in a module that set or enable Express's trust
// proxy setting on any object: set("trust proxy", ...) or enable("trust
// proxy"), with either quote, escape sequences in the setting's name, and line
// breaks or comments anywhere in the call. A call inside a comment, string or
// template is not a call, nor is a call of a function named set or enable that
// is not a method. The reader does not handle a setting name written as a
// template or held in a variable, as in app.set(setting, 1), a method named
// with brackets, as in app["set"](...), or a method called through call() or
// apply(), as in app.set.call(app, "trust proxy", 1).
function trustProxyCalls(text) {
  const tokens = moduleTokens(text);
  const is = (token, type, value) => token?.type === type && (value === undefined || token.value === value);
  const calls = [];
  for (let i = 0; i < tokens.length; i++) {
    const method = tokens[i + 1];
    if (is(tokens[i], "punct", ".") && (is(method, "name", "set") || is(method, "name", "enable")) && is(tokens[i + 2], "punct", "(") && is(tokens[i + 3], "string", "trust proxy")) {
      calls.push(method.value);
    }
  }
  return calls;
}

test("the trust proxy reader finds set and enable calls in any layout, and none in a comment, string or template, for another setting or of a function that is not a method", () => {
  assert.deepEqual(trustProxyCalls('app.set("trust proxy", "10.0.0.2");\n'), ["set"]);
  assert.deepEqual(trustProxyCalls("app.set('trust proxy', 'uniquelocal');\n"), ["set"]);
  assert.deepEqual(trustProxyCalls('app.enable("trust proxy");\n'), ["enable"]);
  assert.deepEqual(trustProxyCalls('server\n  .set /* hop */ (\n    "trust\\u0020proxy",\n    1,\n  );\n'), ["set"]);
  assert.deepEqual(trustProxyCalls('// app.set("trust proxy", "10.0.0.2")\n/* app.enable("trust proxy") */\n'), []);
  assert.deepEqual(trustProxyCalls('const a = \'app.set("trust proxy", 1)\';\nconst b = `app.enable("trust proxy")`;\n'), []);
  assert.deepEqual(trustProxyCalls('app.set("x-powered-by", false);\napp.disable("trust proxy");\napp.get("trust proxy");\n'), []);
  assert.deepEqual(trustProxyCalls('set("trust proxy", 1);\nenable("trust proxy");\n'), []);
  // handler.ts names app.set("trust proxy", "10.0.0.2") in a comment, and a
  // call of that form added after its app.disable("x-powered-by") is read.
  const handler = readText("examples/validated-task-handler/handler.ts");
  assert.ok(handler.includes('app.set("trust proxy", "10.0.0.2")'), "handler.ts names the setting step 1 shows in a comment");
  assert.ok(handler.includes('app.disable("x-powered-by");\n'), "handler.ts disables the X-Powered-By header");
  for (const setting of ['"10.0.0.2"', '"uniquelocal"']) {
    const added = handler.replace('app.disable("x-powered-by");\n', `app.disable("x-powered-by");\napp.set("trust proxy", ${setting});\n`);
    assert.equal(trustProxyCalls(added).length, trustProxyCalls(handler).length + 1, `app.set("trust proxy", ${setting}) added to handler.ts is read as a call`);
  }
});

// The path and text of each test file.
function testFiles() {
  return readdirSync(join(root, "test"))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => ({ path: `test/${name}`, text: readText(`test/${name}`) }));
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

test("the node:test import reader reads a slash after export default as a regular expression, and a slash after a postfix ++ or --, a property named default, the ) of if (...), for (...), for await (...) or while (...), or a ++ or -- that follows that ) on the same line as division", () => {
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
  assert.deepEqual(namesImportedFromNodeTest('for await (const x of a) /import { describe } from "node:test"/.test(s);\n'), ["describe"]);
  // A ++ or -- right after such a ) on the same line is a prefix operator,
  // but the reader reads it as a postfix one and so the slash after it as
  // division too. After a line break it reads it as a prefix operator.
  assert.deepEqual(namesImportedFromNodeTest('if (x) ++/import { describe } from "node:test"/.lastIndex;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('for (;;) --/import { describe } from "node:test"/.lastIndex;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('for await (const x of a) ++/import { describe } from "node:test"/.lastIndex;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('while (x) /* note */ --/import { describe } from "node:test"/.lastIndex;\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('if (x)\n++/import { describe } from "node:test"/.lastIndex;\n'), []);
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

test("the node:test import reader reads the of of a for...of loop as the keyword when the left side of the loop holds a template substitution inside brackets, and when a line break comes before the of", () => {
  // Read as a variable, the of would make the slash after it divide, and the
  // backtick after that slash would open a template that hides the
  // declaration.
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  for (const before of [
    "for (o[`${k}`] of /`/g.exec(s)) f(o);\n",
    "for (x\nof /`/g.exec(s)) f(x);\n",
  ]) {
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

test("the node:test import reader reads a slash on the line after a let or var that declares one name without an initializer as a regular expression, and a slash after an initializer as division", () => {
  // A line break ends let x before the slash, which starts a regular
  // expression. Read as division, the slash would leave the backtick after it
  // to open a template that hides the declaration.
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  for (const before of [
    "let x\n/`/g.exec(s);\n",
    "var x\n/`/g.exec(s);\n",
    "let of\n/`/g.exec(s);\n",
    "var of\n/`/g.exec(s);\n",
    "export let x\n/`/g.exec(s);\n",
    "let \\u0078\r\n/`/g.exec(s);\n",
    "let x // note\n/`/g.exec(s);\n",
    "var x /* note\n */ /`/g.exec(s);\n",
    "if (a) { let x\n/`/g.exec(s); }\n",
    "function f() { var x\n/`/g.exec(s); }\n",
    "let x\r/`/g.exec(s);\n",
    "let x\u{2028}/`/g.exec(s);\n",
    "var x\u{2029}/`/g.exec(s);\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
  // Read as the start of a regular expression, the slash after an initializer
  // would close at the slash in the template, and the backtick after it would
  // open a template that hides the declaration.
  for (const before of ["let x = a\n/ 2, t = `/`;\n", "var x = a\n/ 2, t = `/`;\n", "let x = of\n/ 2, t = `/`;\n"]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
  // A slash after a name the declaration lists after its first starts a
  // regular expression too, but the reader reads it as division, so it reads
  // the import text inside as a declaration.
  assert.deepEqual(namesImportedFromNodeTest('let x, y\n/import { describe } from "node:test"/.test(s);\n'), ["describe"]);
  assert.deepEqual(namesImportedFromNodeTest('var x = 1, y\n/import { describe } from "node:test"/.test(s);\n'), ["describe"]);
});

test("the node:test import reader reads the of after the name a let or var declares in the parentheses after for or for await as the for...of keyword, and a slash on the same line as the name after let or var, or on the line after a name that follows as const or a property named let or var, as division", () => {
  const declaration = 'import { after } from "node:test";\nconst u = ``;\n';
  // The of after the name a let or var declares there is the keyword, as it is
  // after any other name, and the slash after it starts a regular expression.
  for (const before of [
    "for (let x of /`/g.exec(s)) f(x);\n",
    "for (var x of /`/g.exec(s)) f(x);\n",
    "for await (let x of /`/g.exec(s)) f(x);\n",
  ]) {
    assert.deepEqual(namesImportedFromNodeTest(before + declaration), ["after"], JSON.stringify(before));
  }
  // Read as the start of a regular expression, each slash below would close at
  // the slash in the template, and the backtick after it would open a template
  // that hides the declaration. No module has a slash on the same line as the
  // name right after let or var. The reader does not check that, and reads one
  // as division, as it does after any other name.
  assert.deepEqual(namesImportedFromNodeTest("let x / 2, t = `/`;\n" + declaration), ["after"]);
  assert.deepEqual(namesImportedFromNodeTest("var x /* note */ / 2, t = `/`;\n" + declaration), ["after"]);
  // The const of a TypeScript as const declares nothing, and a let or var
  // after a . is a property name, so the name on the next line is an operand
  // and the slash on the line after it divides.
  for (const before of [
    "const a = [1] as const\nb\n/ 2, t = `/`;\n",
    "y = o.let\nx\n/ 2, t = `/`;\n",
    "y = o?.var\nx\n/ 2, t = `/`;\n",
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

test("moduleTokens() reads a long run of /[ in linear time", () => {
  // Each slash of the run starts a regular expression whose character class
  // never closes. Scanning from each one to the end of the line took more than
  // three seconds on 40,000 characters and grew with the square of the length.
  const start = performance.now();
  const tokens = moduleTokens("/[".repeat(20000));
  const ms = performance.now() - start;
  assert.equal(tokens.length, 40000, "each character is one punctuator");
  assert.ok(ms < 1000, `reading 40,000 characters took ${Math.round(ms)} ms`);
});

test("moduleTokens() marks a TypeScript non-null assertion and the > that ends the type arguments of a type after as or satisfies, after the } of an object literal, of a later type in a union or intersection and of a typeof query too, and not a ! or > that is an operator, as a ! right after the ) of if (...) is, and reads a slash after any of them as the start of a regular expression", () => {
  // The last ! or > before the regular expression the text holds.
  const beforeRegularExpression = (text, options) => {
    const tokens = moduleTokens(text, options);
    const regex = tokens.findIndex((token) => token.type === "regex");
    assert.ok(regex > 0, `${JSON.stringify(text)} has a regular expression after a token`);
    return tokens.slice(0, regex).findLast((token) => token.type === "punct" && ["!", ">"].includes(token.value));
  };
  for (const text of ["a! / b / c", "f(a)[0]! / b / c", "a!! / b / c", "x as A<1>! / b / c"]) {
    assert.equal(beforeRegularExpression(text).nonNull, true, JSON.stringify(text));
  }
  // The } of an object literal ends an operand: one right after (, [, a
  // comma, =, ?, ... or ${, or at the start of a text read as an expression.
  for (const [text, options] of [["x = {}! / b / c"], ["f(a, [{}!! / b / c])"], ["{}! / b / c", { expression: true }], ["{ a: 1 }! / b / c", { expression: true }]]) {
    assert.equal(beforeRegularExpression(text, options).nonNull, true, JSON.stringify(text));
  }
  for (const [text, options] of [["x = {} as A<1> / b / c"], ["{} satisfies A<1> / b / c", { expression: true }], ["x as A | B<1> / b / c"], ["x as A<1> & B<1> / b / c"], ["x as A | B | C<1> / b / c"], ["x as typeof f<1> / b / c"], ["x as typeof ns.f<1> / b / c"], ["x as typeof number<1> / b / c"], ["x as A | typeof f<1> / b / c"]]) {
    assert.equal(beforeRegularExpression(text, options).endsTypeArguments, true, JSON.stringify(text));
  }
  // Type arguments follow a name after a . even when that name, or the one
  // before the ., is a name such as number, and a < right after such a name
  // that follows an as inside type arguments compares, as does a < that
  // starts <= inside them, so the next > ends them.
  for (const text of ["x as A<1> / b / c", "x satisfies ns.A<B<1>> / b / c", "x as A<() => void> / b / c", "a! as A<1> / b / c", "x as number.A<1> / b / c", "x as ns.number<1> / b / c", "x as A<{ [a as number < b]: 1 }> / b / c", "x as A<{ [a <= b]: 1 }> / b / c"]) {
    assert.equal(beforeRegularExpression(text).endsTypeArguments, true, JSON.stringify(text));
  }
  // A ! after a line break, after no operand or that starts != or !==, a >
  // that ends no type arguments, and the > after a < that follows a line
  // break, the name after an as with a line break before it or a name such as
  // number right after an as or satisfies, are operators. So is the > of the
  // last two texts: the <= right after the name of a type before it compares
  // and starts no type arguments.
  for (const text of ["a\n!/b/.test(c)", "a /*\n*/ !/b/.test(c)", "x ? !/b/.test(c) : d", "a != /b/.test(c)", "a !== /b/.test(c)", "a < b > /b/.test(c)", "x as A > /b/.test(c)", "x as A<1> > /b/.test(c)", "x as A\n<1> /b/.test(c)", "x\nas A<1> /b/.test(c)", "x as number < b > /b/.test(c)", "x satisfies void < b > /b/.test(c)", "x as D <= b > /b/.test(c)", "x satisfies ns.D <= b > /b/.test(c)"]) {
    const token = beforeRegularExpression(text);
    assert.ok(!token.nonNull && !token.endsTypeArguments, JSON.stringify(text));
  }
  // A ! right after the ) of if (...), for (...), for await (...) or
  // while (...) negates, as a statement starts there, and so does one right
  // after the } of a block, as at the start of a module. A < right after
  // number compares when number starts a later type in a union, and a || or
  // && ends the type, so the > after the < is an operator in the last three.
  for (const text of ["if (a) !/b/.test(c)", "while (a) !!/b/.test(c)", "for (;0;) !/b/.test(c)", "for await (const x of y) !/b/.test(c)", "do ; while (a) !/b/.test(c)", "if (a) {} !/b/.test(c)", "{}! /b/.test(c)", "x as A | number < b > /b/.test(c)", "x as A || b < c > /b/.test(c)", "x as A && b < c > /b/.test(c)"]) {
    const token = beforeRegularExpression(text);
    assert.ok(!token.nonNull && !token.endsTypeArguments, JSON.stringify(text));
  }
});

test("regularExpressionEnds() reads past an escaped slash and a slash in a character class, and gives -1 when the line ends first, after a backslash too", () => {
  assert.equal(regularExpressionEnds("x = /a/g")(4), 7);
  assert.equal(regularExpressionEnds("/a\\/b/")(0), 6);
  assert.equal(regularExpressionEnds("/[/]/")(0), 5);
  assert.equal(regularExpressionEnds("/a")(0), -1);
  assert.equal(regularExpressionEnds("/a\\")(0), -1);
  // A regular expression literal holds no line terminator, even escaped.
  for (const lineBreak of ["\n", "\r", "\r\n", "\u{2028}", "\u{2029}"]) {
    for (const source of ["/a" + lineBreak + "b/", "/a\\" + lineBreak + "b/", "/[a\\" + lineBreak + "]/"]) {
      assert.equal(regularExpressionEnds(source)(0), -1, JSON.stringify(source));
    }
  }
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
    `the npm test sentence says Node.js ${major}.${minor} is a tested floor, not a measured minimum`
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
    `the npm test sentence says why releases before ${major}.${lowest} cannot run the tests`
  );
  assert.ok(
    sentence.includes(`releases ${major}.${lowest} to ${major}.${minor - 1} are untested`),
    "the npm test sentence says which releases below the floor are untested, leaving out releases that cannot run the tests"
  );
}

test("docs/validated-task-handler.md says the Node.js version for npm test is the lowest release tested, not a measured minimum", () => {
  // npm test cannot run on a release without node --test or without a name the
  // test files import from node:test, and passes on 18.17. No release between
  // the two has been run, so the floor may be higher than the tests need.
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const sentence = handlerPageLines.find((l) => l.includes("`npm test` from the repository root"));
  assert.ok(sentence, "docs/validated-task-handler.md names the command that runs the tests");
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
// table and the number of payloads the command sends. The version the list was
// read from is on docs/testing-against-real-attacks.md.
function checkAttackSection(section, payloads) {
  const number = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];
  const command = codeBlocks(section).find((b) => b.body.includes("hackmyagent attack "));
  assert.ok(command, "the section has a hackmyagent attack command");
  assert.match(command.body, /--category a2a-attack\b/, "the command runs the a2a-attack category");
  assert.doesNotMatch(command.body, /--intensity\b/, "the command runs at the default intensity, active");
  const rows = section.split("\n").filter((l) => l.startsWith("|")).slice(2);
  const cells = rows.map((row) => row.split("|").slice(1, -1).map((cell) => cell.trim()));
  assert.deepEqual(cells, payloads, "the table lists each payload of the a2a-attack category with its intensity and description");
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
  assert.match(attackPage, /`a2a-attack` category of hackmyagent 0\.33\.2\b/, "docs/testing-against-real-attacks.md names the scanner version the table was read from");
  assert.ok(attackSection(readme).includes("[docs/testing-against-real-attacks.md](docs/testing-against-real-attacks.md) names the release the table was read from"), "the attack section links the page that names the scanner version");
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

test("docs/testing-against-real-attacks.md and the handler's header name the tests on the linked attack page, and neither they nor the README name an attack that the page and the scanner's category both lack", () => {
  const handler = readText("examples/validated-task-handler/handler.ts");
  const header = handler.match(/^\/\*\*[\s\S]*?\*\//)?.[0] ?? "";
  const link = "https://agentpwn.com/attacks/a2a-attack";
  const sentence = attackPage.split("\n").find((l) => l.includes(`](${link})`));
  assert.ok(sentence, "docs/testing-against-real-attacks.md links the attack page");
  assert.ok(header.includes(link), "the handler's header links the attack page");
  // A comment wraps, so join its lines before looking for a name in it.
  const flat = (text) => text.replace(/[\s*]+/g, " ").toLowerCase();
  for (const page of a2aAttackPages) {
    assert.ok(sentence.includes(page), `docs/testing-against-real-attacks.md names the ${page} test`);
    assert.ok(flat(header).includes(page.toLowerCase()), `the handler's header names the ${page} test`);
  }
  assert.doesNotMatch(flat(readme), unlistedAttacks, "README.md names an attack the page and the category lack");
  for (const page of docsPages) {
    assert.doesNotMatch(flat(readText(page)), unlistedAttacks, `${page} names an attack the page and the category lack`);
  }
  assert.doesNotMatch(flat(handler), unlistedAttacks, "handler.ts names an attack the page and the category lack");
});

test("the license section matches the LICENSE file", () => {
  const license = readText("LICENSE");
  assert.match(license, /Apache License\s+Version 2\.0/);
  const section = readme.split(/^## License$/m)[1] ?? "";
  assert.match(section, /Apache 2\.0/, "README names the Apache 2.0 license");
  assert.doesNotMatch(section, /\bMIT\b/, "README does not name a different license");
});
