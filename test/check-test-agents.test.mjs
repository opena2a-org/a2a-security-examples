// Test agent table checks. Run with: node --test test/check-test-agents.test.mjs
// (npm test at the repository root runs every test file). These tests use no
// network; npm run check:test-agents fetches the live cards and home pages.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkAgent, maxBodyBytes, maxTitleAttributes, maxTitleText, siteName, testAgents } from "../scripts/check-test-agents.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(join(root, "README.md"), "utf8");

// The title element of each test agent's home page. Checked 2026-10-11.
const homePageTitles = {
  "devpipeline-ai.dev": "DevPipeline AI — Internal Developer Portal",
  "databridge-labs.dev": "DataBridge Labs — Internal Developer Portal",
  "finops-agent.dev": "FinOps Agent — Internal Developer Portal",
  "cloudops-agent.io": "CloudOps Agent — Cloud Operations Console",
  "bankingops-ai.dev": "BankingOps AI — Internal Developer Portal",
  "clinicalops-agent.io": "ClinicalOps Agent — Internal Developer Portal",
  "compliance-agent-platform.dev": "Compliance Agent Platform — Internal Developer Portal",
  "defenseops-ai.dev": "DefenseOps AI — Internal Developer Portal",
  "govtech-agent.io": "GovTech Agent — Internal Developer Portal",
  "hrops-ai-platform.io": "HROps AI Platform — Internal Developer Portal",
  "infraops-platform.io": "InfraOps Platform — Internal Developer Portal",
  "legalhq-ai.io": "LegalHQ AI — Internal Developer Portal",
  "medtech-platform.dev": "MedTech Platform — Internal Developer Portal",
  "payroll-ai-platform.io": "Payroll AI Platform — Internal Developer Portal",
  "rxops-ai.dev": "RxOps AI — Internal Developer Portal",
  "salesops-agent.dev": "SalesOps Agent — Internal Developer Portal",
  "tradingdesk-labs.io": "TradingDesk Labs — Internal Developer Portal",
  "voiceops-platform.io": "VoiceOps Platform — Internal Developer Portal",
  "mcp-servers.org": "MCP Server Registry",
  "agent-docs.io": "Agent Documentation Hub",
  "llm-tools-guide.dev": "LLM Tools Guide",
  "ai-sdk-reference.dev": "AI SDK Reference",
};

// The hosts whose /.well-known/agent.json returned no JSON card. Checked 2026-10-11.
const hostsWithoutCard = ["cloudops-agent.io"];

// A fetch that answers from a map of URL to status, content type and body, and
// fails for any other URL.
function stubFetch(responses) {
  return async (/** @type {string} */ url) => {
    const res = responses[url];
    if (!res) throw new Error(`unexpected fetch of ${url}`);
    return new Response(res.body, { status: res.status, headers: { "content-type": res.type } });
  };
}

const card = { status: 200, type: "application/json; charset=utf-8", body: '{"name":"probe Agent"}' };
const home = (title) => ({ status: 200, type: "text/html; charset=utf-8", body: `<html><head><title>${title}</title></head></html>` });

// The problems reported for a home page with no title, when the check read all
// of it, when it read only the first 256 KB, and when a title tag lies outside
// the bounds of the title the check reads or is not closed by </title>.
const noTitle = "the home page has no title";
const noTitleInRead = "the home page has no title in its first 256 KB, which is all the check reads";
const noTitleInBounds =
  "the home page has no title the check can read, which needs a title tag with at most 256 characters of attributes and at most 1024 characters of text without a <, closed by </title>";
const noTitleInBoundsOrRead = `${noTitleInBounds}, ending in its first 256 KB`;

test("the test agent check reads every row of the README's test agent table", () => {
  const section = readme.split(/^### Test agents$/m)[1]?.split(/^#{1,3} /m)[0] ?? "";
  const rows = section.split("\n").filter((line) => line.startsWith("| ") && !line.startsWith("| Agent |"));
  const agents = testAgents(readme);
  assert.ok(agents.length > 0, "the README lists test agents");
  assert.equal(agents.length, rows.length, "every row of the table gives a name and an https link to a host");
  assert.deepEqual(agents.find((agent) => agent.host === "cloudops-agent.io"), { name: "CloudOps Agent", host: "cloudops-agent.io" });
});

test("every name in the test agent table is the name its home page gives", () => {
  const agents = testAgents(readme);
  assert.deepEqual(agents.map((agent) => agent.host).sort(), Object.keys(homePageTitles).sort(), "homePageTitles holds a title for each listed host");
  for (const { name, host } of agents) {
    assert.equal(name, siteName(homePageTitles[host]), `the README calls ${host} "${name}", and its home page calls it "${siteName(homePageTitles[host])}"`);
  }
});

test("the README says each test agent exposes an agent card except the agents recorded as serving none", () => {
  const names = testAgents(readme).filter((agent) => hostsWithoutCard.includes(agent.host)).map((agent) => agent.name);
  assert.equal(names.length, hostsWithoutCard.length, "the table lists every host recorded as serving no card");
  const agents = names.length > 0 ? `Each test agent except ${names.join(" and ")}` : "Each test agent";
  const claim = `${agents} exposes a standard A2A agent card at \`/.well-known/agent.json\``;
  assert.ok(readme.includes(claim), `README says: ${claim}`);
});

test("the site name is the title before an em dash, with HTML entities decoded", () => {
  assert.equal(siteName("HROps AI Platform — Internal Developer Portal"), "HROps AI Platform");
  assert.equal(siteName("MCP Server Registry"), "MCP Server Registry");
  assert.equal(siteName(" Defense &amp; Intel — Portal"), "Defense & Intel");
});

test("the test agent check passes an agent with a JSON card and a home page that gives the table's name", async () => {
  const fetchImpl = stubFetch({
    "https://probe.dev/.well-known/agent.json": card,
    "https://probe.dev/": home("Probe AI — Internal Developer Portal"),
  });
  assert.deepEqual(await checkAgent({ name: "Probe AI", host: "probe.dev" }, fetchImpl), []);
});

test("the test agent check reports a card path that returns an HTML 404", async () => {
  const fetchImpl = stubFetch({
    "https://cloudops-agent.io/.well-known/agent.json": { status: 404, type: "text/html; charset=utf-8", body: "<html>Not found</html>" },
    "https://cloudops-agent.io/": home("CloudOps Agent — Cloud Operations Console"),
  });
  assert.deepEqual(await checkAgent({ name: "CloudOps Agent", host: "cloudops-agent.io" }, fetchImpl), [
    "/.well-known/agent.json returned 404 text/html; charset=utf-8",
  ]);
});

test("the test agent check reports a card that is not a JSON object and a home page that gives another name", async () => {
  const cases = [
    [{ ...card, type: "text/html" }, "/.well-known/agent.json returned text/html, not JSON"],
    [{ ...card, body: "<html>" }, "/.well-known/agent.json is not valid JSON"],
    [{ ...card, body: "[]" }, "/.well-known/agent.json is not a JSON object"],
    [{ ...card, body: "null" }, "/.well-known/agent.json is not a JSON object"],
  ];
  for (const [cardResponse, problem] of cases) {
    const fetchImpl = stubFetch({
      "https://compliance-agent-platform.dev/.well-known/agent.json": cardResponse,
      "https://compliance-agent-platform.dev/": home("Compliance Agent Platform — Internal Developer Portal"),
    });
    assert.deepEqual(await checkAgent({ name: "Compliance Engine", host: "compliance-agent-platform.dev" }, fetchImpl), [
      problem,
      'the home page calls the agent "Compliance Agent Platform", not "Compliance Engine"',
    ]);
  }
});

test("the test agent check reports a host it cannot reach and a home page without a title", async () => {
  const unreachable = async () => {
    throw new Error("getaddrinfo ENOTFOUND gone.dev");
  };
  assert.deepEqual(await checkAgent({ name: "Gone", host: "gone.dev" }, unreachable), [
    "/.well-known/agent.json could not be fetched: getaddrinfo ENOTFOUND gone.dev",
    "the home page could not be fetched: getaddrinfo ENOTFOUND gone.dev",
  ]);
  const fetchImpl = stubFetch({
    "https://probe.dev/.well-known/agent.json": card,
    "https://probe.dev/": { status: 200, type: "text/html", body: "<html></html>" },
  });
  assert.deepEqual(await checkAgent({ name: "Probe AI", host: "probe.dev" }, fetchImpl), [noTitle]);
});

test("the test agent check names the bounds it read when it finds no title in a page that may hold one past them", async () => {
  const check = (body, name = "Probe AI") =>
    checkAgent(
      { name, host: "probe.dev" },
      stubFetch({
        "https://probe.dev/.well-known/agent.json": card,
        "https://probe.dev/": { status: 200, type: "text/html", body },
      })
    );
  assert.equal(maxTitleAttributes, 256);
  assert.equal(maxTitleText, 1024);
  const longest = "a".repeat(maxTitleText);
  const attributes = (length) => ` data-x="${"b".repeat(length - 10)}"`;
  assert.equal(attributes(maxTitleAttributes).length, maxTitleAttributes);
  assert.deepEqual(await check(`<title>${longest}</title>`, longest), []);
  assert.deepEqual(await check(`<title${attributes(maxTitleAttributes)}>Probe AI</title>`), []);
  assert.deepEqual(await check(" ".repeat(300 * 1024) + "<title>Probe AI</title>"), [noTitleInRead]);
  assert.deepEqual(await check(`<title>${longest}a</title>`, longest), [noTitleInBounds]);
  assert.deepEqual(await check(`<title${attributes(maxTitleAttributes + 1)}>Probe AI</title>`), [noTitleInBounds]);
  assert.deepEqual(await check("<title>Probe <AI></title>"), [noTitleInBounds]);
  assert.deepEqual(await check("<TITLE>Probe AI" + " ".repeat(maxBodyBytes)), [noTitleInBoundsOrRead]);
});

test("the test agent check says a title must be closed by </title> when a short title within the bounds is not, and not when the part it read holds no title tag", async () => {
  const check = (body) =>
    checkAgent(
      { name: "Probe AI", host: "probe.dev" },
      stubFetch({
        "https://probe.dev/.well-known/agent.json": card,
        "https://probe.dev/": { status: 200, type: "text/html", body },
      })
    );
  assert.ok(noTitleInBounds.endsWith(", closed by </title>"));
  assert.deepEqual(await check("<title>Probe AI"), [noTitleInBounds]);
  assert.deepEqual(await check("<title>Probe AI</title >"), [noTitleInBounds]);
  assert.deepEqual(await check("<title>Probe AI</TITLE>"), []);
  // A page that runs past the part the check reads and holds no "<title" in
  // that part has no title tag a closing tag could be missing from, so it is
  // told how much the check reads and nothing about the closing tag.
  assert.ok(!noTitleInRead.includes("</title>"));
  assert.deepEqual(await check(" ".repeat(maxBodyBytes + 1)), [noTitleInRead]);
});

test("the test agent check reports no title, not the title bounds, for a page that holds <title only outside a title tag", async () => {
  const check = (body) =>
    checkAgent(
      { name: "Probe AI", host: "probe.dev" },
      stubFetch({
        "https://probe.dev/.well-known/agent.json": card,
        "https://probe.dev/": { status: 200, type: "text/html", body },
      })
    );
  // An element whose name only begins with title, and a title tag in a comment.
  assert.deepEqual(await check("<titlebar>x</titlebar>"), [noTitle]);
  assert.deepEqual(await check("<title-bar>x</title-bar>"), [noTitle]);
  assert.deepEqual(await check("<!-- <title> --><p>x</p>"), [noTitle]);
  assert.deepEqual(await check("<!----><!-- <TITLE lang='en'>Probe <AI></title> --><p>x</p>"), [noTitle]);
  // A comment the page does not close runs to its end.
  assert.deepEqual(await check("<p>x</p><!-- <title>Probe <AI></title>"), [noTitle]);
  assert.deepEqual(await check("<title"), [noTitle]);
  assert.deepEqual(await check("<titlebar>x</titlebar>" + " ".repeat(maxBodyBytes)), [noTitleInRead]);
  assert.deepEqual(await check("<!-- <title> -->" + " ".repeat(maxBodyBytes)), [noTitleInRead]);
  // A title tag ends its name with white space, / or >, and one outside a comment still names the bounds.
  for (const tag of ["<title>", "<TITLE lang='en'>", "<title\n>", "<title\tlang='en'>", "<title/>"]) {
    assert.deepEqual(await check(`${tag}Probe <AI></title>`), [noTitleInBounds], `the tag ${JSON.stringify(tag)}`);
  }
  assert.deepEqual(await check("<!-- a --><title>Probe <AI></title>"), [noTitleInBounds]);
  assert.deepEqual(await check("<!--><title>Probe <AI></title>"), [noTitleInBounds]);
  assert.deepEqual(await check("<!---><title>Probe <AI></title>"), [noTitleInBounds]);
  assert.deepEqual(await check("<title>Probe <!-- AI</title>"), [noTitleInBounds]);
  assert.deepEqual(await check("<!-- <title> --><title>Probe AI</title>"), []);
});

test("the test agent check reads a home page made of repeated <title with no > in linear time", async () => {
  // A title pattern with unbounded quantifiers took more than ten seconds on
  // the first of these 400 KB pages and grew with the square of the length.
  // Nothing ends the name of that page's one tag, so it holds no title tag. The
  // second page starts a title tag every seven characters, and the third opens
  // a comment every four and closes none.
  const pages = [
    ["<title", noTitleInRead],
    ["<title ", noTitleInBoundsOrRead],
    ["<!--", noTitleInRead],
  ];
  for (const [unit, problem] of pages) {
    const repeats = Math.ceil(400000 / unit.length);
    const fetchImpl = stubFetch({
      "https://probe.dev/.well-known/agent.json": card,
      "https://probe.dev/": { status: 200, type: "text/html", body: unit.repeat(repeats) },
    });
    const start = performance.now();
    assert.deepEqual(await checkAgent({ name: "Probe AI", host: "probe.dev" }, fetchImpl), [problem]);
    const ms = performance.now() - start;
    assert.ok(ms < 1000, `checking ${repeats} repeats of ${JSON.stringify(unit)} took ${Math.round(ms)} ms`);
  }
});

test("the test agent check reads a title that ends within the first 256 KB of the home page, and none that ends after them", async () => {
  const title = "<title>Probe AI</title>";
  const check = (body) =>
    checkAgent(
      { name: "Probe AI", host: "probe.dev" },
      stubFetch({
        "https://probe.dev/.well-known/agent.json": card,
        "https://probe.dev/": { status: 200, type: "text/html", body },
      })
    );
  assert.equal(maxBodyBytes, 256 * 1024);
  assert.deepEqual(await check(" ".repeat(maxBodyBytes - title.length) + title), []);
  assert.deepEqual(await check(" ".repeat(maxBodyBytes - title.length + 1) + title), [noTitleInBoundsOrRead]);
});

test("the test agent check stops reading a response body after its first 256 KB", async () => {
  // A 4 MB body of spaces served in 64 KB chunks, counting the bytes served.
  const chunkBytes = 64 * 1024;
  const totalBytes = 16 * maxBodyBytes;
  let served = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      if (served === totalBytes) return controller.close();
      served += chunkBytes;
      controller.enqueue(new Uint8Array(chunkBytes).fill(32));
    },
    cancel() {
      cancelled = true;
    },
  });
  const fetchImpl = stubFetch({
    "https://probe.dev/.well-known/agent.json": card,
    "https://probe.dev/": { status: 200, type: "text/html", body },
  });
  assert.deepEqual(await checkAgent({ name: "Probe AI", host: "probe.dev" }, fetchImpl), [noTitleInRead]);
  assert.ok(cancelled, "the check cancels the rest of the body");
  // One chunk past the limit shows the body runs on, and the stream holds one more ready.
  assert.ok(served <= maxBodyBytes + 2 * chunkBytes, `the check took ${served} bytes of a ${totalBytes} byte body`);
});

test("the test agent check reports a card longer than 256 KB as too long, not as invalid JSON", async () => {
  const fetchImpl = stubFetch({
    "https://probe.dev/.well-known/agent.json": { ...card, body: JSON.stringify({ name: "probe Agent", description: "a".repeat(maxBodyBytes) }) },
    "https://probe.dev/": home("Probe AI — Internal Developer Portal"),
  });
  assert.deepEqual(await checkAgent({ name: "Probe AI", host: "probe.dev" }, fetchImpl), ["/.well-known/agent.json is longer than 256 KB"]);
});
