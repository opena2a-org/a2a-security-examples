// Fetches the agent card and the home page of every test agent the README
// lists, and reports each agent that serves no JSON card at
// /.well-known/agent.json or whose home page calls it by another name than the
// table does. Run with: npm run check:test-agents (exits 1 if any agent fails).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const timeoutMs = 15000;

// The name and host of each row of the README's test agent table.
export function testAgents(readme) {
  const section = readme.split(/^### Test agents$/m)[1]?.split(/^#{1,3} /m)[0] ?? "";
  const row = /^\| ([^|]+?) \| \[([^\]]+)\]\(https:\/\/([^/)]+)\/?\) \| [^|]+ \|$/gm;
  return [...section.matchAll(row)].map((m) => ({ name: m[1], host: m[3] }));
}

// The name a home page gives itself: the text of its title element before an
// em dash, as in "DevPipeline AI — Internal Developer Portal".
export function siteName(title) {
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" };
  const text = title.replace(/&(amp|lt|gt|quot|#39);/g, (_, entity) => entities[entity]);
  return text.split(" — ")[0].trim();
}

async function get(fetchImpl, url) {
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, type: res.headers.get("content-type") ?? "", body: await res.text() };
  } catch (err) {
    return { error: err?.message ?? String(err) };
  }
}

// The problems found with one agent: an empty list when its card is a JSON
// object and its home page title gives the name the table gives.
export async function checkAgent({ name, host }, fetchImpl = fetch) {
  const problems = [];
  const card = await get(fetchImpl, `https://${host}/.well-known/agent.json`);
  if (card.error) {
    problems.push(`/.well-known/agent.json could not be fetched: ${card.error}`);
  } else if (card.status !== 200) {
    problems.push(`/.well-known/agent.json returned ${card.status} ${card.type}`.trim());
  } else if (!/\bjson\b/i.test(card.type)) {
    problems.push(`/.well-known/agent.json returned ${card.type || "no content type"}, not JSON`);
  } else {
    let parsed;
    try {
      parsed = JSON.parse(card.body);
    } catch {
      problems.push("/.well-known/agent.json is not valid JSON");
    }
    if (parsed !== undefined && (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))) {
      problems.push("/.well-known/agent.json is not a JSON object");
    }
  }
  const home = await get(fetchImpl, `https://${host}/`);
  if (home.error) {
    problems.push(`the home page could not be fetched: ${home.error}`);
  } else if (home.status !== 200) {
    problems.push(`the home page returned ${home.status}`);
  } else {
    const title = home.body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1];
    if (title === undefined) problems.push("the home page has no title");
    else if (siteName(title) !== name) problems.push(`the home page calls the agent "${siteName(title)}", not "${name}"`);
  }
  return problems;
}

async function main() {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const agents = testAgents(readFileSync(join(root, "README.md"), "utf8"));
  if (agents.length === 0) {
    console.error("FAIL no rows found in the README's test agent table");
    process.exitCode = 1;
    return;
  }
  const results = await Promise.all(agents.map(async (agent) => ({ agent, problems: await checkAgent(agent) })));
  for (const { agent, problems } of results) {
    const label = `${agent.name} (${agent.host})`;
    console.log(problems.length === 0 ? `ok   ${label}` : `FAIL ${label}: ${problems.join("; ")}`);
  }
  const failed = results.filter((result) => result.problems.length > 0).length;
  console.log(`${agents.length - failed} of ${agents.length} test agents pass`);
  if (failed > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
