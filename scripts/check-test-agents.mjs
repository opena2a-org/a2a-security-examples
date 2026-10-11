// Fetches the agent card and the home page of every test agent the README
// lists, and reports each agent that serves no JSON card at
// /.well-known/agent.json or whose home page calls it by another name than the
// table does. Run with: npm run check:test-agents (exits 1 if any agent fails).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const timeoutMs = 15000;
// The check reads no more of a response body than this, so a body that never
// ends cannot hold it.
export const maxBodyBytes = 256 * 1024;
// The most characters of attributes in a title tag and of text in a title that
// the check reads.
export const maxTitleAttributes = 256;
export const maxTitleText = 1024;
const titleText = new RegExp(`([^<]{0,${maxTitleText}})</title>`, "iy");

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

// White space in HTML, and the characters that end a tag name, an attribute
// name and an unquoted attribute value.
const space = "\t\n\f\r ";
const tagNameEnd = /[\t\n\f\r />]/g;
const attributeNameEnd = `${space}/>=`;
const unquotedValueEnd = `${space}>`;
const isLetter = (c) => c !== undefined && /[A-Za-z]/.test(c);
// The elements other than script whose text runs to their end tag, so a
// "<title>" or "<!--" in it starts nothing, and the end tag that ends each.
const rawTextEnd = new Map(
  ["style", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript"].map((name) => [name, new RegExp(`</${name}[\\t\\n\\f\\r />]`, "gi")])
);
// The parts of a script's text that change where it ends: "<!--", "-->", and a
// script start or end tag.
const scriptToken = /<!--|-->|<(\/?)script(?=[\t\n\f\r />])/gi;
// The elements whose title elements are not the page's title.
const foreignElements = new Set(["svg", "math"]);

// The index just past a comment whose "<!--" ends at i, or -1 if the page ends
// first. A comment ends at "-->" or "--!>", and "<!-->" and "<!--->" are whole
// comments.
function commentEnd(body, i) {
  if (body[i] === ">") return i + 1;
  if (body.startsWith("->", i)) return i + 2;
  for (let dashes = body.indexOf("--", i); dashes !== -1; dashes = body.indexOf("--", dashes + 1)) {
    if (body[dashes + 2] === ">") return dashes + 3;
    if (body.startsWith("!>", dashes + 2)) return dashes + 4;
  }
  return -1;
}

// The index of the "</script" that ends a script whose text starts at i, or -1
// if the page ends first. A script ends at its first "</script" followed by
// white space, "/" or ">", except in a part of it that "<!--" starts and "-->"
// ends: there a "<script" starts a part that the next "</script" ends in place
// of the script, as in <script><!--<script></script>--></script>. The dashes of
// a "<!--" are also the first two of a "-->", so "<!-->" ends the part it starts.
function scriptEnd(body, i) {
  // Whether the scan is in a part that "<!--" started, and in one that a
  // "<script" started within it.
  let escaped = false;
  let nested = false;
  scriptToken.lastIndex = i;
  for (let token; (token = scriptToken.exec(body)) !== null; ) {
    if (token[0] === "<!--") {
      escaped = true;
      scriptToken.lastIndex = token.index + 2;
    } else if (token[0] === "-->") {
      escaped = nested = false;
    } else if (token[1] === "/") {
      if (!nested) return token.index;
      nested = false;
    } else if (escaped) {
      nested = true;
    }
  }
  return -1;
}

// The ">" that ends a tag whose name ends at i, and whether a "/" before it
// closes the tag, or undefined if the page ends first. A quoted attribute value
// may hold ">".
function tagEnd(body, i) {
  while (i < body.length) {
    const c = body[i];
    if (c === ">") return { end: i, selfClosing: false };
    if (c === "/" && body[i + 1] === ">") return { end: i + 1, selfClosing: true };
    if (space.includes(c) || c === "/") {
      i++;
      continue;
    }
    // An attribute name, which may begin with "=", then an optional value.
    i++;
    while (i < body.length && !attributeNameEnd.includes(body[i])) i++;
    let j = i;
    while (j < body.length && space.includes(body[j])) j++;
    if (body[j] !== "=") {
      i = j;
      continue;
    }
    j++;
    while (j < body.length && space.includes(body[j])) j++;
    if (body[j] === '"' || body[j] === "'") {
      const close = body.indexOf(body[j], j + 1);
      if (close === -1) return undefined;
      i = close + 1;
    } else {
      while (j < body.length && !unquotedValueEnd.includes(body[j])) j++;
      i = j;
    }
  }
  return undefined;
}

// The first title element of a page: undefined when the page holds no title
// tag, and otherwise its text, which is undefined when the title lies past the
// bounds the check reads or is not closed by </title>. The page is split into
// tags the way an HTML parser splits it: a title tag is "<title" followed by
// white space, "/" or ">", so "<titlebar>" is none, and it counts only outside
// comments, which end at "-->" or "--!>", doctypes and other "<!" and "<?"
// declarations, quoted attribute values, the text of script, style, textarea
// and the other raw text elements, and svg and math elements. The check builds
// no tree as a parser does, so it reads a title in a template element, and it
// keeps an svg or math element open to its own end tag: it reads no title that
// such an element holds in an element that holds HTML, such as foreignObject
// or desc in svg and mi in math, and none after markup at which a parser
// closes the element, such as the end tag of an element that holds it, as in
// <div><svg></div>, or the start tag of an HTML element such as p or div, as
// in <svg><p>. Each search starts where the last one stopped, which keeps the
// scan linear in the length of the page.
function findTitle(body) {
  // The svg and math elements open at the scan position, innermost last.
  const foreign = [];
  const open = { svg: 0, math: 0 };
  let i = 0;
  while (i !== -1) {
    const lt = body.indexOf("<", i);
    if (lt === -1) return undefined;
    const next = body[lt + 1];
    if (body.startsWith("<!--", lt)) {
      i = commentEnd(body, lt + 4);
    } else if (foreign.length > 0 && body.startsWith("<![CDATA[", lt)) {
      const close = body.indexOf("]]>", lt + 9);
      i = close === -1 ? -1 : close + 3;
    } else if (next === "!" || next === "?" || (next === "/" && !isLetter(body[lt + 2]))) {
      // A declaration, or an end tag whose name starts with no letter, runs to the next ">".
      const close = body.indexOf(">", lt + 2);
      i = close === -1 ? -1 : close + 1;
    } else if (isLetter(next) || next === "/") {
      const endTag = next === "/";
      const nameStart = lt + (endTag ? 2 : 1);
      tagNameEnd.lastIndex = nameStart;
      const nameEnd = tagNameEnd.exec(body)?.index;
      if (nameEnd === undefined) return undefined;
      const name = body.slice(nameStart, nameEnd).toLowerCase();
      const htmlStartTag = !endTag && foreign.length === 0;
      const tag = tagEnd(body, nameEnd);
      // A title tag the page does not close is one the check cannot read.
      if (tag === undefined) return htmlStartTag && name === "title" ? {} : undefined;
      i = tag.end + 1;
      if (foreignElements.has(name)) {
        if (!endTag && !tag.selfClosing) {
          foreign.push(name);
          open[name]++;
        } else if (endTag && open[name] > 0) {
          // An end tag closes the elements opened after the one it ends.
          for (let closed; closed !== name; open[closed]--) closed = foreign.pop();
        }
      } else if (htmlStartTag && name === "title") {
        titleText.lastIndex = i;
        return { text: tag.end - nameEnd <= maxTitleAttributes ? titleText.exec(body)?.[1] : undefined };
      } else if (htmlStartTag && name === "plaintext") {
        return undefined;
      } else if (htmlStartTag && name === "script") {
        i = scriptEnd(body, i);
      } else if (htmlStartTag && rawTextEnd.has(name)) {
        const end = rawTextEnd.get(name);
        end.lastIndex = i;
        i = end.exec(body)?.index ?? -1;
      }
    } else {
      i = lt + 1;
    }
  }
  return undefined;
}

// A problem with each control character shown as \x1B, so text a site sends
// cannot move the cursor or change the colors of the terminal it is printed to.
const visible = (text) => text.replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`);

// The problem with a home page in which the check found no title it can read.
// For a page that runs past the part the check reads, the message names that
// part, since a title may lie past it. For a page in which findTitle found a
// title tag the check cannot read, the message names the bounds on a title's
// attributes and text, since a title may lie past them, and the closing tag,
// since a title within them may not be closed; for a page in which findTitle
// found no title tag, the message names neither of those two.
function missingTitle({ truncated }, hasTitleTag) {
  const kb = maxBodyBytes / 1024;
  if (!hasTitleTag) {
    return truncated ? `the home page has no title in its first ${kb} KB, which is all the check reads` : "the home page has no title";
  }
  const bounds = `a title tag with at most ${maxTitleAttributes} characters of attributes and at most ${maxTitleText} characters of text without a <, closed by </title>`;
  return `the home page has no title the check can read, which needs ${bounds}${truncated ? `, ending in its first ${kb} KB` : ""}`;
}

// The first maxBodyBytes of a response body as text, and whether the body runs
// past them. The rest of a longer body is cancelled, not read.
async function bodyPrefix(res) {
  const chunks = [];
  let size = 0;
  for await (const chunk of res.body ?? []) {
    chunks.push(chunk.subarray(0, maxBodyBytes - size));
    size += chunk.byteLength;
    if (size > maxBodyBytes) break;
  }
  return { body: new TextDecoder().decode(Buffer.concat(chunks)), truncated: size > maxBodyBytes };
}

async function get(fetchImpl, url) {
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, type: res.headers.get("content-type") ?? "", ...(await bodyPrefix(res)) };
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
  } else if (card.truncated) {
    problems.push(`/.well-known/agent.json is longer than ${maxBodyBytes / 1024} KB`);
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
    const title = findTitle(home.body);
    if (title?.text === undefined) problems.push(missingTitle(home, title !== undefined));
    else if (siteName(title.text) !== name) problems.push(`the home page calls the agent "${siteName(title.text)}", not "${name}"`);
  }
  return problems.map(visible);
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
