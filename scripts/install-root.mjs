// Installs the development dependency of the repository root, hackmyagent, for
// npm test, which runs this before it installs the example and runs the test
// files: npm ci in the repository root, without install scripts. The one test
// that runs hackmyagent is skipped on a Node.js release where
// process.features.require_module is not true, since the release package.json
// pins loads an ES module with require(), and on such a release this installs
// nothing. The packages npm ci installs with that release include
// @hono/node-server 2.1.5, whose engines field asks for Node.js 20 or later
// (package-lock.json), and on Node.js 18.17.1 with npm's engine-strict setting
// on, npm ci stops at that package with EBADENGINE. Run with:
// node scripts/install-root.mjs (exits with the status of npm ci, or 0 when it
// installs nothing).
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Whether a Node.js release with these features can run the hackmyagent
// release package.json pins, which loads an ES module with require().
export function canRunHackMyAgent(features = process.features) {
  return features.require_module === true;
}

// The command that installs the repository root on a Node.js release with these
// features, or null on one that cannot run hackmyagent.
export function rootInstallCommand(features = process.features) {
  return canRunHackMyAgent(features) ? "npm ci --ignore-scripts --no-audit --no-fund" : null;
}

function main() {
  const command = rootInstallCommand();
  if (!command) {
    console.log(
      `Skipping npm ci in the repository root: Node.js ${process.version} cannot require() an ES module, which the hackmyagent release package.json pins needs, so the test that runs it is skipped.`
    );
    return;
  }
  // The command runs through a shell, as the steps of an npm script do.
  const result = spawnSync(command, { cwd: join(dirname(fileURLToPath(import.meta.url)), ".."), stdio: "inherit", shell: true });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
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

if (startedWithThisFile()) main();
