import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const required = [
  "ARCHITECTURE.md",
  "apps/agentosd/Cargo.toml",
  "apps/cli/Cargo.toml",
  "apps/tui/Cargo.toml",
  "apps/desktop/package.json",
  "crates/domain-contracts/Cargo.toml",
  "crates/cognition-runtime/Cargo.toml",
  "crates/harness-adapter/Cargo.toml",
  "crates/codex-adapter/Cargo.toml",
  "crates/local-ide-control/Cargo.toml",
  "packages/native-harness/package.json",
  "workers/foundation-probe/pyproject.toml",
  "contracts/proto/egopulse/foundation/v1/health.proto"
];

const missing = required.filter((path) => !existsSync(path));
if (missing.length > 0) {
  throw new Error(`Missing foundation paths:\n${missing.join("\n")}`);
}

function filesUnder(root) {
  const result = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (["node_modules", "target", ".venv", "generated"].includes(entry)) continue;
    if (statSync(path).isDirectory()) result.push(...filesUnder(path));
    else result.push(path);
  }
  return result;
}

const forbiddenFrameworkTerms = ["langchain", "langgraph", "qdrant", "tauri", "react"];
for (const file of filesUnder("crates/domain-contracts")) {
  if (!file.endsWith(".rs") && !file.endsWith(".toml")) continue;
  const text = readFileSync(file, "utf8").toLowerCase();
  for (const term of forbiddenFrameworkTerms) {
    if (text.includes(term)) {
      throw new Error(`${relative(".", file)} leaks framework term: ${term}`);
    }
  }
}

const nonAuthorityRoots = [
  "apps",
  "crates/local-api",
  "crates/process-supervision",
  "packages",
  "workers"
];
const directDatabaseTerms = [
  "rusqlite",
  "libsqlite3_sys",
  "bundled-sqlcipher"
];
for (const root of nonAuthorityRoots) {
  for (const file of filesUnder(root)) {
    if (!/\.(rs|toml|ts|tsx|js|mjs|py|json)$/.test(file)) continue;
    const text = readFileSync(file, "utf8").toLowerCase();
    for (const term of directDatabaseTerms) {
      if (text.includes(term)) {
        throw new Error(`${relative(".", file)} attempts to own an Authority database: ${term}`);
      }
    }
  }
}

const taskNonOwnerRoots = [
  "apps",
  "crates/local-api",
  "crates/local-ide-control",
  "crates/process-supervision",
  "packages",
  "workers"
];
const taskAuthorityStorageTerms = [
  "task-authority.sqlcipher",
  "task_authority::store"
];
for (const root of taskNonOwnerRoots) {
  for (const file of filesUnder(root)) {
    if (!/\.(rs|toml|ts|tsx|js|mjs|py|json)$/.test(file)) continue;
    const text = readFileSync(file, "utf8").toLowerCase();
    for (const term of taskAuthorityStorageTerms) {
      if (text.includes(term)) {
        throw new Error(`${relative(".", file)} attempts to depend on Task Authority storage: ${term}`);
      }
    }
  }
}

const collaborationNonOwnerRoots = [
  "apps",
  "crates/cognition-runtime",
  "crates/local-api",
  "crates/process-supervision",
  "packages",
  "workers"
];
const collaborationStorageTerms = [
  "collaboration-control.sqlcipher",
  "collaboration_control::store"
];
for (const root of collaborationNonOwnerRoots) {
  for (const file of filesUnder(root)) {
    if (!/\.(rs|toml|ts|tsx|js|mjs|py|json)$/.test(file)) continue;
    const text = readFileSync(file, "utf8").toLowerCase();
    for (const term of collaborationStorageTerms) {
      if (text.includes(term)) {
        throw new Error(`${relative(".", file)} attempts to depend on Collaboration storage: ${term}`);
      }
    }
  }
}

const providerPrivateProtocolTerms = [
  "codex-app-server",
  "thread/start",
  "thread/read",
  "turn/start",
  "turn/interrupt"
];
const providerNeutralRoots = ["apps", "crates", "packages", "workers"];
for (const root of providerNeutralRoots) {
  for (const file of filesUnder(root)) {
    const normalized = relative(".", file).replaceAll("\\", "/");
    if (normalized.startsWith("crates/codex-adapter/")) continue;
    if (!/\.(rs|toml|ts|tsx|js|mjs|py|json)$/.test(file)) continue;
    const text = readFileSync(file, "utf8").toLowerCase();
    for (const term of providerPrivateProtocolTerms) {
      if (text.includes(term)) {
        throw new Error(`${normalized} leaks Codex-private protocol term: ${term}`);
      }
    }
  }
}

console.log("repository boundary check passed");
