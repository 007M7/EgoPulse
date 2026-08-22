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

console.log("repository boundary check passed");
