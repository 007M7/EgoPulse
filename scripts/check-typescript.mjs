import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const compiler = join(dirname(require.resolve("typescript")), "tsc.js");
const projects = [
  "packages/generated-client/tsconfig.json",
  "packages/agent-sdk/tsconfig.json",
  "packages/native-harness/tsconfig.json",
  "apps/desktop/tsconfig.json",
];

for (const project of projects) {
  const result = spawnSync(process.execPath, [compiler, "--noEmit", "--project", project], {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

console.log("TypeScript project checks passed");
