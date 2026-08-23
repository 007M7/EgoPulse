import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const baseline = join(repositoryRoot, "contracts", "baselines", "v01-gate3-draft11.binpb");
const expectedSha256 = "77f07275c43b21f53de000d06c18728e0fe617c585b73ab1756f29650cf31b70";
const cacheDirectory = join(repositoryRoot, ".cache", "buf");
mkdirSync(cacheDirectory, { recursive: true });
const actualSha256 = createHash("sha256").update(readFileSync(baseline)).digest("hex");
if (actualSha256 !== expectedSha256) {
  throw new Error(`Gate 3 breaking baseline digest mismatch: ${actualSha256}`);
}

const require = createRequire(import.meta.url);
const executable = require.resolve("@bufbuild/buf/bin/buf");
const result = spawnSync(process.execPath, [executable, "breaking", "--against", baseline], {
  cwd: repositoryRoot,
  env: { ...process.env, BUF_CACHE_DIR: cacheDirectory },
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

console.log(`Buf breaking baseline passed: ${expectedSha256}`);
