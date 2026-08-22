import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

const cacheDir = join(process.cwd(), ".cache", "buf");
mkdirSync(cacheDir, { recursive: true });

const require = createRequire(import.meta.url);
const executable = require.resolve("@bufbuild/buf/bin/buf");

const result = spawnSync(process.execPath, [executable, "lint"], {
  env: { ...process.env, BUF_CACHE_DIR: cacheDir },
  stdio: "inherit",
});

if (result.error) throw result.error;
process.exit(result.status ?? 1);
