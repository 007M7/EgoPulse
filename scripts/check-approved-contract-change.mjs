import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const previousBaseline = join(repositoryRoot, "contracts", "baselines", "v01-gate3-draft11.binpb");
const expectedPreviousSha256 = "77f07275c43b21f53de000d06c18728e0fe617c585b73ab1756f29650cf31b70";
const cacheDirectory = join(repositoryRoot, ".cache", "buf");
mkdirSync(cacheDirectory, { recursive: true });

const actualPreviousSha256 = createHash("sha256").update(readFileSync(previousBaseline)).digest("hex");
if (actualPreviousSha256 !== expectedPreviousSha256) {
  throw new Error(`Gate 3 draft.11 audit baseline digest mismatch: ${actualPreviousSha256}`);
}

const require = createRequire(import.meta.url);
const executable = require.resolve("@bufbuild/buf/bin/buf");
// Node 24 on Windows can reject child-process stdout/stderr pipes with EPERM
// in restricted workspaces. A temporary file handle preserves the exact
// output inspection below without weakening the approved-break assertion.
const outputPath = join(cacheDirectory, "approved-breaking-output.txt");
const outputHandle = openSync(outputPath, "w");
let result;
try {
  result = spawnSync(process.execPath, [executable, "breaking", "--against", previousBaseline], {
    cwd: repositoryRoot,
    env: { ...process.env, BUF_CACHE_DIR: cacheDirectory },
    stdio: ["ignore", outputHandle, outputHandle],
  });
} finally {
  closeSync(outputHandle);
}
if (result.error) throw result.error;
const output = readFileSync(outputPath, "utf8");
if (result.status === 0) {
  throw new Error("Founder-authorized Local API wire break was not detected against draft.11");
}

const normalizedOutput = output.replaceAll("\\", "/");
const approvedBreaks = [
  'Previously present field "2" with name "decision" on message "DecideHarnessApprovalRequest" was deleted.',
  'Previously present field "1" with name "authority_result" on message "DecideHarnessApprovalResponse" was deleted.',
];
for (const approved of approvedBreaks) {
  if (!normalizedOutput.includes(approved)) throw new Error(`approved breaking change was not detected: ${approved}`);
}
const detectedBreaks = normalizedOutput.split(/\r?\n/).filter((line) => line.includes("Previously present field "));
if (detectedBreaks.length !== approvedBreaks.length) {
  throw new Error(`unexpected breaking-change set against draft.11:\n${normalizedOutput}`);
}

console.log("Founder-authorized draft.11 break set detected exactly: Local API approval request field 2 and response field 1");
