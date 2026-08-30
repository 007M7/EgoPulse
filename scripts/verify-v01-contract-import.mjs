import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const contractsRoot = join(repositoryRoot, "contracts");
const manifestPath = join(contractsRoot, "manifest.json");
const expectedManifestSha256 = "c1e497f37d4385002bc151299c04a04821173dcc62b48568def4a573fe9d5d19";
const expectedArtifactCount = 246;
const expectedFixtureCount = 184;
const expectedClientKernelProfileSha256 = "c729726c718a6f49c45e74a0f7435aa0974748661461f4be0e1315b838b17fa4";
const expectedAuthorizationProfileSha256 = "e44e1cee143b35173372b75fa7ce4efb5732be58bb787d59e961450599d612ab";
const expectedContextRevokeProfileSha256 = "b76c42ca6de53e7140de707f4700def5a8d2e5ca29912930607fd2125a169573";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function resolveArtifactPath(artifactPath) {
  assert(!isAbsolute(artifactPath), `absolute artifact path is forbidden: ${artifactPath}`);
  const normalized = normalize(artifactPath.replaceAll("/", sep));
  assert(normalized !== ".." && !normalized.startsWith(`..${sep}`), `artifact path escapes contracts/: ${artifactPath}`);
  const absolute = resolve(contractsRoot, normalized);
  const fromRoot = relative(contractsRoot, absolute);
  assert(fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`), `artifact path escapes contracts/: ${artifactPath}`);
  return absolute;
}

assert(existsSync(manifestPath), "contracts/manifest.json is missing");
const manifestBytes = readFileSync(manifestPath);
const manifestSha256 = sha256(manifestBytes);
assert(manifestSha256 === expectedManifestSha256, `manifest digest mismatch: ${manifestSha256}`);

const manifest = JSON.parse(manifestBytes.toString("utf8"));
assert(manifest.candidateVersion === "0.1.0-draft.18", "unexpected V-01 implementation contract version");
assert(manifest.targetedRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3", "missing Founder authority for targeted revision");
assert(manifest.approvalReadModelRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-approval-read-model-a", "missing Founder authority for approval read model revision");
assert(manifest.g408cSupportProfilesAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08c-a1-a2-a3", "missing Founder authority for G4-08C support profiles");
assert(manifest.contextRevokeLinearizationAuthorityRef === "conversation:2026-08-30:founder-r9a-context-revoke-linearization-freeze", "missing Founder authority for R-9A Context revoke linearization");
assert(manifest.artifacts.length === expectedArtifactCount, "unexpected V-01 artifact count");

let fixtureCount = 0;
for (const artifact of manifest.artifacts) {
  const artifactPath = resolveArtifactPath(artifact.path);
  assert(existsSync(artifactPath), `missing imported artifact: ${artifact.path}`);
  const actual = sha256(readFileSync(artifactPath));
  assert(actual === artifact.sha256, `imported artifact digest mismatch: ${artifact.path}`);
  if (artifact.path.startsWith("fixtures/")) fixtureCount += 1;
}

assert(fixtureCount === expectedFixtureCount, `unexpected fixture count: ${fixtureCount}`);
assert(sha256(readFileSync(join(contractsRoot, "profiles", "client-kernel", "v1", "v01-default.json"))) === expectedClientKernelProfileSha256, "client-kernel profile digest mismatch");
assert(sha256(readFileSync(join(contractsRoot, "profiles", "authorization", "v1", "v01-default.json"))) === expectedAuthorizationProfileSha256, "authorization capability profile digest mismatch");
assert(sha256(readFileSync(join(contractsRoot, "profiles", "context-revoke", "v1", "v01-default.json"))) === expectedContextRevokeProfileSha256, "Context revoke semantic profile digest mismatch");
assert(existsSync(join(contractsRoot, "proto", "egopulse", "foundation", "v1", "health.proto")), "Foundation health contract was lost during V-01 import");

console.log(
  `V-01 contract SSOT verified: version=${manifest.candidateVersion}, manifest=${manifestSha256}, artifacts=${manifest.artifacts.length}, fixtures=${fixtureCount}`,
);
