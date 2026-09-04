import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const contractsRoot = join(repositoryRoot, "contracts");
const manifestPath = join(contractsRoot, "manifest.json");
const expectedManifestSha256 = "7216449c1960915f21d333bbd46dd4c85e3b18c5f99aa94b57683a4556d74a52";
const expectedArtifactCount = 268;
const expectedFixtureCount = 200;
const expectedClientKernelProfileSha256 = "62390a1fe45374e3d73d6dce6d695aeabe460d9421ecf78a334f437bd8832116";
const expectedAuthorizationProfileSha256 = "948c2abb84cf7249dcff23213772cbc7aa136630a3b254aa592f8099223e58d2";
const expectedContextRevokeProfileSha256 = "ee77f4894dfd64394f674d37634a29383bf453dc68494f3d75268e85df2590e4";
const expectedHarnessContentProfileSha256 = "c969c9eda5394617aa8bcbca4ed0086eb0dd61ced2519818db830cc73ed1e58f";

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
assert(manifest.candidateVersion === "0.1.0-draft.21", "unexpected V-01 implementation contract version");
assert(manifest.status === "targeted_revision_r9c_contract_founder_frozen_locally_verified", "unexpected R-9C contract status");
assert(manifest.targetedRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3", "missing Founder authority for targeted revision");
assert(manifest.approvalReadModelRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-approval-read-model-a", "missing Founder authority for approval read model revision");
assert(manifest.g408cSupportProfilesAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08c-a1-a2-a3", "missing Founder authority for G4-08C support profiles");
assert(manifest.contextRevokeLinearizationAuthorityRef === "conversation:2026-08-30:founder-r9a-context-revoke-linearization-freeze", "missing Founder authority for R-9A Context revoke linearization");
assert(manifest.contextRevokeSchemeCAuthorityRef === "conversation:2026-08-31:founder-r9a-gate11-scheme-c", "missing Founder authority for R-9A Scheme C validation and historical replay");
assert(manifest.r9cHarnessContentAuthorityRef === "conversation:2026-09-04:founder-froze-r9c-d01-d12-and-phase-2-82-section-7", "missing Founder authority for R-9C Harness content and migration/rollback contract");
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
assert(sha256(readFileSync(join(contractsRoot, "profiles", "harness-content-disclosure", "v1", "v01-default.json"))) === expectedHarnessContentProfileSha256, "Harness content disclosure profile digest mismatch");
assert(existsSync(join(contractsRoot, "proto", "egopulse", "foundation", "v1", "health.proto")), "Foundation health contract was lost during V-01 import");

console.log(
  `V-01 contract SSOT verified: version=${manifest.candidateVersion}, manifest=${manifestSha256}, artifacts=${manifest.artifacts.length}, fixtures=${fixtureCount}`,
);
