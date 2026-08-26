import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const contractsRoot = join(repositoryRoot, "contracts");
const manifestPath = join(contractsRoot, "manifest.json");
const expectedManifestSha256 = "220485bc3f8fecf59b78e620ce08dd643829c0a35f4bf955787339278f301930";
const expectedArtifactCount = 239;
const expectedFixtureCount = 182;
const expectedClientKernelProfileSha256 = "367ad4210c499d7501acd060f5b544255521cefefca86b8d69a2cea022166c11";
const expectedAuthorizationProfileSha256 = "5ae8cff8552910c780cdde9e29f1a5a3a95e40803ebcbb1de26544de5f6ac29f";

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
assert(manifest.candidateVersion === "0.1.0-draft.15", "unexpected V-01 implementation contract version");
assert(manifest.targetedRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3", "missing Founder authority for targeted revision");
assert(manifest.approvalReadModelRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-approval-read-model-a", "missing Founder authority for approval read model revision");
assert(manifest.g408cSupportProfilesAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08c-a1-a2-a3", "missing Founder authority for G4-08C support profiles");
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
assert(existsSync(join(contractsRoot, "proto", "egopulse", "foundation", "v1", "health.proto")), "Foundation health contract was lost during V-01 import");

console.log(
  `V-01 contract SSOT verified: version=${manifest.candidateVersion}, manifest=${manifestSha256}, artifacts=${manifest.artifacts.length}, fixtures=${fixtureCount}`,
);
