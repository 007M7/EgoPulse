import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "..");
const contractsRoot = join(repositoryRoot, "contracts");
const manifestPath = join(contractsRoot, "manifest.json");
const expectedManifestSha256 = "64da25010ce5284679e386864721ed54c364f8fa2811cd9d38b386ba8b8aea6e";
const expectedArtifactCount = 231;
const expectedFixtureCount = 179;

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
assert(manifest.candidateVersion === "0.1.0-draft.13", "unexpected V-01 implementation contract version");
assert(manifest.targetedRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3", "missing Founder authority for targeted revision");
assert(manifest.approvalReadModelRevisionAuthorityRef === "conversation:2026-08-24:founder-v01-g4-08-approval-read-model-a", "missing Founder authority for approval read model revision");
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
assert(existsSync(join(contractsRoot, "proto", "egopulse", "foundation", "v1", "health.proto")), "Foundation health contract was lost during V-01 import");

console.log(
  `V-01 contract SSOT verified: version=${manifest.candidateVersion}, manifest=${manifestSha256}, artifacts=${manifest.artifacts.length}, fixtures=${fixtureCount}`,
);
