# V-01 implementation contract provenance

The 198 artifacts listed by `contracts/manifest.json` were imported from the Founder-accepted Gate 3 candidate without changing their bytes.

- Accepted candidate: `0.1.0-draft.11`
- Accepted manifest SHA-256: `adbcba96ee023f886ba6ea8de0083d7f09c2f5db67b60ddd6db6b231932fbe66`
- Gate 3 authority: `conversation:2026-08-23:founder-v01-gate3-pass`
- Gate 4 DRI authority: `conversation:2026-08-23:founder-v01-gate4-dri-confirmation`
- Verification command: `pnpm run check:v01-contract-import`

The imported `README.md` is itself a frozen Gate 3 artifact and therefore retains candidate-time wording. After successful import verification, `EgoPulse/contracts/` is the implementation-period machine-contract SSOT. Any change to a manifest-controlled artifact requires an explicit contract revision and governance decision; it must not be edited silently.

The existing Foundation health contracts remain in this directory and are not part of the V-01 manifest.
