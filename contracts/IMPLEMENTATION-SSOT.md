# V-01 implementation contract provenance and targeted revision

The original 198-artifact Gate 3 import remains auditable as `0.1.0-draft.11`. The current implementation contract SSOT is the Founder-authorized `0.1.0-draft.12` targeted revision.

- Accepted candidate: `0.1.0-draft.11`
- Accepted manifest SHA-256: `adbcba96ee023f886ba6ea8de0083d7f09c2f5db67b60ddd6db6b231932fbe66`
- Gate 3 authority: `conversation:2026-08-23:founder-v01-gate3-pass`
- Gate 4 DRI authority: `conversation:2026-08-23:founder-v01-gate4-dri-confirmation`
- Targeted revision authority: `conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3`
- Targeted scope: C-03 Harness Adapter, C-07 Local API, C-08 Persistence/Recovery, and inserted G4-07A Policy Decision Authority
- Verification command: `pnpm run check:v01-contract-import`

Draft.12 removes the client-authored Adapter approval envelope from Local API, reserves the removed wire field identities, and routes approval writes through Policy Decision Authority. It also adds Policy Decision to the required persistence/recovery domain set and generates Rust client/server service code with Tonic.

The imported `README.md` retains its historical candidate-time wording. `EgoPulse/contracts/` remains the implementation-period machine-contract SSOT; every manifest-controlled change requires an explicit revision authority and regenerated digest evidence.
