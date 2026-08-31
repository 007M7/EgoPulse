# V-01 implementation contract provenance and targeted revision

The original 198-artifact Gate 3 import remains auditable as `0.1.0-draft.11`. The current implementation contract candidate is `0.1.0-draft.19`; complete R-9A is locally verified with Scheme C new-commit validation, exact historical replay compatibility and durable Gate 1-12 evidence.

- Accepted candidate: `0.1.0-draft.11`
- Accepted manifest SHA-256: `adbcba96ee023f886ba6ea8de0083d7f09c2f5db67b60ddd6db6b231932fbe66`
- Gate 3 authority: `conversation:2026-08-23:founder-v01-gate3-pass`
- Gate 4 DRI authority: `conversation:2026-08-23:founder-v01-gate4-dri-confirmation`
- Targeted revision authority: `conversation:2026-08-24:founder-v01-g4-08-a1-a2-a3`
- Approval Read Model revision authority: `conversation:2026-08-24:founder-v01-g4-08-approval-read-model-a`
- G4-08C support-profile authority: `conversation:2026-08-24:founder-v01-g4-08c-a1-a2-a3`
- Memory/RAG worker authority: `conversation:2026-08-26:founder-memory-rag-m01-m06-freeze`
- Memory retrieval authority: `conversation:2026-08-26:founder-memory-rag-m07-m10-freeze`
- Context revoke linearization authority: `conversation:2026-08-30:founder-r9a-context-revoke-linearization-freeze`
- Context revoke Scheme C authority: `conversation:2026-08-31:founder-r9a-gate11-scheme-c`
- Targeted scope: C-03 Harness Adapter, C-07 Local API, C-08 Persistence/Recovery, G4-07A Policy Decision Authority, G4-08A Harness Approval Read Model, G4-08C-A1 Client Kernel Profile, G4-08C-A3 Authorization Capability Profile, M-01 through M-06 Memory/RAG Worker, M-07 through M-10 governed Memory retrieval, and complete R-9A Context revoke/dispatch/recovery linearization
- Verification command: `pnpm run check:v01-contract-import`

Draft.12 removed the client-authored Adapter approval envelope from Local API, reserved the removed wire field identities, and routed approval writes through Policy Decision Authority. Draft.13 adds Adapter-owned approval request lifecycle/revision facts, a rebuildable read model joining those facts to optional Policy-owned decision state, typed get/list/watch/await APIs, stable cursor/reset behavior, and a sanitized Authority result that cannot expose native routing or proof internals. Draft.14 adds independently versioned, digest-addressed client-kernel conformance and authorization capability profiles. Draft.15 freezes M-01 through M-06: accepted-snapshot-only retrieval, supervised Protobuf transport and reference-only Python Worker output. Draft.16 freezes M-07 through M-10: `LocalCognitionService/RetrieveMemory`, `local.memory.retrieve`, daemon-owned principal/scope authorization, typed cognition failures and one shared CLI/TUI capability boundary. Draft.17 adds the candidate `PrepareWork`/`ConfirmWork` natural-language work boundary; it does not authorize client-authored snapshots, raw compiled context, direct Task construction or dispatch bypasses. Draft.18 adds `local.context.revoke`, an `ExecuteContextMutation` command owned by Context Authority, the separately projected `context_state_revision`, full semantic-digest confirmation bound to the authenticated session Founder, and a strict sanitized receipt. It adds no Context stream, Adapter dispatch grant, resend path or raw Context exposure.

Draft.19 does not change that draft.18 wire checkpoint, any Proto field/tag/RPC, Context Authority SQL schema/migration, or the semantic digest algorithm and fixed vectors. It freezes lowercase ASCII reason slugs and namespaced evidence/proof references for new commits, rejects rather than normalizes raw or encoded Context/Provider content, preserves exact historical replay for the same authenticated principal, idempotency key and full semantic digest with zero writes, and returns idempotency conflict for changed semantics before applying new-commit validation. Gate 7 preserves existing receipt and Task/Run/Step/Attempt facts, Gate 9 proves both commit orders with an independent external witness, Gate 10 proves zero Founder Verdict advancement, and Gate 11 closes Scheme C/history compatibility.

The imported `README.md` retains its historical candidate-time wording. `EgoPulse/contracts/` remains the implementation-period machine-contract SSOT; every manifest-controlled change requires an explicit revision authority and regenerated digest evidence.
