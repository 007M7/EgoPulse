# Phase 2-45 — Kimi recovery and exact-model boundary

- Date: 2026-08-27
- Native candidate: Kimi CLI 1.49.0 multi-session ACP (`kimi acp`)
- Admission status: candidate-only

## Corrected native capability fact

The installed Kimi CLI 1.49.0 multi-session ACP implementation advertises and
implements all of the following:

- `agentCapabilities.loadSession = true`;
- `sessionCapabilities.list`;
- `sessionCapabilities.resume`;
- `session/load` with persisted-history replay;
- `session/resume` bound to the original session id and working directory.

This differs from the older EgoPulse assumption that Kimi had no native
recovery surface. The candidate adapter now rejects a Kimi ACP runtime that
does not advertise both `loadSession` and `session/resume`.

Session recovery is not dispatch-outcome reconciliation. A successful
`session/resume` proves that the native session can be reattached; its response
does not identify whether a particular interrupted prompt completed, which
tool side effects committed, or which terminal observation belongs to the
EgoPulse dispatch. The adapter therefore records a hashed resume receipt but
keeps the dispatch as `OutcomeUnknown`. It never converts session reachability
into a successful task result or an automatic retry.

## Exact model binding

`KimiAcpConfig::with_required_model` binds a candidate profile to the exact ACP
model id returned in `models.currentModelId`. This includes the thinking suffix
when present, for example `kimi-k2.5,thinking`.

The adapter fails closed when:

- the configured model id is empty;
- the session response does not attest a current model;
- the current model differs from the configured model;
- a resumed session reports a different model.

This prevents a valid Kimi process from silently satisfying a dispatch with a
different model than the selected capability profile.

## Authentication boundary

The no-inference Windows probe passed initialization and the new recovery
capability checks, then returned `authentication_required` from `session/new`.
No prompt or model request was sent.

The inspected Kimi 1.49.0 multi-session ACP checks its persisted Kimi Code OAuth
token before creating or loading a session. Kimi CLI's general configuration
model supports static provider API keys, but that does not by itself prove
that this ACP entry point accepts a user-owned API key without Kimi Code login.
EgoPulse therefore records two separate unresolved rows:

1. Kimi Code account authentication through the native `login` method;
2. user-owned Moonshot/Kimi API-key authentication through a supported Harness
   route, without fabricated OAuth state or secrets copied into EgoPulse logs.

The second row is required by the product's local BYOK promise. It must not be
claimed from the first row.

## Evidence

```text
cargo test -p egopulse-kimi-adapter
14 passed, 0 failed, 2 ignored

cargo clippy -p egopulse-kimi-adapter --all-targets -- -D warnings
passed

live no-inference capability probe
1 passed, 0 failed
initialize=passed
session_disposition=authentication_required
prompt_sent=false
model_call=false
```

## Remaining admission gates

1. choose and evidence the BYOK-capable Kimi Harness route;
2. run an authenticated exact-model prompt, tool, permission and cancellation
   lifecycle;
3. restart the Harness and validate session resume against the same workspace;
4. reconcile a specific dispatch result or preserve the existing explicit
   outcome-unknown hold;
5. bind terminal output to Artifact, Verification and Founder Verdict;
6. install the reviewed capability profile in production bootstrap.
