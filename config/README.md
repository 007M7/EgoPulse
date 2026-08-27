# EgoPulse local configuration

`agentos-config.example.json` is the template for a local production
bootstrap. It contains paths, contract references, workflow settings and
environment-variable names only; real secrets must not be placed in JSON or
committed to Git.

Copy the template to a user-owned data directory and replace the
user-owned `replace-*` placeholders. The `egopulse.authorization.v1` reference
is a frozen repository contract and must remain unchanged. Then set:

```powershell
$env:EGOPULSE_USER_CONFIG = 'D:\EgoPulse\data\agentos-config.json'
```

The ten local encryption/authentication keys must be non-zero 32-byte hexadecimal strings supplied
by their corresponding environment variables:

- `EGOPULSE_TASK_KEY_HEX`
- `EGOPULSE_MEMORY_KEY_HEX`
- `EGOPULSE_ARTIFACT_KEY_HEX`
- `EGOPULSE_VERIFICATION_KEY_HEX`
- `EGOPULSE_POLICY_KEY_HEX`
- `EGOPULSE_VERDICT_KEY_HEX`
- `EGOPULSE_ADAPTER_KEY_HEX`
- `EGOPULSE_COLLABORATION_KEY_HEX`
- `EGOPULSE_READ_MODEL_KEY_HEX`
- `EGOPULSE_TOKEN_MAC_KEY_HEX`

The read model and local session variables are also supported:

- `EGOPULSE_READ_MODEL_KEY_HEX`
- `EGOPULSE_TOKEN_MAC_KEY_HEX`
- `EGOPULSE_READ_MODEL_DB`
- `EGOPULSE_READ_MODEL_EPOCH`
- `EGOPULSE_IPC_INSTANCE`
- `EGOPULSE_SESSION_TTL_SECONDS`
- `EGOPULSE_HARNESS_DISPATCH_INTERVAL_MS`

## Providers and models

`provider_profiles` separates four concerns that must not be conflated:
Provider identity, replaceable Harness, admission state and model selection.
Each profile contains an editable `models` fallback catalog and one
`selected_model`. Every entry records both the identifier accepted by the
Harness and the provider-native identifier; these differ for routes such as
`zai/glm-5.3` -> `glm-5.3`. The selection names the Harness identifier and must
exist in the catalog. EgoPulse sends that exact value and must reject silent
substitution.

The example catalog is only an offline fallback snapshot. Vendor model lists
change faster than EgoPulse releases, so the production flow will refresh from
the Harness/provider-owned model catalog, cache a redacted snapshot and let the
user explicitly change `selected_model`. Refresh never changes the selection
automatically.

When present, `catalog_snapshot` records the source, collection time, Harness
version and evidence digest of that catalog. These fields establish
provenance for configuration review; they do not prove that the executable,
credentials or model lifecycle is reachable.

`credential.mode=api_key_environment` stores only `source_env` and
`target_env`. The secret value remains outside JSON. Production profiles
resolve it only at startup and inject it into the selected child process.
Candidate and held profiles are visible configuration, but they are not
production dispatch routes.

For Memory/RAG retrieval, first run the packaged
`setup-memory-worker.ps1`. Set `memory_retrieval.worker_executable` to the
created `workers\memory-rag\.venv\Scripts\python.exe`, set its working
directory to the package root, and preserve the two packaged `src` paths in
`PYTHONPATH`. The daemon, not the client or Worker, owns the principal-to-scope
allowlist.

Before starting the daemon, run `agentosd.exe --check-config`. This parses the
daemon environment and the user-owned JSON but does not call the composition
root, open Authority stores, create business databases or listen on IPC. A
successful check prints `stores_opened=false`; an invalid check exits with
code `78`.

For setup tools and scripts, append `--json` to emit a redacted Provider/Model
catalog:

```powershell
agentosd.exe --check-config --json
```

The JSON reports each configured Provider, Harness, admission state, model
catalog, exact selected model and credential mode. API-key profiles expose
only the source environment-variable name; credential values are never
serialized. This is a configuration preflight, not a live capability probe:
`candidate` and `held` profiles remain unavailable for production dispatch.

To enable candidate proposals from an admitted runtime, configure
`memory_candidate_producers` with one entry per fixed route. Each entry binds
`producer_id`, `principal_id`, `principal_kind` (`Agent`, `Model` or `Harness`)
and `scope_ref` at daemon composition time. The runtime receives only its
bound submit-only capability; it cannot select another producer, scope,
principal, or call Memory acceptance/revocation. Omitting the list leaves the
candidate-producer registry empty and does not affect Founder Memory
governance.

Unknown fields, missing or invalid keys, inconsistent contract references and
unapproved verification profiles fail closed during startup.
