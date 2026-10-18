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

## Governed repository setup

For a fresh Windows installation, select the real Git repository and a reviewed
acceptance contract explicitly:

```powershell
.\install-egopulse.ps1 -RepositoryRoot 'D:\work\project' `
  -AcceptanceContractPath 'D:\work\project-acceptance.json'
```

`-GitExecutable` can select an absolute Git executable. `-ReviewModel` can
select an exact model from the configured production Codex catalog; otherwise
the configured selected model is used. Setup does not start a model or run the
acceptance commands. The installation report distinguishes a configured worker
from a completed task.

The acceptance JSON uses `repository_change_acceptance/v1` with a contract ID,
version, positive revision, allowed/forbidden/read-only relative paths,
required commands and evidence requirements. Each command states its ID,
criterion (`scope`, `tests` or `review`), `requirement: "must_pass"`, absolute
executable, ordered argv, relative cwd, environment allowlist/overrides,
timeout, output limit and expected exit code. Evidence requirements include
`repository_baseline`, `repository_patch`, `workspace_manifest`,
`command_receipt` and `independent_checker`. The daemon derives its reference
with the same normalized parser used when freezing a Task. Operators do not
need to reproduce that digest algorithm.
Environment names use uppercase identifiers (for example, `SYSTEMROOT`,
`TEMP` and `TMP` on Windows); Authority and EgoPulse secrets are disallowed.

Setup connects the existing repository material collector, scope/tests/review
checkers and Founder supporting-material intake. Built-in definitions are
compiled into `agentosd` from the source repository's
`config/repository-profiles.v1.json`; the binary package needs no editable
copy of that catalog. Model review
receives selected repository material through the configured provider; agent
tool network access is disabled. Zero findings still leave model review
unverified and cannot automatically accept a Task.

The installer keeps a separate candidate, validates it with `--check-config`,
then promotes it before the first startup. Existing configurations are kept
unless `-Force` explicitly requests a reinstall with a backup. To prepare an
existing configuration for review without replacing it, run:

```powershell
agentosd.exe --prepare-repository-config 'D:\EgoPulse\repository-setup.json' --json
```

The request contains absolute `config_path`, a new `candidate_path`,
`repository_root`, `acceptance_contract_path`, `git_executable`, and optional
`review_model`. The candidate path must not exist. This command opens no
Authority stores and changes neither the source configuration nor Task state.
Validate the candidate with the normal keys and configuration preflight before
using it. Historical deployments remain immutable; a changed model or policy
gets a distinct checker deployment identity.

## Providers and models

For task creation, result inspection, Founder materials and interrupted
decision recovery, see the [repository work loop](../docs/engineering/repository-work-loop.md).

`provider_profiles` separates four concerns that must not be conflated:
Provider identity, replaceable Harness, admission state and model selection.
Each profile contains an editable `models` fallback catalog and one
`selected_model`. Every entry records both the identifier accepted by the
Harness and the provider-native identifier; these differ for routes such as
`zai/glm-5.3` -> `glm-5.3`. The selection names the Harness identifier and must
exist in the catalog. EgoPulse sends that exact value and must reject silent
substitution.

Provider and Harness are independent identities. A candidate or held profile
may pair any known Provider with any known Harness so compatibility can be
evaluated without changing the schema or runtime architecture. Parsing that
pair proves only representability: it does not prove that the Harness can
authenticate to the Provider, preserve the exact model, or satisfy the
governed lifecycle. Production admission is per Provider/Harness route and
enforced from the composition allowlist: GPT through Codex app-server, and
DeepSeek through DSH, OpenCode or Codex app-server, with at most one
production profile configured at a time. Every other combination remains
non-selectable until separately promoted with evidence.

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

`work_capabilities` is the separate v3 routing boundary. Each selectable
`choice_id` resolves to one fully sealed Provider/Harness/model route. The
mutable `default_choice_id` is used only when preparing future work;
confirmation copies the exact route into the immutable Context and Task facts.
Changing the default never rewrites active or recoverable work, and catalog
visibility alone never admits a route.

Existing v2 installations remain readable but cannot change the future-work
default until the explicit migration is applied. Startup never edits the
configuration. Preview, apply and (while the migrated v3 remains unchanged)
rollback with:

```powershell
agentosd.exe --preview-v3-migration --json
agentosd.exe --migrate-to-v3 --json
agentosd.exe --preview-v2-rollback --json
agentosd.exe --rollback-to-v2 --json
```

Migration retains the complete prior file as
`agentos-config.json.v2.bak`. Rollback restores those exact bytes and retains
the migrated file as `agentos-config.json.v3-rollback.bak`. A concurrent edit,
preference revision change or any other post-migration drift fails closed.
These commands do not open or migrate Authority stores.

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

`identity.permission_codes` never selects an Authority principal kind. Founder
Memory governance requires the reviewed `memory_kind` binding, and
`local.context.revoke` additionally requires `context_kind: "Founder"`.
Missing or non-Founder Context binding fails startup before the daemon serves.

## Verification worker checker output

`verification_worker` runs one configured checker for one criterion. Two
declarations decide how that checker's output is read and cited:

- `checker_output_source` — `stdout` (the default) reads the review artifact
  from the process' stdout. `envelope_artifact_path` treats stdout as a JSON
  envelope and loads the review artifact from the `artifact_path` it names;
  that path must resolve inside `working_directory`, and the artifact is read
  with a 16 MiB cap. Anything else in the envelope is not interpreted.
- `checker_output_capture` (optional) — when present, `agentosd` seals the
  exact bytes the checker produced through the governed checker-output
  collector and cites that artifact as the criterion's raw output. Without it,
  the configured `mapper.raw_output_artifact_id` stays the citation, and that
  artifact must then be a member of the Task's own artifact set.

| Field | Meaning |
| --- | --- |
| `raw_output_type_ref` | Artifact type contract of the raw checker output; must be admitted in `artifact.allowed_artifact_type_refs` |
| `retention_profile_ref` | Retention profile for the captured output; must be admitted in `artifact.allowed_retention_profile_refs` |
| `collector_principal_id` | Governed collector that stages the captured output |
| `artifact_authority_principal_id` | Authority principal that seals it; must differ from the collector |
| `max_output_bytes` | Upper bound for one captured output, 1 to 67108864 |

The checker profile's `output_contract_ref` is used as the captured artifact's
transformation contract, so it must be admitted in
`artifact.allowed_transformation_contract_refs`. A checker that exits non-zero
is always a failed criterion; with capture configured, the bytes it wrote
before exiting are sealed as well, so a declared stop reason such as
`budget_exceeded` stays readable instead of being discarded.
