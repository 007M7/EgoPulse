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

The eight Authority keys must be non-zero 32-byte hexadecimal strings supplied
by their corresponding environment variables:

- `EGOPULSE_TASK_KEY_HEX`
- `EGOPULSE_MEMORY_KEY_HEX`
- `EGOPULSE_ARTIFACT_KEY_HEX`
- `EGOPULSE_VERIFICATION_KEY_HEX`
- `EGOPULSE_POLICY_KEY_HEX`
- `EGOPULSE_VERDICT_KEY_HEX`
- `EGOPULSE_ADAPTER_KEY_HEX`
- `EGOPULSE_COLLABORATION_KEY_HEX`

The read model and local session variables are also supported:

- `EGOPULSE_READ_MODEL_KEY_HEX`
- `EGOPULSE_TOKEN_MAC_KEY_HEX`
- `EGOPULSE_READ_MODEL_DB`
- `EGOPULSE_READ_MODEL_EPOCH`
- `EGOPULSE_IPC_INSTANCE`
- `EGOPULSE_SESSION_TTL_SECONDS`
- `EGOPULSE_HARNESS_DISPATCH_INTERVAL_MS`

For Memory/RAG retrieval, first run the packaged
`setup-memory-worker.ps1`. Set `memory_retrieval.worker_executable` to the
created `workers\memory-rag\.venv\Scripts\python.exe`, set its working
directory to the package root, and preserve the two packaged `src` paths in
`PYTHONPATH`. The daemon, not the client or Worker, owns the principal-to-scope
allowlist.

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
