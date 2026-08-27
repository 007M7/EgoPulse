# Memory Authority configuration

The production bootstrap schema is `egopulse.production-bootstrap/v2`.
`stores.memory` is a required independent SQLCipher store:

```json
{
  "database_path": "egopulse-data/memory.db",
  "store_epoch": "replace-memory-epoch",
  "key_env": "EGOPULSE_MEMORY_KEY_HEX"
}
```

The Memory database has a separate key and store epoch from Task, Artifact,
Policy, Verdict, Adapter and Collaboration. Reusing another Authority's key
or database path is not an accepted configuration. The daemon opens the
Memory Authority once during production composition and keeps the
single-writer handle alive for the daemon lifetime.

The retrieval boundary is `LocalCognitionService/RetrieveMemory`. The daemon
authorizes the principal and scope, supervises the Python Worker, validates
the typed response, and returns references plus bounded snippets. The Worker
does not receive a database handle or an Authority key. It reads the request
payload supplied by the daemon and cannot promote, revoke, or directly write
accepted memory.
