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

The memory database has a separate key and store epoch from Task, Artifact,
Policy, Verdict, Adapter and Collaboration. Reusing another Authority's key
or database path is not an accepted configuration. The daemon opens the
Memory Authority once during the production composition build and keeps the
single-writer handle alive for the daemon lifetime.

This configuration only enables the Rust Authority lifecycle. It does not
expose a Memory API, enable Python retrieval, or grant any client direct
database access.
