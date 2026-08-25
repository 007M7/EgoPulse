# Artifact Authority configuration

Artifact Authority is configured separately from the other authorities.

- `stores.artifact` selects the SQLCipher database, content-addressed blob root, store epoch, and the environment variable that supplies the 32-byte key.
- The top-level `artifact` policy is an explicit admission allowlist owned by the local installation.
- Workspace references, artifact type contracts, transformation contracts, retention profiles, claim profiles, and evidence profiles must all be present and unique.
- The production guard rejects empty policy, workspace drift, contract drift, unauthenticated principals, empty payloads, and incomplete lineage before an artifact is admitted.

The example file contains `replace-*` placeholders. Replace them in the user-owned copy before starting `agentosd`; secret keys remain environment variables and never enter JSON.

Verification is still deny-by-default for unreviewed external references. Opening Artifact Authority does not, by itself, authorize a Sego result or a Task verification write.
