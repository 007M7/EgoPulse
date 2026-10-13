# Local protected-key installation and recovery

New Windows installations keep ten Authority/read-model/session keys in
`local-keys.dpapi`. DPAPI uses CurrentUser; the persisted environment contains
only `EGOPULSE_KEY_FILE`, configuration/IPC references and command paths. Each
native process authenticates and validates the entire payload before injecting
keys into its own process. No plaintext User key is written. Existing key files
are imported, never silently overwritten. Missing, corrupt, incomplete or
unexpected key files fail closed as `LOCAL_KEYS_INVALID` before stores are opened.

`-NoPersistEnvironment` remains a hermetic process-only installer mode and does
not create a protected file or touch User environment values. Add
`-UseProtectedKeyFile` to validate a DPAPI installation without registering any
User environment values; `-Launch` starts its daemon with those process references. Run the installer
in the same shell with `-Launch` if the daemon must inherit those process keys.

## Legacy migration boundary

An existing configuration without a protected key file reports
`LEGACY_KEYS_MIGRATION_REQUIRED`. The installer does not infer that a process or
User key belongs to that database, mint replacements, delete HKCU values, or
rekey a real database. Before an operator authorizes migration:

1. Stop the installation's daemon and retain its exact binaries/configuration.
2. Back up the full data root and capture a protected backup of the matching keys
   on the owning Windows account, without printing or logging values.
3. Test reopening a copy with its matching keys and capture redacted counts and
   integrity/replay results. An unrelated key must fail to open it.
4. Prepare the new protected file using the same existing keys, validate it on
   copied stores, and obtain approval for that specific migration and any HKCU
   plaintext deletion. A file-only protection change need not rekey databases.
5. Retain the matching old data/key backup and restoration instructions. On a
   failed migration, restore the matching configuration, database and key set;
   never create a new database to hide a failure.

The DPAPI file alone cannot be decrypted under an unrelated Windows account.
Backups need the account's Windows/DPAPI recovery material or a separately
approved protected export. Key protection is not external API-key rotation or
release approval. This batch supplies engineering and isolated tests; it does
not perform any legacy-user migration, HKCU deletion or database rekey.
