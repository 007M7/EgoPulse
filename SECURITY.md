# Security policy

EgoPulse is in foundation development and has no production release.

## Baseline rules

- Secrets belong in the operating-system credential store, never source, logs or ordinary configuration.
- Desktop capabilities follow least privilege.
- Workers and Harnesses receive per-Attempt filesystem, network, tool and time budgets.
- External input is validated at the process or contract boundary.
- Authority decisions are server-side and cannot be replaced by UI or model output.
- Telemetry must not collect Prompt, Memory or Artifact bodies by default.

## Unsigned early-access packages

Until a Windows code-signing certificate is available, any published Windows
early-access package is unsigned. Windows SmartScreen may therefore display an
unknown-publisher warning. Users should download the accompanying `.sha256`
file from the same GitHub release, verify the archive hash locally before
extracting it, and treat a hash mismatch or unexpected publisher prompt as a
reason to stop and report the package rather than bypassing the warning.

Security reports should be sent privately to the repository owner. Do not open a public issue containing exploit details or sensitive data.
