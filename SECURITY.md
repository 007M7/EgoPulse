# Security policy

EgoPulse is in foundation development and has no production release.

## Baseline rules

- Secrets belong in the operating-system credential store, never source, logs or ordinary configuration.
- Desktop capabilities follow least privilege.
- Workers and Harnesses receive per-Attempt filesystem, network, tool and time budgets.
- External input is validated at the process or contract boundary.
- Authority decisions are server-side and cannot be replaced by UI or model output.
- Telemetry must not collect Prompt, Memory or Artifact bodies by default.

Security reports should be sent privately to the repository owner. Do not open a public issue containing exploit details or sensitive data.
