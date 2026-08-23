# Contributing

## Change sequence

1. Identify the user outcome, scope and non-goals.
2. Confirm the owning module and dependency direction.
3. Freeze affected contract, state, permission, failure and recovery semantics.
4. Implement the smallest complete vertical change.
5. Run the relevant repository checks.
6. Record migration, compatibility, monitoring and rollback impact.

Technical choices must state why they fit EgoPulse constraints, what alternatives were rejected, and where their costs will be paid. Popularity or familiarity alone is not a decision.

## Rust and SQLCipher checks

Run the repository Rust gate through:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-rust.ps1
```

The SQLCipher build uses vendored OpenSSL and therefore requires Perl plus the Visual C++ build tools on Windows. The script accepts Perl already on `PATH` and also detects the standard Strawberry Perl location. It fails with an explicit prerequisite error instead of silently replacing SQLCipher with plaintext SQLite.

## Branches and commits

- Keep commits scoped and reviewable.
- Do not mix generated files, unrelated refactors and behavior changes without a reason.
- Never commit credentials, runtime state, model weights or personal data.
