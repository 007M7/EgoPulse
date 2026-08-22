# Contributing

## Change sequence

1. Identify the user outcome, scope and non-goals.
2. Confirm the owning module and dependency direction.
3. Freeze affected contract, state, permission, failure and recovery semantics.
4. Implement the smallest complete vertical change.
5. Run the relevant repository checks.
6. Record migration, compatibility, monitoring and rollback impact.

Technical choices must state why they fit EgoPulse constraints, what alternatives were rejected, and where their costs will be paid. Popularity or familiarity alone is not a decision.

## Branches and commits

- Keep commits scoped and reviewable.
- Do not mix generated files, unrelated refactors and behavior changes without a reason.
- Never commit credentials, runtime state, model weights or personal data.
