# Phase 2-08 Process supervision fault evidence

## Status

Implemented for the Windows x64 release target. This evidence closes the
real-child fault slice of the generic Worker process boundary; it does not
claim that a Memory Worker or a specific Harness is production-wired.

## Real-child matrix

The integration suite launches the Windows PowerShell executable through the
same `SupervisedProcessSpec` path used by a Worker. It proves:

| Scenario | Expected result |
|---|---|
| one valid framed response | opaque response payload returned |
| truncated framed response | `Protocol`, fail closed |
| non-zero child exit | `Crashed` |
| child exceeds deadline | `Timeout` |
| child exceeds stdout budget | `OutputLimit` |
| caller cancels the exchange | child PID is terminated by `kill_on_drop` |

The tests intentionally use a system executable only as a deterministic test
fixture. Timeout performs an explicit terminate-and-reap before returning;
caller cancellation is verified against the real Windows PID after the
exchange future is dropped. Production Workers remain explicit absolute
executable paths with their own working directory, environment policy, native
protocol and approved business contract.

## Boundary interpretation

These tests establish process-lifecycle guarantees, not semantic correctness
of a Worker. A future Worker vertical must add its own schema validation,
request/response evidence binding and cancellation/recovery assertions on top
of this reusable boundary.
