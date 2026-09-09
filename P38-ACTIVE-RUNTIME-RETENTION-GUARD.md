# P38 — Active Runtime Retention Guard

## Purpose

Close the lifecycle-retention safety gap discovered during r32 burn-in: a staged release referenced by the authoritative active-runtime state must never be classified disposable merely because it is not the currently executing assembly, is not referenced by a pending lifecycle request, and is outside the two-newest retention window.

## Burn-in baseline

At P38 entry, r32 had remained healthy since the successful P35 cutover at 2026-09-09T01:01:04Z. Boot recovery acceptance remained accepted with no failure reasons, pending lifecycle request count was zero, and the active state was schema v2 with:

- current: r32 / SHA-256 `1436E68D7D0E67BA9656AC8911A94CBFB78AAFAD6EC6A1E0BD7AD31BCE8D73B7`
- previous: r28 / SHA-256 `93F1E53C1A9F085475CEB9E2ED651C0C42876EB7AFDD31D89685C0FAD9A0396B`

The old retention inventory incorrectly classified r28 as `eligible` even though the authoritative active-state still referenced it as `previous`.

## Safety contract

Release retention now fails closed on the fixed authoritative state file:

`C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\active-runtime.json`

For release cleanup only:

1. active-runtime state must exist, be a non-reparse bounded JSON file, and have schemaVersion 2;
2. `current` is required and `previous` may be null;
3. each populated slot must resolve to one direct staged release under the fixed release root;
4. each slot must point to `YowThi.DevelopmentAgent3.dll` and the on-disk DLL SHA-256 must exactly match the state;
5. any release referenced by active-state `current` or `previous` is protected;
6. cleanup planning seals the exact active-state file SHA-256 as `activeStateFingerprint`;
7. cleanup execution re-reads the active state immediately before deletion, rejects any fingerprint change, and rechecks that the target did not become current/previous;
8. deletion remains native `File.Delete` plus non-recursive `Directory.Delete`; no shell, PowerShell, cmd, generic executor, or force deletion is introduced.

Rollback-backup retention remains independent because active-state slots reference staged releases, not rollback-store packages.

## Retirement rule

r28 must not be deleted while it remains the active-state `previous` release. P38 does not manually edit active-runtime state. The safe retirement path is a subsequent validated runtime deployment that advances the authoritative slots naturally, for example `current=r33 / previous=r32`; only after that state is proven healthy may the new retention guard classify r28 disposable.

## Local verification

- Agent Release build: 0 warnings / 0 errors
- Acceptance Release build: 0 warnings / 0 errors
- Acceptance tests: 52 passed / 0 failed / 0 skipped

No runtime cutover, active-state mutation, or r28 deletion is part of this source change.
