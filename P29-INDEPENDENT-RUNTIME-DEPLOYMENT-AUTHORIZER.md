# P29 — Independent Runtime Deployment Authorizer

## Objective

P29 adds a standalone local authorizer between the inert P27 deployment request and the P28 dedicated runtime deployment executor. The authorizer does not itself stop/start the Formal runtime or the Runtime Supervisor. It validates an independently signed approval, emits one short-lived P28 authorization, and launches only the fixed P28 executor as its direct child.

## Approval boundary

The authorizer accepts exactly one approval JSON file under:

`C:\Dev\YowThi-ERP-Dev-v4\.runtime-supervisor-deployment\approvals`

The approval binds:

- exact approval ID / nonce
- exact P27 request ID and request SHA-256
- exact P28 executor SHA-256
- fixed signer key ID `p30-runtime-deployment-signer-v1`
- issue/expiry timestamps with a maximum five-minute approval lifetime
- ECDSA P-256 signature over a deterministic canonical payload

The authorizer verifies the embedded signer public-key SPKI SHA-256 before any approval can be accepted.

## P29 fail-closed state

P29 intentionally ships with an empty signer public key and an all-zero signer SPKI SHA-256 sentinel. A module initializer rejects execution before `Main` whenever that signer identity is unprovisioned or mismatched.

Therefore P29 publication does **not** make runtime deployment possible, even if the authorizer executable is started directly by an existing generic process capability. P30 must independently provision the signer public key and exact SPKI SHA-256 before any approval can pass.

## Authorizer sequence after future signer provisioning

1. Validate the approval path is one direct JSON child of the fixed approvals root.
2. Validate approval identity, nonce, lifetime and signer key ID.
3. Verify ECDSA P-256 signature over the canonical approval payload.
4. Read the exact P27 request and require its SHA-256 to equal the signed approval binding.
5. Require P27 `processAuthorization=false` and `requiresDedicatedSupervisorExecutor=true`.
6. Revalidate active runtime DLL/SHA/PID and loopback endpoint against the request.
7. Revalidate target release DLL/SHA and fixed Runtime Supervisor executable/SHA.
8. Revalidate the fixed P28 executor at `C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.exe` against the signed executor SHA-256.
9. Emit one immutable P28 authorization with `processAuthorization=true`, bounded by the approval, request and a maximum two-minute authorization lifetime.
10. Launch only the fixed P28 executor as a direct child, with only the generated authorization path as its argument.
11. Require exactly one P28 completed/failed terminal result and archive the approval into an authorizer terminal directory.

## Composition-resistance

- An unsigned or forged approval file is rejected.
- Direct authorizer launch is harmless while signer provisioning remains disabled.
- The authorizer cannot select an arbitrary executable: the P28 executor path is fixed in source.
- The authorizer cannot select an arbitrary runtime or Supervisor: identities come from the immutable P27 request and current active-state read-back.
- The authorizer never calls Runtime Supervisor service controls and never starts/stops a Formal Agent runtime directly.
- The only `Process.Start` target is the fixed P28 executor.
- The P28 executor independently revalidates request SHA, runtime identities, Supervisor identity, executor identity and its direct-parent authorizer identity before mutation.

## Publication boundary

P29 source publication is accepted when the authorizer project compiles in self-hosted CI, contract tests pass, the workflow explicitly builds the authorizer, and all existing gates remain green.

Because the local build execute was blocked by the platform safety layer during P29 development, P29 does not pin the authorizer executable SHA into P28 and does not install ProgramData binaries. Those packaging/provisioning actions require a verified build artifact and remain deferred. Runtime r28 and the legacy r29 pending handoff must remain untouched.
