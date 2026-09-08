# P35 — Managed Payload Identity Binding

## Objective

Close the framework-dependent .NET apphost identity gap by binding each runtime-deployment executable together with its sibling managed DLL.

An EXE SHA-256 match alone is not sufficient evidence of the managed code being executed. P35 therefore requires EXE + managed-DLL identity throughout the interactive approval, signing, authorization, parent-guard and executor pre-main validation chain.

## Fixed P35 artifact identities

### Approval Bridge
- EXE: `D5DBDC7F12FEA22C0DBB140D0809381F70754DAC3BECA02F83519EFA74CA431B`
- DLL: `8E9BA46CB8BC950475AA01612DE7C24C104B06D3B0B74EA6C19E3A6EC6C20E99`

### Signer
- EXE: `99ABCA56DED0DA3994A4F04D1650C06E6BA3A69C17D281B27DB1D6B6F7002091`
- DLL: `BB853313DD8977A938A9DD2168E6FB3D96B7CD9E26BF5895EFF1840732F63168`

### Authorizer
- EXE: `61587C8AE9A58BDA0BD68199A99FBD4D60A544E70690730127E81F57FBF3408E`
- DLL: `CB9A4EA443CD98E33AFE7AD8BD81B05C5AF827DD35281253F5DBB4BB87B744A6`

### Executor
- EXE: `73F79CBED40087D4AB29480A72469620CDFA1F2310509DCA4DD3298EB57BCB0B`
- DLL: `1443E9281707C8433A4BC83D8B949FCDE5825B9EADE430960D5E199B8082853A`

All four component Release builds completed with zero warnings and zero errors.

## Contract changes

1. Activated package schema is upgraded to schema version 3.
2. Every signer / authorizer / executor component requires:
   - `installFileName`
   - `exeSha256`
   - `managedDllFileName`
   - `managedDllSha256`
3. Approval Bridge binding also requires its EXE and managed DLL identities.
4. Signing intent includes `executorDllSha256`.
5. CurrentUser ECDSA signer validates installed Executor EXE + DLL and signs both identities.
6. P29 approval canonical payload contains `executorSha256` followed by `executorDllSha256`.
7. Authorizer verifies the same canonical payload, revalidates Executor EXE + DLL and copies both identities into the P28 authorization.
8. Executor parent guard pins Authorizer EXE + DLL.
9. Signer parent guard pins Approval Bridge EXE + DLL.
10. `ManagedPayloadAuthorizationGate` runs as an Executor module initializer and validates the signed authorization, fixed ProgramData Executor EXE and fixed sibling Executor DLL before `Main`.

## Existing security boundaries preserved

- CurrentUser non-exportable ECDSA P-256 signing key remains the approval root.
- Approval Bridge remains active-console / Explorer-parent / explicit-Yes gated.
- Authorizer UAC `runas` elevation remains fixed to the ProgramData Authorizer and fixed approval-root JSON.
- Runtime and health endpoints remain loopback-only.
- Supervisor remains the single runtime lifecycle owner.
- Executor failure terminal results continue to propagate failure to Authorizer / Bridge.
- No legacy `.agent3-handoff\ready` activation path is reintroduced.
- No generic PowerShell, shell, managed-process or service composition is accepted as a substitute for this chain.

## Local acceptance

- Acceptance project build: 0 warnings / 0 errors.
- Full acceptance suite: 48 passed / 0 failed / 0 skipped.
- P35 adds explicit regression coverage for package-v3 managed-DLL identities, signed Executor EXE+DLL propagation, parent EXE+DLL guards and Executor pre-main managed-payload authorization.

## Publication boundary

P35 source publication does not itself install any new deployment binary into `C:\ProgramData\YowThi\RuntimeDeployment` and does not perform a runtime transition.

The active Formal runtime remains r28 until P35 exact-SHA CI succeeds, source is promoted to main, ProgramData is reinstalled/read back with the P35 EXE+DLL identities, and the user performs a fresh Explorer approval plus Windows UAC approval for the retained r28 -> r32 request.
