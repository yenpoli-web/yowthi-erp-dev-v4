# P33 — Bootstrap Request Adapter

## Purpose

P33 closes the one-time migration gap between the currently active r28 catalog and the P27→P31→P29→P28 deployment chain. r28 can create the legacy typed lifecycle **request-only** update intent, but does not expose `runtime_supervisor_deployment_request_*` through its active MCP catalog.

The Approval Bridge may therefore promote exactly one eligible lifecycle update request into a short-lived P27-compatible deployment request, but only after independent interactive approval.

## Security boundary

The adapter is part of `YowThi.RuntimeDeploymentApprovalBridge` and inherits its module-load requirement:

- Windows interactive user session only.
- Current process must be in the active console session.
- Direct parent must be Windows Explorer.
- Installed Bridge executable path and SHA-256 must match the activated package manifest.

No P27-compatible request is written before the user selects **Yes** in the Bridge approval dialog.

## Bootstrap input contract

The only bootstrap input is one direct `*-update-request.json` child under:

`C:\Dev\YowThi-ERP-Dev-v4\.agent3-lifecycle\pending`

It must satisfy all of the following:

- `schemaVersion = 1`
- `requestType = agent-lifecycle-transition-request`
- `requestedAction = update`
- `scope = request-only`
- `processAuthorization = false`
- `requiresSeparateRuntimePlans = true`
- file name matches the GUID-N `planId`
- current runtime path/SHA matches active state
- target is one direct staged release under the fixed lifecycle release root
- current and target runtime DLL SHA-256 values validate against disk
- listen/health endpoints match the active loopback runtime

Immediately after the interactive **Yes**, the Bridge re-reads and re-hashes the bootstrap request, revalidates active runtime state, target runtime, endpoints, and the fixed Runtime Supervisor executable, and rejects the transition if a P27 request appeared concurrently.

## Generated P27-compatible request

The generated request is one immutable direct JSON child under:

`C:\Dev\YowThi-ERP-Dev-v4\.runtime-supervisor-deployment\requests`

It binds:

- source lifecycle `planId` as `RequestPlanId`
- new random GUID-N `RequestId`
- target release name
- exact current runtime DLL/SHA/PID
- exact target runtime DLL/SHA
- exact loopback listen/health URLs
- exact Runtime Supervisor executable/SHA
- `ProcessAuthorization = false`
- `RequiresDedicatedSupervisorExecutor = true`
- five-minute request lifetime

Post-write readback requires the generated request to be the only eligible deployment request and requires its bytes/SHA identity to match the in-memory request.

## Downstream chain

After P27-compatible request creation, the existing path is unchanged:

Approval Bridge → CurrentUser Signer → Authorizer → Dedicated Executor → Runtime Supervisor.

The Bridge never starts the Executor directly and does not use legacy `.agent3-handoff\ready` or `runtime_handoff_activate`.

## P33 pinned executable identities

- Approval Bridge SHA-256: `EAA32076285F957FB08A5D34C5252DF95F546981F51EFF5681BBEAF60A6A6AAB`
- Signer SHA-256 after Bridge-parent repinning: `BB603C9EC44EB9E8C120D3A8361D8E7D8E7D99A87A02DFB91D9F1C5808346C36`
- Authorizer remains: `7BD1F5AEFD057B06E420C2A4E20E7A3BB5A3A9F28C9A0AE324AF4F19A11E9AFE`
- Executor remains: `4A10CE0E0FD85704191E7C5580CCD4F1D29A106AD28DDF35EFD2FB0B3DBB2398`

ProgramData installation and actual runtime cutover remain separate acceptance steps. The Bridge must still be manually launched from Explorer by the interactive user for the real deployment approval.
