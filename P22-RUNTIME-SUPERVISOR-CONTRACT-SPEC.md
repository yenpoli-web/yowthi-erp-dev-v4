# P22 — Runtime Supervisor Contract Specification

## Scope

This branch is documentation/schema only. It does not add MCP tools, queue writers, Runtime Supervisor workers, process-control code, service-control code, or runtime activation behavior.

The executable P22 request-only implementation remains preserved only on the local branch `p22-runtime-supervisor-deployment-authorization-validation` and is not part of this specification branch.

## Deployment request envelope

A future typed deployment request SHOULD bind the following immutable identities:

- `schemaVersion`
- `requestId`
- `releaseName`
- `currentRuntimeDll`
- `currentRuntimeSha256`
- `currentProcessId`
- `targetRuntimeDll`
- `targetRuntimeSha256`
- `listenUrl`
- `healthUrl`
- `supervisorExe`
- `supervisorSha256`
- `processAuthorization=false`
- `requiresDedicatedSupervisorExecutor=true`
- `createdUtc`
- `expiresUtc`

## Safety invariants

1. A deployment request is data only and is not process authorization.
2. Creating or validating a request must not create, modify, consume, or delete `.agent3-handoff\ready`.
3. A request must not start, stop, restart, terminate, signal, or replace any process.
4. A request must not install, uninstall, start, stop, or reconfigure any Windows service.
5. The existing r29 pending handoff must remain untouched.
6. A future executor must be a dedicated typed capability with a platform-visible contract and explicit user authorization.
7. The future executor must revalidate current runtime identity, target runtime identity, Runtime Supervisor identity, fixed loopback endpoint identity, request integrity, and authorization immediately before any mutation.
8. Generic process, service, shell, PowerShell, desktop-input, or filesystem mutation tools are not substitutes for the dedicated executor.

## Publication boundary

Publishing this specification does not publish or enable an executor. No runtime transition can occur from these files.
