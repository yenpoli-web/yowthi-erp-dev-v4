# P28 — Dedicated Runtime Deployment Executor v2

## Objective

P28 introduces a standalone, narrowly scoped runtime deployment executor for the Formal Agent runtime. It is not an MCP tool and it does not make a P27 request sufficient to change process state.

## Control-plane separation

The P27 request remains inert and carries:

- `processAuthorization=false`
- `requiresDedicatedSupervisorExecutor=true`

P28 consumes only a separate immutable authorization record from the fixed directory:

`C:\Dev\YowThi-ERP-Dev-v4\.runtime-supervisor-deployment\authorized`

The authorization must bind the exact P27 request SHA-256 and must explicitly carry `processAuthorization=true`. Authorization lifetime is bounded to at most ten minutes and may not outlive the request it authorizes.

P28 does not implement the component that creates authorization records and does not expose an MCP endpoint that invokes the executor. Those are separate control-plane concerns.

### Parent-authorizer execution gate

An authorization JSON file alone is intentionally insufficient. The executor has a module-initializer guard that requires its direct parent process to be the fixed local executable:

`C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentAuthorizer.exe`

The guard verifies the parent executable path, rejects reparse points, and verifies its exact SHA-256 before executor `Main` can run. P28 intentionally ships with an all-zero unprovisioned authorizer SHA sentinel, so the executor always rejects execution in P28. A later independently reviewed phase must build and install the local authorizer and then replace that sentinel with its exact reviewed SHA-256 before deployment can become possible.

This prevents composing the existing generic file-create and process-start capabilities into a runtime-deployment bypass: a forged authorization file plus direct executor launch still fails before `Main`.

## Single lifecycle owner

The Runtime Supervisor remains the owner of Formal runtime start/stop behavior. The executor does not call `Process.Start` or `Process.Kill` for the Agent runtime.

The deployment sequence, once the parent-authorizer identity is provisioned in a later phase, is:

1. Revalidate authorization, bound request SHA-256, current runtime DLL/SHA/PID, target release DLL/SHA, loopback endpoint, Runtime Supervisor executable/SHA, and executor executable/SHA.
2. Require exact current runtime SHA-256 from the loopback `/health` endpoint immediately before mutation.
3. Stop the fixed `YowThiV4RuntimeSupervisor` Windows service through the native Service Control Manager.
4. Prove the currently authorized runtime PID has exited.
5. Atomically replace `active-runtime.json` with a target slot whose PID is zero and whose `previous` slot is the prior current runtime.
6. Restart the fixed Runtime Supervisor service.
7. Allow the Supervisor to start the target Agent runtime and recover tunnels.
8. Require exact target runtime SHA-256 from `/health` and require active-state read-back with a positive target PID.
9. Emit one immutable terminal completion result and retire the authorization record.

## Rollback

If target activation or verification fails after mutation begins, the executor:

1. Stops the Runtime Supervisor if necessary.
2. Restores the previously sealed active-runtime state.
3. Restarts the Runtime Supervisor.
4. Requires exact previous runtime SHA-256 health.
5. Emits an immutable failed terminal result containing whether rollback was proven healthy.

A failure whose rollback cannot be proven healthy remains a hard failure.

## Safety invariants

- No shell, PowerShell, cmd, generic command executor, or caller-selected executable is used.
- No direct Agent `Process.Start`, `Process.Kill`, or arbitrary PID termination is used.
- No `.agent3-handoff\ready` record is created, modified, or consumed.
- The legacy r29 pending handoff `776317640d1948cb80afa47c7149c852` is not consumed or modified by P28 development or validation.
- Runtime, Supervisor, request, authorization, executor, and parent-authorizer identities are revalidated before mutation.
- Terminal result existence prevents authorization replay.
- P28 source publication alone does not deploy or activate a new Formal runtime.
- P28 is intentionally non-activatable while the authorizer SHA sentinel remains unprovisioned.

## P28 publication boundary

P28 is accepted when the executor project builds, contract tests pass, the self-hosted workflow builds the executor explicitly, and existing gates remain green. Deployment remains unavailable until a separately authorized local control-plane component is built, reviewed, installed, and cryptographically pinned into the executor's parent-authorizer gate.
