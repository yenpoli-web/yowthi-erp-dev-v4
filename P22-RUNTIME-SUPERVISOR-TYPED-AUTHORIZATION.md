# P22 — Runtime Supervisor Typed Deployment Authorization

## Objective

Define a platform-transparent, typed deployment authorization contract for YowThi Runtime Supervisor without changing the currently deployed runtime-control workers in this phase.

## Phase A scope — contract/data-plane only

This phase MAY:

- Define immutable deployment request and authorization-envelope schemas.
- Bind one request to exact current Agent runtime SHA-256, exact target staged release SHA-256, exact Supervisor binary SHA-256, exact loopback listen/health endpoints, and a request identifier.
- Record explicit `processAuthorization=false` and `requiresDedicatedSupervisorExecutor=true`.
- Expose request-only MCP plan/execute tools that create immutable JSON under a dedicated fixed queue that is NOT consumed by the current Runtime Supervisor.
- Expose read-only status/validation for those request records.
- Add acceptance tests that prove this phase cannot write `.agent3-handoff\ready`, cannot stop/start/kill processes, and cannot mutate Windows services.

This phase MUST NOT:

- Create, modify, or delete `.agent3-handoff\ready`.
- Consume or modify the existing r29 pending handoff.
- Start, stop, restart, terminate, or replace any Agent or Runtime Supervisor process.
- Stop/start/reconfigure Windows services.
- Change RuntimeSupervisorWorker or RuntimeHandoffActivationWorker.
- Treat creation of a deployment request as process authorization.
- Provide a generic process or service mutation escape hatch.

## Fixed queue

`C:\Dev\YowThi-ERP-Dev-v4\.runtime-supervisor-deployment\requests`

The current Runtime Supervisor has no consumer for this queue. Therefore creation of a request is inert with respect to runtime/process/service state.

## Future Phase B prerequisite

A future deployment executor must be a dedicated typed capability with an explicit platform-visible contract. It must independently revalidate the sealed request, current/target runtime identities, Supervisor identity, queue state, loopback endpoint identity, and explicit user authorization immediately before any process/service mutation.

P22 Phase A does not implement that executor.
