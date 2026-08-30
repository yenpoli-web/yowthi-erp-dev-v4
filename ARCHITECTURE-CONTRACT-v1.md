# YowThi ERP Dev v4 / YowThi Development Agent 3.0
## Architecture Contract v1

Status: Draft for formal acceptance
Date: 2026-08-28

## 1. Purpose
Build a new development-control plugin and local agent architecture that provides broader capability than YowThi ERP Dev v3 / Agent 2.7.4 while eliminating the generic shell execution model that caused recurring platform safety blocks in v2/v3.

## 2. Non-negotiable architecture rules
1. Core operations MUST use native typed executors.
2. No production control path may depend on a generic `admin_execute` that accepts or dispatches arbitrary PowerShell/cmd commands.
3. Signed plans MUST describe the real operation directly: tool, operation, target, parameters, risk class, expiry, and signature.
4. Execution MUST revalidate target, parameters, protected-path policy, expiry, signature, and unused state.
5. Successful plans are one-time and consumed atomically.
6. Every plan prepare / approve / execute / reject / mismatch / failure MUST be written to a tamper-evident audit chain.
7. Protected production root `C:\yowthi-erp` is read-only unless a future explicit production-deployment contract authorizes a narrowly scoped typed operation.
8. Generic shell access, if retained for diagnostics, MUST be isolated from the normal ChatGPT tool catalog and MUST NOT be required by core ERP-development workflows.

## 3. Plan model
A signed plan contains no shell command body.

Required fields:
- schemaVersion
- planId
- approvalCode
- tool
- operation
- target
- parameters
- riskClass
- summary
- createdUtc
- expiresUtc
- signature

The signature MUST cover every execution-relevant field.

## 4. Executor model
Each capability owns a typed executor. Examples:
- file_delete -> native filesystem API
- directory_delete -> native filesystem API
- service_stop -> Windows service API
- process_stop -> process API
- git_checkout -> Git-specific executor with structured arguments
- docker_remove_container -> Docker-specific executor with structured arguments
- postgres_migrate -> PostgreSQL-specific executor with structured migration parameters

No executor may translate an arbitrary caller-provided command string into PowerShell/cmd execution.

## 5. Capability targets
The v4 catalog must exceed the functional coverage of the v3 85-tool catalog.

Capability domains:
1. Filesystem: read, write, patch, copy, move, delete, directory operations, search, metadata, hash, large-file scan, archives.
2. Git/GitHub: status, diff, branch, checkout, commit, fetch, pull, push, merge, tag, remote inspection and controlled updates.
3. Docker: containers, images, volumes, networks, compose, build, logs, health, controlled exec where safely typed.
4. PostgreSQL: server status, database/role/schema inspection, migration, backup, restore, query, seed, acceptance checks.
5. Windows: services, processes, scheduled tasks, environment, registry, event logs, update status and controlled actions.
6. Network: ports, DNS, Tailscale, connectivity, firewall.
7. Development: .NET build/test/publish, Node/npm, Python, linting, integration tests.
8. Workspace: create workspace, inspect tree, enforce workspace boundaries, project metadata, artifact handling.
9. Agent lifecycle: version, health, backup, verify, update, rollback, diagnostics.
10. Jobs: long-running tasks, status, logs, cancellation.
11. Transfer: staged upload/download, checksum verification, safe extraction.
12. Desktop automation: launch, window, input and clipboard only where explicitly necessary.
13. ERP engineering: schema migration, seed data, integration tests, deployment staging, database acceptance, release checks.

## 6. Risk model
Risk classes: low, medium, high, critical.
Risk class is determined server-side from operation type and target context, never trusted from caller input.
High/critical operations require explicit user approval and exact signed-intent match.

## 7. Protected-path policy
Default protected root: `C:\yowthi-erp`.
Rules:
- Reads allowed when needed for migration/reference analysis.
- Writes, deletes, moves, registry/service changes tied to production are denied by default.
- Any future production deployment must use dedicated deployment executors with explicit release scope and rollback support.

## 8. Capability gates
### P0 — Control Plane
- plan signing
- approval model
- one-time consumption
- expiry
- exact intent validation
- audit chain
- protected paths
- no generic shell dependency

### P1 — Filesystem
Acceptance sequence, all native typed operations:
1. create file
2. read file
3. modify file
4. copy file
5. move file
6. delete file
7. verify audit chain
8. verify protected-root denial

P1 is a hard gate. If any core operation requires generic shell execution, P1 fails.

### P2 — Development
Git + build/test/publish + workspace operations.

### P3 — Infrastructure
Docker + PostgreSQL + Windows + network.

### P4 — Operations
Transfers + archives + jobs + backup/restore + agent lifecycle.

### P5 — ERP Engineering
Migrations + integration tests + deployment staging + release acceptance.

## 9. Platform-compatibility acceptance
A capability is not accepted merely because it works locally.
It must also execute consistently through the ChatGPT/App tool path without recurring platform safety blocks caused by over-broad tool semantics.

## 10. Migration policy
- Agent 2.7.4 remains available only as bootstrap/reference/rollback during v4 development.
- Do not extend 2.7.x with new architectural features.
- New v4 source must live under `C:\Dev\YowThi-ERP-Dev-v4`.
- Do not reuse legacy runtime executor code that depends on generic PowerShell/cmd dispatch.

## 11. Initial implementation order
1. Create Agent 3.0 solution skeleton.
2. Implement signing + plan store + audit chain.
3. Implement native filesystem executors.
4. Run P0/P1 acceptance through the actual ChatGPT/App path.
5. Only after P1 passes, expand to Git, Docker, PostgreSQL and Windows capability domains.

## 12. Definition of success
YowThi ERP Dev v4 is successful when it provides more functional coverage than v3, while core privileged operations remain narrowly typed, auditable, one-time, protected-path aware, and platform-compatible without relying on a universal shell execution gateway.
