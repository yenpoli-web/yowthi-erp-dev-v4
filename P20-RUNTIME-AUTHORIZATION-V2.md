# P20 — Runtime Authorization v2

## Purpose

P20 replaces the current MCP-side handoff activation authority with an approval-separated runtime authorization flow. The objective is not to rename or rephrase an operation to evade platform safety controls. The objective is to reduce MCP authority so that an MCP call cannot directly create a Supervisor-consumable ready authorization and cannot directly or indirectly cause a runtime process transition by itself.

## Current state and blocker

The current `runtime_handoff_activate_execute` validates a sealed pending handoff and writes an immutable JSON record under `.agent3-handoff\ready`. The Runtime Supervisor monitors that ready queue and can then perform the process cutover. Although the MCP method itself does not call process stop/start APIs, creation of the ready record is causally sufficient to authorize the Supervisor transition and is therefore correctly treated as a high-risk runtime-control action.

The current P19 candidate is staged as r29. The existing pending handoff `776317640d1948cb80afa47c7149c852` remains intact and must not be consumed, rewritten, copied to ready, or otherwise activated by P20 development or validation.

## Security properties

1. MCP request creation alone MUST NOT create any file under `.agent3-handoff\ready`.
2. MCP request creation alone MUST NOT stop, start, restart, terminate, signal, or otherwise modify any process or Windows service.
3. MCP request creation alone MUST NOT be sufficient for the Runtime Supervisor to change the active runtime.
4. The current runtime SHA-256, current process identity, pending manifest SHA-256, candidate runtime SHA-256, fixed loopback URLs, and fixed queue identities must be sealed and revalidated.
5. Requests are immutable CreateNew files; overwrite, arbitrary paths, arbitrary runtime DLLs, and caller-selected queue roots are prohibited.
6. A second approval must come from a local administrative control plane that is not exposed as an MCP tool to ChatGPT.
7. The local administrative approval must bind to the exact MCP request SHA-256 and the same current/candidate identities before creating a Supervisor-consumable ready authorization.
8. The Runtime Supervisor must reject missing, stale, mismatched, replayed, or multiply approved requests.
9. Existing production protection and `C:\yowthi-erp` exclusion remain unchanged.
10. No shell, PowerShell, cmd, arbitrary process execution, generic file write, or manual ready-file construction may be used as a substitute for the typed flow.

## Proposed flow

### Phase A — MCP request only

New typed MCP capability:

- `runtime_handoff_approval_request_plan(handoffPlanId)`
- `runtime_handoff_approval_request_execute(planId, approvalCode)`

The execute operation creates one immutable request record under a fixed `.agent3-handoff\approval-requests` root. It does not write to `.agent3-handoff\ready`.

The request contains only bounded authorization metadata required for later local approval, including:

- schema version
- request plan ID
- handoff plan ID
- pending manifest SHA-256
- current runtime SHA-256
- current process ID/start identity as applicable
- candidate runtime SHA-256
- fixed listen/health identity
- created/expiry timestamps

### Phase B — local administrative approval

A separate local administrative component, not registered as an MCP tool, reviews one exact request and creates the Supervisor-consumable ready authorization only after explicit local administrative confirmation.

The local approval must revalidate:

- exact request SHA-256
- exact pending manifest SHA-256
- pending handoff still present and immutable
- candidate package is one direct staged release
- candidate DLL SHA-256
- current active runtime SHA-256 and process identity
- ready target absence
- request not expired or previously consumed

### Phase C — Runtime Supervisor

The Runtime Supervisor consumes only a locally approved ready authorization. Its process transition and health/rollback behavior remain separately bounded and must not be callable by the MCP request tool.

## Acceptance gates

P20 is accepted only when all of the following are proven:

1. Source diff is limited to the P20 authorization/control-plane implementation and necessary tests/documentation.
2. Agent and Runtime Supervisor builds complete with zero errors.
3. Existing acceptance tests remain green.
4. New tests prove an MCP approval request creates no ready file.
5. New tests prove an MCP approval request causes no runtime PID/SHA change during an observation window.
6. New tests prove the Runtime Supervisor ignores an unapproved request.
7. New tests prove a locally approved record is rejected if request, pending manifest, current runtime, or candidate SHA differs.
8. Replay and overwrite attempts are rejected.
9. The existing pending handoff `776317640d1948cb80afa47c7149c852` is unchanged throughout P20 validation.
10. No use is made of generic filesystem mutation, manual ready-file creation, runtime_stop/start, process_stop/start, PowerShell, or shell as a workaround for the blocked activation path.

## Deployment constraint

P20 code must not be used as a mechanism to bypass the current platform block on r28 → r29 activation. Until an independently authorized deployment path exists, r28 remains the active healthy runtime and r29 remains staged. P20 may be developed, tested, reviewed, and published to source control without changing the active runtime.
