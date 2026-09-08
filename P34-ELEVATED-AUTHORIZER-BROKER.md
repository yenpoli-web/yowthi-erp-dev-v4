# P34 — Elevated Runtime Deployment Authorizer Broker

## Purpose

P34 closes the Windows privilege boundary discovered during the first P33 interactive r28 → r32 cutover attempt.

The P33 approval identity was correct and the CurrentUser signer and authorizer signature chain succeeded. The dedicated executor did not create a terminal result because it was launched with the ordinary interactive Explorer token and could not acquire Runtime Supervisor service start/stop access through the Windows Service Control Manager.

The failed P33 transaction was archived before cleanup as:

`acceptance\p33-failed-cutover-evidence-20260908T0546Z.zip`

SHA-256:

`A5C7B872CF2255D38796182F024F2D204EA99452AAE0DFE3B86B8BEB13241D66`

The archive contains the P27 request, two signed approvals, two authorizations, signer terminal evidence, and authorizer failure terminals. r28 remained healthy and the Runtime Supervisor was never stopped by the failed attempts.

## Elevated authorization boundary

The independent approval chain remains:

Explorer → Approval Bridge → CurrentUser non-exportable ECDSA P-256 Signer → Authorizer.

P34 adds one Windows UAC boundary between the Authorizer and the dedicated Executor:

Authorizer → Windows `runas` UAC → Elevated Authorizer → Dedicated Executor → Runtime Supervisor.

The private signing key remains CurrentUser scoped and is not moved into the elevated process, repository, ProgramData package, Agent, prompt, command arguments, or logs. The elevated Authorizer consumes only the already-signed approval JSON.

## Elevation gate

`src\YowThi.RuntimeDeploymentAuthorizer\ElevationGate.cs`

The module-load elevation gate requires all of the following before `runas` can be requested:

- Windows host.
- Exactly one approval argument.
- The approval is one existing direct `.json` child of the fixed `.runtime-supervisor-deployment\approvals` root.
- The approval is not a reparse point.
- The current executable is exactly `C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentAuthorizer.exe`.
- The installed Authorizer executable is not a reparse point.
- Elevation state is read from the actual process token using `OpenProcessToken(TOKEN_QUERY)` → `GetTokenInformation(TokenElevation)` → `CloseHandle`.
- If the current Authorizer token is already elevated, no second elevation is requested.
- Otherwise the fixed Authorizer executable is relaunched with `UseShellExecute=true` and `Verb=runas`, with only the fixed approval path as argument.
- UAC cancellation propagates as Win32 error 1223 / non-zero process exit.

The gate accepts no caller-selected executable, working directory, command shell, PowerShell, generic managed-process tool, or arbitrary argument vector.

## Executor parent identity

The dedicated Executor remains protected by its direct-parent guard. P34 repins the fixed Authorizer artifact used by that guard.

Final executable identities:

- Approval Bridge: `EAA32076285F957FB08A5D34C5252DF95F546981F51EFF5681BBEAF60A6A6AAB`
- Signer: `BB603C9EC44EB9E8C120D3A8361D8E7D8E7D99A87A02DFB91D9F1C5808346C36`
- Authorizer: `EC6CAE1D23127EA59D67F5EB3C380B59144C24A47B6C974350313501B4FD17CD`
- Executor: `B2B2D52B3EAF28EF48B17595E806789A76FF9FC5636CD5157D0601C61F7861F1`

Final changed DLL identities:

- Authorizer DLL: `0A7E25136F4B66F6D5CDAC0D8F6E5E65C68C94BDFED0E5B812AD7C553BE44DBE`
- Executor DLL: `73B043809ECBC54E437C41AB977ACEF9CE35010F0A29BC317479B422AC5F009F`

## Terminal outcome correctness

P34 also closes a result-propagation defect identified while reading the failed P33 chain.

The Authorizer now treats an Executor failed terminal as an Authorizer failure. Only the combination of:

- exactly one Executor completed terminal,
- no Executor failed terminal, and
- Executor process exit code 0

may create an `authorizer-completed` terminal with `status=completed`.

An Executor failed terminal, a missing/ambiguous terminal, or a non-zero Executor exit code causes the Authorizer to return non-zero and write its own failed terminal. The previous `executor-failed` value is no longer accepted as an Authorizer completed result.

The Authorizer also preserves the strict loopback-only `/health` endpoint validation used by the deployment request and active runtime identity checks.

## Acceptance

Local P34 build gates:

- Authorizer Release build: 0 warnings / 0 errors.
- Executor Release build: 0 warnings / 0 errors.
- Acceptance project Release build: 0 warnings / 0 errors.
- Acceptance suite: 43 passed / 0 failed / 0 skipped.

ProgramData installation, exact-SHA readback, and the next real interactive r28 → r32 deployment approval remain separate post-CI acceptance steps. The real Approval Bridge and subsequent UAC consent must still be performed by the interactive user from Windows Explorer.
