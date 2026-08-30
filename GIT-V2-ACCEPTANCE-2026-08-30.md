# YowThi ERP Dev v4 — Git v2 Acceptance

Date: 2026-08-30

## Accepted backend

- Repository: `C:\Dev\YowThi-ERP-Dev-v4`
- Branch: `main`
- Baseline commit: `0e5363aa5fa20e643832640b3a21f6c254dd69c2`
- Safe-directory hardening commit: `fdd1ac0045de3e1a34909d68880d2121fea783b7`
- Accepted runtime build: `C:\Dev\YowThi-ERP-Dev-v4\acceptance\git-safe-directory-v1-build\YowThi.DevelopmentAgent3.dll`
- Runtime endpoint: `http://127.0.0.1:8808`
- Runtime SHA-256: `A97004D37DB44D32A38DA93FC91F7C12B7648762BBBB3CA6C493D0B41D0E450A`
- Runtime health: `ok`
- Git tunnel profile: `C:\ProgramData\YowThi\TunnelClient\profiles\yowthi-erp-git-v1-8803.yaml`
- Tunnel target: `http://127.0.0.1:8808/mcp`
- Tunnel ID: `tunnel_6a8c65350d348191a50d28397d063783`

## Hardening result

`GitTools.cs` and `GitV2Tools.cs` now add a command-scoped Git configuration for each controlled Git process:

`-c safe.directory=<validated repository>`

This does not modify global Git configuration or repository-local Git configuration and does not trust unrelated paths.

Build verification completed with 0 warnings and 0 errors.

## Connector compatibility status

The Git v2 connector can load the expected tool catalog, but repeated first invocations have been disabled by the platform connector lifecycle layer. The backend hardening, build, runtime, tunnel target, and repository commits are independent of that platform-layer issue.

Do not modify Git backend security controls to work around this connector lifecycle behavior. Treat connector lifecycle compatibility as a separate platform integration issue.

## Legacy endpoint handling

Endpoint `8803` remains intentionally untouched. A health probe responded successfully, but the Agent-owned runtime-stop plan resolved PID 19460 to a tracked runtime fingerprint for `acceptance\windows-services-v2-build`, not the expected Git v2 build. Because the ownership/runtime fingerprint was inconsistent, no stop or delete action was executed.

Legacy acceptance build directories are retained for audit/reproducibility until a later cleanup task can identify each runtime with an exact trusted fingerprint.
