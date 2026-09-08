# P30 — Runtime Deployment Signer + Packaging

## Objective

P30 adds a dedicated local runtime-deployment signer and defines the packaging boundary for the P28/P29/P30 control plane. P30 does not activate deployment. The active Formal runtime remains r28.

## Signer isolation

The signer is a standalone Windows-only executable. It never starts or stops the Formal Agent, Runtime Supervisor, authorizer, or executor. It only converts one validated signing intent into one signed P29 approval JSON.

The signer accepts exactly one signing-intent JSON file under:

`C:\Dev\YowThi-ERP-Dev-v4\.runtime-supervisor-deployment\signing-intents`

The intent binds:

- exact signing-intent ID
- exact approval ID and nonce
- exact P27 request ID and request SHA-256
- exact installed P28 executor SHA-256
- issue/expiry timestamps with a maximum five-minute lifetime
- fixed action `runtime-deploy`

Before signing, the signer re-reads the exact P27 request, requires `processAuthorization=false`, requires `requiresDedicatedSupervisorExecutor=true`, and proves the signing intent does not outlive the request.

## P31 parent gate

A signing-intent file alone is insufficient. The signer has a module-initializer parent guard requiring its direct parent to be the fixed future approval bridge:

`C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentApprovalBridge.exe`

The signer validates the parent executable path, rejects reparse points, and validates the bridge executable SHA-256. P30 intentionally ships with an all-zero bridge SHA sentinel, so direct signer launch always fails before `Main`.

P31 must independently build, review and pin the bridge SHA before signer invocation can become possible.

## CNG signer-key gate

The private signing key is never embedded in source, JSON, environment variables, command-line arguments, or repository files.

The signer opens only the fixed machine-scoped Windows CNG key:

- key name: `YowThiRuntimeDeploymentSignerV1`
- provider: Microsoft Software Key Storage Provider
- scope: machine key
- algorithm: ECDSA P-256
- private-key export: forbidden
- signer key ID: `p30-runtime-deployment-signer-v1`

The signer computes the public SubjectPublicKeyInfo SHA-256 and requires it to equal a compile-time pinned identity. P30 intentionally ships with an all-zero signer SPKI SHA sentinel, so signer execution remains disabled and no signing key is provisioned in P30.

## Signed approval compatibility

P30 signs the same canonical payload that P29 verifies:

1. `schemaVersion`
2. `approvalId`
3. `requestId`
4. `requestSha256`
5. `executorSha256`
6. `signerKeyId`
7. `issuedUtc`
8. `expiresUtc`
9. `nonce`
10. `action=runtime-deploy`

The signature algorithm is ECDSA P-256 with SHA-256.

## Packaging boundary

The eventual fixed installation root remains:

`C:\ProgramData\YowThi\RuntimeDeployment`

The deployment-control package contains exactly three executable components:

- `YowThi.RuntimeDeploymentSigner.exe`
- `YowThi.RuntimeDeploymentAuthorizer.exe`
- `YowThi.RuntimeDeploymentExecutor.exe`

Each installed executable must be bound by an exact SHA-256 in the package manifest. The package also records the signer SPKI SHA and the future approval-bridge SHA.

P30 package manifests explicitly carry `deploymentEnabled=false`, `signerKey.provisioned=false`, and `approvalBridge.provisioned=false`. Therefore packaging or copying P30 binaries alone cannot authorize runtime mutation.

## Safety invariants

- No signer private key is generated or provisioned by P30.
- No P31 approval bridge binary is generated or installed by P30.
- P30 does not remove the all-zero P28 authorizer-parent SHA sentinel.
- P30 does not remove the all-zero P29 signer SPKI sentinel.
- P30 signer itself also has all-zero P31 bridge and signer SPKI sentinels.
- No `Process.Start`, process termination, service control, shell, PowerShell, cmd, or generic executor exists in the P30 signer source.
- No `.agent3-handoff\ready` or legacy handoff queue is read, created, modified, or consumed.
- Runtime r28 remains the active runtime throughout P30 development and validation.

## Publication boundary

P30 source publication is accepted when:

- signer Release build is 0 warnings / 0 errors;
- signing-intent and package schemas are present;
- contract tests prove both fail-closed gates and canonical-signature compatibility;
- the self-hosted workflow explicitly builds the signer;
- all existing CI jobs remain green.

Binary installation, CNG private-key provisioning, P28/P29 SHA pinning and P31 bridge provisioning remain separate later steps. P30 source publication by itself does not enable deployment.
