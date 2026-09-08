# P31 — Interactive Runtime Deployment Approval Bridge

## Objective

P31 hardens the P28/P29/P30 deployment chain so that runtime mutation cannot be authorized entirely from the LocalSystem Session 0 control plane. The signer key is moved from machine scope to the interactive Windows user's CurrentUser CNG store, and the approval bridge plus key provisioner require the active console session and a direct Windows Explorer parent.

P31 source publication does not provision the key, does not install ProgramData binaries, does not pin the remaining SHA sentinels, and does not activate a runtime deployment.

## Trust boundary

Formal and Bootstrap run as LocalSystem. A machine-scoped signing key would therefore not provide a sufficiently independent authorization root if future host mutation primitives become broader.

P31 changes the signer identity to:

- key name: `YowThiRuntimeDeploymentSignerV1`
- key ID: `p31-runtime-deployment-signer-user-v1`
- provider: Microsoft Software Key Storage Provider
- scope: CurrentUser
- algorithm: ECDSA P-256
- private-key export: forbidden

The signer still carries an all-zero compile-time SPKI SHA sentinel until the interactive provisioner has created the key and produced a public receipt.

## Interactive session guard

Both `YowThi.RuntimeDeploymentKeyProvisioner.exe` and `YowThi.RuntimeDeploymentApprovalBridge.exe` enforce at module load:

1. Windows and `Environment.UserInteractive`.
2. `WTSGetActiveConsoleSessionId()` must identify a non-zero active console session.
3. The current process must belong to that exact session.
4. The direct parent process must belong to that exact session.
5. The direct parent executable must be the fixed Windows `explorer.exe` path.

A Session 0 `Process.Start` from the Agent therefore cannot satisfy the bridge/provisioner trust boundary.

## Key provisioner

The key provisioner accepts no command-line arguments. After an explicit Yes/No interactive dialog it creates or verifies the fixed CurrentUser CNG key. It rejects:

- non-ECDSA keys;
- non-P-256 keys;
- exportable private keys;
- keys without signing usage.

It exports only SubjectPublicKeyInfo and writes only a public receipt under:

`C:\Dev\YowThi-ERP-Dev-v4\acceptance\runtime-deployment-p31-key\public-key.json`

The receipt contains the user SID, key ID/scope/provider/algorithm, public SPKI, SPKI SHA-256 and timestamp. No private-key bytes are written.

## Approval bridge

The bridge accepts no arbitrary path or executable input. It discovers exactly one unexpired request-only P27 deployment request and shows the target release/current SHA/target SHA to the interactive user. Approval requires an explicit Yes click.

The bridge then:

1. requires an installed schemaVersion 2 package manifest with `deploymentEnabled=true`;
2. requires `signerKey.provisioned=true` and `approvalBridge.provisioned=true`;
3. binds the package to the current interactive user SID and CurrentUser signer key ID;
4. SHA-validates the installed signer, authorizer, executor and bridge itself;
5. creates one short-lived signing intent bound to the exact P27 request SHA and installed executor SHA;
6. launches only the fixed signer as its child;
7. requires the signed approval file;
8. launches only the fixed authorizer as its child;
9. leaves actual Supervisor/runtime mutation exclusively to the P28 executor reached through the authorizer.

The bridge itself has no service-control, direct runtime start/stop, shell, PowerShell, cmd, or legacy handoff capability.

## Activated package contract

P31 defines `P31-RUNTIME-DEPLOYMENT-ACTIVATED-PACKAGE.schema.json` with:

- schemaVersion 2;
- `deploymentEnabled=true`;
- exact SHA-256 for signer/authorizer/executor;
- CurrentUser signer key ID, user SID and SPKI SHA;
- exact approval bridge SHA;
- both signer key and approval bridge `provisioned=true`.

This schema describes the later activated installation state. P31 source publication does not create that state.

## Remaining fail-closed gates

After P31 source publication and before interactive provisioning:

- P28 authorizer-parent SHA remains all zero;
- P29 signer SPKI/base64 remains unprovisioned;
- P30/P31 signer SPKI SHA remains all zero;
- P30/P31 signer approval-bridge SHA remains all zero;
- `C:\ProgramData\YowThi\RuntimeDeployment` remains absent;
- runtime r28 remains active.

## Provisioning sequence after source publication

A later explicit step must:

1. place only the reviewed key provisioner on the interactive desktop and have the logged-in user launch it through Explorer;
2. read back the public receipt;
3. pin the exact SPKI SHA/public key in signer/authorizer source;
4. build the approval bridge and obtain its exact SHA;
5. pin that bridge SHA in the signer parent guard;
6. rebuild signer/authorizer/executor and obtain final exact SHA values;
7. construct the schemaVersion 2 activated package manifest;
8. install the fixed package to ProgramData with read-back verification;
9. separately decide whether to create a fresh P27 deployment request for an actual runtime cutover.

The historical failed r29 handoff is not reused.
