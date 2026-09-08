# P31 — Runtime Deployment Exact-SHA Pinning

## Provisioned signer identity

The interactive P31 key provisioner completed successfully for the logged-in Windows user and produced a public-only receipt. The private key remains in the CurrentUser CNG key store and is non-exportable.

- key name: `YowThiRuntimeDeploymentSignerV1`
- key ID: `p31-runtime-deployment-signer-user-v1`
- key scope: `CurrentUser`
- algorithm: `ECDSA_P256`
- SPKI SHA-256: `3794BFF6F3FEB5B64F58A85F1CD9E4C526ACBFBDF2B51E25A27CEAF88124981A`

The public SPKI identity is pinned in both `SigningKeyGate` and `ApprovalSignatureGate`.

## Pinned executable identities

- Approval Bridge SHA-256: `9FF4EAF2A642DEF2013ACF2356440E7B51B24A476303E7D91B1228D250337EF5`
- Signer SHA-256: `97BEA5C33F4BFC84CB94855B189DA150D4760B30D7289098478086558E3D6613`
- Authorizer SHA-256: `7BD1F5AEFD057B06E420C2A4E20E7A3BB5A3A9F28C9A0AE324AF4F19A11E9AFE`
- Executor SHA-256: `4A10CE0E0FD85704191E7C5580CCD4F1D29A106AD28DDF35EFD2FB0B3DBB2398`

`ApprovalBridgeParentGuard` pins the exact Approval Bridge SHA. `AuthorizerParentGuard` pins the exact Authorizer SHA.

## Activated package candidate

A schemaVersion 2 activated-package candidate is prepared only under the development acceptance root:

`C:\Dev\YowThi-ERP-Dev-v4\acceptance\runtime-deployment-p31-activated-package\package-manifest.json`

It carries `deploymentEnabled=true`, the exact executable SHA identities, CurrentUser signer identity, user SID binding, and provisioned bridge identity.

This candidate is not installed to ProgramData by this phase.

## Safety boundary

This phase does not:

- create `C:\ProgramData\YowThi\RuntimeDeployment`;
- execute the Approval Bridge, Signer, Authorizer or Executor;
- create or consume a legacy `.agent3-handoff\ready` authorization;
- stop/start the Runtime Supervisor;
- modify active-runtime state;
- activate any staged Agent runtime.

Runtime r28 remains the active Formal runtime until a later separately authorized installation and cutover phase.
