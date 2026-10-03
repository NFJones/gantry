# Application approval-gated action

Compose proposal generation, model review, and an explicit non-idempotent action.
The `Decision` is an application-level semantic gate, **not authenticated human
approval, capability authority, or permission to perform a real submission**.
The embedding host remains responsible for authorization and policy enforcement.
The offline action only returns a scripted receipt; nothing is published.

Scenarios cover acceptance, rejection (no action dispatch), and host policy denial
after application acceptance. Exact trace assertions check proposal propagation,
reviewer selection, action recovery class, and absence of automatic resubmission.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/application_approval_action
```

Spec: [sealed decisions](../../../SPEC.md#GNT-5.10),
[action declarations](../../../SPEC.md#GNT-6.12),
[operation failures](../../../SPEC.md#GNT-5.9).
