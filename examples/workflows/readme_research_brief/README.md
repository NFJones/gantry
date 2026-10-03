# README research brief

`main.gnt` composes a declared read-only README capability with a grounded brief
workflow. The host script supplies local text, never a network service. An empty
README takes a deterministic fallback and must not dispatch a prompt.

`case.json` covers evidence and no-evidence paths, asserting capability arguments,
recovery class, the called workflow site, and ordered named model inputs. Exact
hook consumption also checks that the fallback does not ask a model.

Build once from the repository root, then reuse the runner:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/readme_research_brief
```

Spec: [workflow calls](../../../SPEC.md#GNT-6.4),
[explicit actions and inputs](../../../SPEC.md#1412-explicit-harness-actions-and-named-prompt-inputs).
