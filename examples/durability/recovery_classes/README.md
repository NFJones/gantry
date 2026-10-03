# Committed outcomes across action recovery classes

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/recovery_classes
```

Inputs 0, 1, and 2 select read-only, idempotent, and non-idempotent actions in
independent SQLite executions. Each returns 42; each restart has no hook response
and must reuse 42. These are completed-result demonstrations, not uncertain-outcome
retries. The earlier multi-action shape timed out before terminal publication;
the independent runs avoid claiming that unvalidated path works.
