# Executable Rust embedding demonstrations

These are public Rust API examples, not fictional Gantry source directives.
`demos.rs` is compiled directly by the dedicated integration test (existing
dependencies only); each directory supplies the source package used by that code.

```sh
timeout 180 cargo test --offline -p gantry-conformance --test example_durability embedding_demonstrations -- --nocapture
```

No credentials, models, sockets, or network calls are used. The driver bounds the
whole demonstration sequence to 30 seconds and shuts down its Tokio runtime.

- `lifecycle`: real pending host action, query, caller cancellation, terminal
  cancellation failure, repeated cancellation with preserved reason, shutdown.
- `observation`: real required event sink, finite timeout/no retries,
  no raw output and deny-protected capabilities, verifies no protected bytes
  arrive, terminal delivery completes, and no required-delivery failures remain.
- `resource_policy`: a successful execution under finite live/pending/retained/
  adapter-identity ceilings, followed by the explicit durable policy refusal.

These tests do not claim resource exhaustion, crash recovery, event transport
delivery to external systems, or durable support for adapter-identity accounting.
