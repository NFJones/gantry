# Durable task graph: start, join, shutdown

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/task_graph
```

Two child tasks return 20 and 22. Public durable start, SQLite commits, joins,
terminal result 42, and orderly shutdown execute. Metadata says `start-only`:
reopening and resuming this terminal graph returned `invalid-authoritative-prefix`
during validation. This package deliberately does **not** claim graph recovery.
