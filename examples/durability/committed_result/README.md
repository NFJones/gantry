# Committed result, no redispatch

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/committed_result
```

The local non-idempotent publish script returns `"receipt-7"` once. After terminal
commit, shutdown and SQLite reopen, an empty script proves the result is reused
without another dispatch. No external publication actually occurs. This is a
logical restart, not an interruption between dispatch and outcome commit.
