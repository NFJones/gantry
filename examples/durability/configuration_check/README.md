# Immutable configuration compatibility

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/configuration_check
```

The initial run commits `"configuration is pinned"`. Resume changes the maximum
hook-output bytes from 1,048,576 to 524,288 and requires
`immutable-configuration-mismatch`, successful owner release, and unchanged prefix.
This changes real Rust configuration, not an invented source directive.
