# Source-free resume

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/source_free
```

Input 41 produces 42. The adapter reopens SQLite and passes
`candidate_package_root: None`, asserting `SourceFree` and the original execution
identity/result. The package remains on disk but is not supplied to resume.
