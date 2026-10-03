# Candidate compatibility

```sh
timeout 120 cargo run --offline -p gantry-conformance --example corpus -- examples/durability/candidate_check
```

The first scenario resumes with the exact candidate and checks `ExactManifest`.
The second uses a temporary candidate with a different return type and requires
`canonical-ir-identity-mismatch`, successful owner release, and unchanged journal
prefix. Literal-only changes are not an equivalence guarantee; see the lane README.
