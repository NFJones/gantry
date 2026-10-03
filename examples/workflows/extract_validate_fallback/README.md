# Extract, validate, retry, and fall back

Compose typed extraction with a conservative fallback and deterministic domain
normalization. `retry_limit = 1` permits one structured-output repair, not a
provider-error retry. A negative count is structurally valid but normalized to
zero by source code; structural validation does not enforce domain meaning.

Scripts cover valid output, invalid type repaired once, exhausted validation,
and provider failure. Trace assertions distinguish repair of the same extraction
from a new fallback prompt and inspect the sealed error passed as a named input.
The fallback has no retries and its own failure would propagate.

From the repository root, build once and reuse:

```sh
timeout 180 cargo build --offline -p gantry-conformance --example corpus
timeout 120 target/debug/examples/corpus examples/workflows/extract_validate_fallback
```

Spec: [operation errors](../../../SPEC.md#GNT-5.9),
[validation retries](../../../SPEC.md#GNT-8.10),
[attempt](../../../SPEC.md#1413-explicit-operation-failure-handling-with-attempt).
