# Required observation and protected-data policy

Run the `embedding_demonstrations` test using the command in `../README.md`.
The implementation is `observation` in `../demos.rs`. A local required sink
receives real events with a one-second attempt limit, no retries, no raw output,
and no protected capabilities. It rejects any delivered protected bytes and
requires terminal delivery plus zero required-delivery failures. There is no
external telemetry system or modeled source observation syntax.
