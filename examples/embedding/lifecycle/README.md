# Query, cancellation, terminal, shutdown

Run the `embedding_demonstrations` test using the command in `../README.md`.
The implementation is `lifecycle` in `../demos.rs`. Its host holds a real action
until its cancellation token is signaled, avoiding timing-dependent cancellation
of an already-completed program. Query sees pending work, cancellation records
the reason, terminal reports the operation cancellation code, and repeated
cancellation preserves the effective reason before orderly shutdown.
