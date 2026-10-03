# Finite resource policy and durable refusal

Run the `embedding_demonstrations` test using the command in `../README.md`.
The implementation is `resource_policy` in `../demos.rs`. It configures live,
pending, retained and adapter ceilings of 64, 64, 128, and 64, executes the package
successfully, then attempts durable start under the same policy. Durable start
must reject `unsupported-durable-adapter-identity-policy` and release ownership.
This demonstrates the actual unavailable boundary, not a working durable adapter
policy. The happy path does not test exhaustion or live-resource transport.
