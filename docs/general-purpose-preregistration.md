# General-purpose preregistration

`protocol/catalogs/general-purpose-preregistration-v1.json` is the canonical,
machine-checked preregistration for the general-purpose implementation effort.
It fixes task intent, representative applications, matrix boundaries, rerun
rules, and claim blockers without selecting final syntax or implementing a
feature.

The initial supported platform scope is Linux and macOS. Windows is not a
release claim. Model and tool behavior is supplied by an embedding harness;
deterministic fakes, mocked hooks, and recorded transcripts are the semantic
oracles. Real-provider interoperability belongs to a separate harness effort
and is not a Gantry language gate.

Each authoring task receives one controlled agent run. Human trials are
deferred until after implementation and do not block this initial gate. Runs
must retain their prompt, starting artifact, context, model configuration,
tools, result, diagnostics, and failed or abandoned status so a material
syntax, API, diagnostics, documentation, or execution-strategy change can
invalidate and rerun the affected evidence.

There is no quantitative performance acceptance threshold in this version.
Implementation work is functionality-first, while review and tests reject
obviously unbounded or needlessly pathological designs. Quantitative latency,
throughput, memory, cancellation-response, and sustained-service targets may
be preregistered by a later version after representative applications exist.
No production execution-strategy claim may infer such qualification from this
catalog.

Every downstream decision record must name its normative owner, compatibility
owner, evidence owner, publication blocker, and material-change rerun set.
The canonical catalog enumerates these fields for all 77 downstream issues;
validation rejects missing, duplicate, self-referential, or empty records.
Until downstream gates provide current evidence, the project must not claim a
stable edition, stable standard library, production execution strategy, or
general-purpose profile.
