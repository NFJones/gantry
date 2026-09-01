//! Exact public codec fixtures for publication-owned protocol formats.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gantry::event::{EventDraft, EventEnvelope, EventPayload};
use gantry::host::event::SinkId;
use gantry::identity::ProtocolIdentity;
use gantry::ir::{
    CanonicalPath, EffectSet, Instruction, InstructionKind, MachineProgram, Parameter,
    StructuralPosition, TypeDescriptor, Workflow,
};
use gantry::portable::{CancellationReasonCategory, DeliveryOutcome, EventKind, IdentityKind};
use gantry::runtime::{
    CancellationCausalIdentity, CancellationReason, CanonicalTranscriptV1,
    ConcurrentDurableCheckpointV1, ConcurrentDurableEvidenceV1, ConcurrentSchedulerV1,
    ConcurrentTaskStateV1, DurableCancellationEvidenceV1, DurableCommitCutV1,
    DurableEventDispatchedV1, DurableEventOccurrenceV1, DurableEventPlanV1, DurableEventSettledV1,
    DurableExecutionStartV1, DurableExecutionStateV1, DurableLogicalEvidenceV1,
    DurableRecoverySnapshotV1, LogicalSessionRegistryCheckpointV1, LogicalSessionRegistryV1,
    Machine, MachineCheckpointV1, MachineLimits, SessionCreationModeV1,
};
use gantry::schema::SchemaValidator;
use gantry::strict_json::{JsonLimits, StrictJsonDocument};
use gantry::timestamp::UtcTimestamp;
use gantry::value::{DEFAULT_VALUE_LIMITS, LogicalValue};
use serde::Deserialize;

const CATALOG_PATH: &str = "protocol/catalogs/public-formats-v1.json";
const GOLDEN_PATH: &str = "protocol/goldens/public-formats-v1.json";
const NEGATIVE_PATH: &str = "protocol/goldens/public-formats-v1.negatives.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatCatalog {
    catalog: String,
    major: u64,
    minor: u64,
    specification_revision: String,
    formats: Vec<FormatFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatFixture {
    format: String,
    family: String,
    encoding: String,
    magic: Option<String>,
    byte_length: String,
    sha256: String,
    schema: String,
    golden: String,
    profiles: Vec<String>,
    requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenCatalog {
    format: String,
    fixtures: Vec<GoldenFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenFixture {
    format: String,
    fixture_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCatalog {
    format: String,
    cases: Vec<NegativeFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeFixture {
    name: String,
    target: String,
    mutation: String,
}

#[test]
fn published_public_formats_match_exact_bytes_and_reject_mutations() {
    let fixtures = fixture_bytes();
    if std::env::var_os("GANTRY_WRITE_PUBLIC_FORMATS").is_some() {
        write_fixture_golden(&workspace_root(), &fixtures);
        return;
    }
    if std::env::var_os("GANTRY_PRINT_PUBLIC_FORMATS").is_some() {
        for (format, bytes) in &fixtures {
            println!("{format}\t{}", encode_hex(bytes));
        }
        return;
    }

    let root = workspace_root();
    let catalog: FormatCatalog = read_json(&root.join(CATALOG_PATH));
    let golden: GoldenCatalog = read_json(&root.join(GOLDEN_PATH));
    assert_eq!(catalog.catalog, "gantry.public-formats");
    assert_eq!((catalog.major, catalog.minor), (1, 0));
    assert_eq!(
        catalog.specification_revision,
        specification_revision(&root)
    );
    assert_eq!(catalog.formats.len(), fixtures.len());
    assert_eq!(golden.format, "gantry.public-format-goldens/v1");
    assert_eq!(golden.fixtures.len(), fixtures.len());
    assert!(
        catalog
            .formats
            .windows(2)
            .all(|pair| pair[0].format < pair[1].format)
    );
    assert!(
        golden
            .fixtures
            .windows(2)
            .all(|pair| pair[0].format < pair[1].format)
    );
    let golden = golden
        .fixtures
        .into_iter()
        .map(|fixture| (fixture.format, decode_hex(&fixture.fixture_hex)))
        .collect::<BTreeMap<_, _>>();

    for fixture in &catalog.formats {
        assert!(matches!(
            fixture.family.as_str(),
            "event" | "journal" | "recovery-projection" | "value"
        ));
        assert!(matches!(
            fixture.encoding.as_str(),
            "canonical-binary" | "canonical-json"
        ));
        assert!(!fixture.profiles.is_empty());
        assert!(!fixture.requirements.is_empty());
        assert!(fixture.profiles.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(
            fixture
                .requirements
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );

        let expected = fixtures
            .get(&fixture.format)
            .unwrap_or_else(|| panic!("unknown published format {}", fixture.format));
        assert_eq!(
            golden.get(&fixture.format),
            Some(expected),
            "{}",
            fixture.format
        );
        assert_eq!(
            fixture.byte_length,
            expected.len().to_string(),
            "{}",
            fixture.format
        );
        assert_eq!(fixture.sha256, sha256(expected), "{}", fixture.format);
        assert_eq!(fixture.golden, GOLDEN_PATH, "{}", fixture.format);
        assert!(root.join(&fixture.schema).is_file(), "{}", fixture.schema);
        assert_schema_accepts(&root, fixture, expected);
        if fixture.encoding == "canonical-binary" {
            let magic = fixture
                .magic
                .as_deref()
                .unwrap_or_else(|| panic!("binary format has no magic: {}", fixture.format));
            assert_eq!(expected.get(..magic.len()), Some(magic.as_bytes()));
        } else {
            assert!(fixture.magic.is_none());
        }
        assert_format_decodes(&fixture.format, expected);

        let mut invalid = expected.clone();
        if fixture.encoding == "canonical-binary" {
            invalid.pop();
        } else {
            invalid.push(b' ');
        }
        assert_format_rejects(&fixture.format, &invalid);
    }

    let negatives: NegativeCatalog = read_json(&root.join(NEGATIVE_PATH));
    assert_eq!(negatives.format, "gantry.public-format-negatives/v1");
    assert_eq!(negatives.cases.len(), 4);
    assert!(
        negatives
            .cases
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
    );
    for case in &negatives.cases {
        let fixture = catalog
            .formats
            .iter()
            .find(|fixture| fixture.format == case.target)
            .unwrap_or_else(|| panic!("unknown negative target {}", case.target));
        let bytes = fixtures
            .get(&case.target)
            .unwrap_or_else(|| panic!("missing negative target bytes {}", case.target));
        assert_schema_rejects(&root, fixture, bytes, &case.mutation);
    }
}

fn assert_schema_accepts(root: &Path, fixture: &FormatFixture, bytes: &[u8]) {
    let schema = fs::read(root.join(&fixture.schema))
        .unwrap_or_else(|error| panic!("could not read {}: {error}", fixture.schema));
    let validator = SchemaValidator::compile(schema, json_limits(2_000_000))
        .unwrap_or_else(|error| panic!("could not compile {}: {error:?}", fixture.schema));
    let instance = schema_instance(fixture, bytes);
    let document =
        StrictJsonDocument::decode(instance, json_limits(2_000_000)).unwrap_or_else(|error| {
            panic!("could not decode {} for schema: {error:?}", fixture.format)
        });
    assert_eq!(
        validator.validate(&document),
        Ok(Vec::new()),
        "{} against {}",
        fixture.format,
        fixture.schema
    );
}

fn assert_schema_rejects(root: &Path, fixture: &FormatFixture, bytes: &[u8], mutation: &str) {
    let schema = fs::read(root.join(&fixture.schema))
        .unwrap_or_else(|error| panic!("could not read {}: {error}", fixture.schema));
    let validator = SchemaValidator::compile(schema, json_limits(2_000_000))
        .unwrap_or_else(|error| panic!("could not compile {}: {error:?}", fixture.schema));
    let mut instance: serde_json::Value = serde_json::from_slice(&schema_instance(fixture, bytes))
        .unwrap_or_else(|error| panic!("could not decode negative instance: {error}"));
    let object = instance
        .as_object_mut()
        .unwrap_or_else(|| panic!("schema instance is not an object: {}", fixture.format));
    match mutation {
        "add-root-field" => {
            object.insert("unexpected".to_owned(), serde_json::Value::Null);
        }
        "corrupt-binary-magic" => {
            object.insert(
                "magic".to_owned(),
                serde_json::Value::String("GNTBAD01".to_owned()),
            );
        }
        "wrong-format" => {
            object.insert(
                "format".to_owned(),
                serde_json::Value::String("gantry.unknown/v1".to_owned()),
            );
        }
        other => panic!("unknown public-format mutation {other}"),
    }
    let encoded = serde_json::to_vec(&instance)
        .unwrap_or_else(|error| panic!("could not encode negative instance: {error}"));
    let document = StrictJsonDocument::decode(encoded, json_limits(2_000_000))
        .unwrap_or_else(|error| panic!("could not decode negative instance: {error:?}"));
    let errors = validator
        .validate(&document)
        .unwrap_or_else(|error| panic!("invalid schema {}: {error:?}", fixture.schema));
    assert!(
        !errors.is_empty(),
        "accepted mutation {mutation} for {} against {}",
        fixture.format,
        fixture.schema
    );
}

fn schema_instance(fixture: &FormatFixture, bytes: &[u8]) -> Vec<u8> {
    if fixture.encoding == "canonical-binary" {
        serde_json::to_vec(&serde_json::json!({
            "format": fixture.format,
            "magic": fixture.magic,
            "fixture_hex": encode_hex(bytes),
        }))
        .unwrap_or_else(|error| panic!("could not encode binary fixture: {error}"))
    } else {
        bytes.to_vec()
    }
}

const fn json_limits(maximum: u64) -> JsonLimits {
    JsonLimits {
        maximum_bytes: maximum,
        maximum_nesting_depth: maximum,
        maximum_nodes: maximum,
        maximum_string_scalars: maximum,
        maximum_list_items: maximum,
    }
}

fn fixture_bytes() -> BTreeMap<String, Vec<u8>> {
    let execution = fresh(IdentityKind::Execution, 1);
    let root_task = ProtocolIdentity::derive(IdentityKind::Task, b"public-format-root")
        .unwrap_or_else(|error| panic!("root task identity failed: {error}"));
    let root_session = fresh(IdentityKind::Session, 2);
    let program = program();
    let foreground = machine(Arc::clone(&program), execution, root_session);
    let sessions = LogicalSessionRegistryV1::new(
        execution,
        root_session,
        SessionCreationModeV1::GantryRoot,
        CanonicalTranscriptV1::empty(),
    )
    .unwrap_or_else(|error| panic!("session registry failed: {error:?}"));
    let state = ConcurrentTaskStateV1::new(execution, root_task, 4)
        .unwrap_or_else(|error| panic!("task state failed: {error:?}"));
    let scheduler = ConcurrentSchedulerV1::new(state);

    let machine_checkpoint = foreground.checkpoint();
    let session_checkpoint = sessions.checkpoint();
    let combined_checkpoint =
        ConcurrentDurableCheckpointV1::capture(&foreground, &scheduler, &sessions)
            .unwrap_or_else(|error| panic!("combined checkpoint failed: {error:?}"));
    let logical = DurableLogicalEvidenceV1::new_with_sessions(
        execution,
        root_task,
        DurableCommitCutV1::Checkpoint,
        None,
        machine_checkpoint.clone(),
        Some(session_checkpoint.clone()),
    )
    .unwrap_or_else(|error| panic!("logical evidence failed: {error:?}"));
    let execution_start = DurableExecutionStartV1::new(
        execution,
        root_task,
        &program,
        Arc::<[u8]>::from(&b"{}"[..]),
        logical.clone(),
    )
    .unwrap_or_else(|error| panic!("execution start failed: {error:?}"));
    let execution_state = DurableExecutionStateV1::new(
        execution,
        Arc::<[u8]>::from(&b"{}"[..]),
        Some(Arc::from("agents-v1")),
        Some(Arc::from("actions-v1")),
    )
    .unwrap_or_else(|error| panic!("execution state failed: {error:?}"));
    let recovery = DurableRecoverySnapshotV1::new_with_execution_state(
        execution_start.clone(),
        Some(execution_state.clone()),
        logical.clone(),
    )
    .unwrap_or_else(|error| panic!("recovery snapshot failed: {error:?}"));
    let combined = ConcurrentDurableEvidenceV1::new(
        DurableCommitCutV1::Checkpoint,
        root_task,
        combined_checkpoint.clone(),
    )
    .unwrap_or_else(|error| panic!("combined evidence failed: {error:?}"));

    let mut cancelled_machine = machine(Arc::clone(&program), execution, root_session);
    assert!(cancelled_machine.cancel("caller-stop").is_some());
    let cancelled_state = DurableLogicalEvidenceV1::new_with_sessions(
        execution,
        root_task,
        DurableCommitCutV1::Cancellation,
        None,
        cancelled_machine.checkpoint(),
        Some(session_checkpoint.clone()),
    )
    .unwrap_or_else(|error| panic!("cancelled state failed: {error:?}"));
    let reason = CancellationReason::new(
        CancellationReasonCategory::Caller,
        Some(Arc::from("caller-stop")),
        Some(CancellationCausalIdentity::Task(root_task)),
        64,
    )
    .unwrap_or_else(|error| panic!("cancellation reason failed: {error:?}"));
    let cancellation = DurableCancellationEvidenceV1::new(reason, cancelled_state)
        .unwrap_or_else(|error| panic!("cancellation evidence failed: {error:?}"));

    let event = EventEnvelope::complete(
        fresh(IdentityKind::Event, 3),
        fresh(IdentityKind::Activity, 4),
        UtcTimestamp::from_unix_seconds(0, 7)
            .unwrap_or_else(|error| panic!("timestamp failed: {error:?}")),
        EventDraft::new(EventKind::OperationCompletion, event_payload())
            .with_execution_id(execution)
            .unwrap_or_else(|error| panic!("event draft failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("event completion failed: {error:?}"));
    let occurrence = DurableEventOccurrenceV1::new(
        ProtocolIdentity::from_storage_material([5; 32]),
        event,
        DurableEventPlanV1::new(Vec::new())
            .unwrap_or_else(|error| panic!("event plan failed: {error:?}")),
    )
    .unwrap_or_else(|error| panic!("event occurrence failed: {error:?}"));
    let sink = SinkId::new("sink-a").unwrap_or_else(|error| panic!("sink ID failed: {error:?}"));
    let attempt = fresh(IdentityKind::DeliveryAttempt, 6);
    let dispatched =
        DurableEventDispatchedV1::new(occurrence.event().event_id(), sink.clone(), attempt, 0)
            .unwrap_or_else(|error| panic!("dispatch evidence failed: {error:?}"));
    let settled = DurableEventSettledV1::new(
        occurrence.event().event_id(),
        sink,
        attempt,
        0,
        DeliveryOutcome::Success,
        0,
        None,
    )
    .unwrap_or_else(|error| panic!("settled evidence failed: {error:?}"));

    BTreeMap::from([
        (
            "canonical-transcript/v1".to_owned(),
            CanonicalTranscriptV1::empty().bytes().to_vec(),
        ),
        (
            "combined-checkpoint/v1".to_owned(),
            combined_checkpoint.canonical_bytes(),
        ),
        (
            "gantry.cancellation/v1".to_owned(),
            cancellation.canonical_body(),
        ),
        (
            "gantry.concurrent-durable-evidence/v1".to_owned(),
            combined.canonical_body(),
        ),
        (
            "gantry.event-delivery-dispatched/v1".to_owned(),
            dispatched.canonical_body(),
        ),
        (
            "gantry.event-delivery-settled/v1".to_owned(),
            settled.canonical_body(),
        ),
        (
            "gantry.event-occurrence/v1".to_owned(),
            occurrence.canonical_body(),
        ),
        (
            "gantry.execution-start/v1".to_owned(),
            execution_start.canonical_body(),
        ),
        (
            "gantry.execution-state/v1".to_owned(),
            execution_state.canonical_body(),
        ),
        (
            "gantry.logical-evidence/v1".to_owned(),
            logical.canonical_body(),
        ),
        (
            "gantry.recovery-snapshot/v1".to_owned(),
            recovery.canonical_body(),
        ),
        (
            "machine-checkpoint/v1".to_owned(),
            machine_checkpoint.canonical_bytes(),
        ),
        (
            "session-checkpoint/v1".to_owned(),
            session_checkpoint.canonical_bytes(),
        ),
    ])
}

fn assert_format_decodes(format: &str, bytes: &[u8]) {
    let context = fixture_context();
    match format {
        "canonical-transcript/v1" => {
            assert!(CanonicalTranscriptV1::decode(bytes, DEFAULT_VALUE_LIMITS).is_ok())
        }
        "combined-checkpoint/v1" => {
            assert!(ConcurrentDurableCheckpointV1::decode(&context.program, bytes).is_ok())
        }
        "gantry.cancellation/v1" => {
            assert!(DurableCancellationEvidenceV1::decode(&context.program, bytes).is_ok())
        }
        "gantry.concurrent-durable-evidence/v1" => {
            assert!(ConcurrentDurableEvidenceV1::decode(&context.program, bytes).is_ok())
        }
        "gantry.event-delivery-dispatched/v1" => {
            assert!(DurableEventDispatchedV1::decode(bytes).is_ok())
        }
        "gantry.event-delivery-settled/v1" => {
            assert!(DurableEventSettledV1::decode(bytes).is_ok())
        }
        "gantry.event-occurrence/v1" => assert!(DurableEventOccurrenceV1::decode(bytes).is_ok()),
        "gantry.execution-start/v1" => {
            assert!(DurableExecutionStartV1::decode(&context.program, bytes).is_ok())
        }
        "gantry.execution-state/v1" => assert!(DurableExecutionStateV1::decode(bytes).is_ok()),
        "gantry.logical-evidence/v1" => {
            assert!(DurableLogicalEvidenceV1::decode(&context.program, bytes).is_ok())
        }
        "gantry.recovery-snapshot/v1" => {
            assert!(DurableRecoverySnapshotV1::decode(&context.program, bytes).is_ok())
        }
        "machine-checkpoint/v1" => {
            assert!(MachineCheckpointV1::decode(&context.program, bytes).is_ok())
        }
        "session-checkpoint/v1" => {
            assert!(LogicalSessionRegistryCheckpointV1::decode(bytes, DEFAULT_VALUE_LIMITS).is_ok())
        }
        other => panic!("unknown format {other}"),
    }
}

fn assert_format_rejects(format: &str, bytes: &[u8]) {
    let context = fixture_context();
    let rejected = match format {
        "canonical-transcript/v1" => {
            CanonicalTranscriptV1::decode(bytes, DEFAULT_VALUE_LIMITS).is_err()
        }
        "combined-checkpoint/v1" => {
            ConcurrentDurableCheckpointV1::decode(&context.program, bytes).is_err()
        }
        "gantry.cancellation/v1" => {
            DurableCancellationEvidenceV1::decode(&context.program, bytes).is_err()
        }
        "gantry.concurrent-durable-evidence/v1" => {
            ConcurrentDurableEvidenceV1::decode(&context.program, bytes).is_err()
        }
        "gantry.event-delivery-dispatched/v1" => DurableEventDispatchedV1::decode(bytes).is_err(),
        "gantry.event-delivery-settled/v1" => DurableEventSettledV1::decode(bytes).is_err(),
        "gantry.event-occurrence/v1" => DurableEventOccurrenceV1::decode(bytes).is_err(),
        "gantry.execution-start/v1" => {
            DurableExecutionStartV1::decode(&context.program, bytes).is_err()
        }
        "gantry.execution-state/v1" => DurableExecutionStateV1::decode(bytes).is_err(),
        "gantry.logical-evidence/v1" => {
            DurableLogicalEvidenceV1::decode(&context.program, bytes).is_err()
        }
        "gantry.recovery-snapshot/v1" => {
            DurableRecoverySnapshotV1::decode(&context.program, bytes).is_err()
        }
        "machine-checkpoint/v1" => MachineCheckpointV1::decode(&context.program, bytes).is_err(),
        "session-checkpoint/v1" => {
            LogicalSessionRegistryCheckpointV1::decode(bytes, DEFAULT_VALUE_LIMITS).is_err()
        }
        other => panic!("unknown format {other}"),
    };
    assert!(rejected, "accepted mutated fixture {format}");
}

struct FixtureContext {
    program: Arc<MachineProgram>,
}

fn fixture_context() -> FixtureContext {
    FixtureContext { program: program() }
}

fn program() -> Arc<MachineProgram> {
    Arc::new(
        MachineProgram::new(vec![Workflow {
            path: path("crate::main"),
            parameters: Vec::<Parameter>::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![
                Instruction {
                    site: position(0),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Push(LogicalValue::unit()),
                },
                Instruction {
                    site: position(1),
                    ty: TypeDescriptor::UNIT,
                    kind: InstructionKind::Return,
                },
            ],
        }])
        .unwrap_or_else(|error| panic!("program failed: {error:?}")),
    )
}

fn machine(
    program: Arc<MachineProgram>,
    execution: ProtocolIdentity,
    session: ProtocolIdentity,
) -> Machine {
    Machine::new_with_context(
        program,
        &path("crate::main"),
        Vec::new(),
        execution,
        MachineLimits::new(32, 4, 4, 8, 16, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| unreachable!("positive machine limits")),
        None,
        Some(session),
    )
    .unwrap_or_else(|error| panic!("machine failed: {error:?}"))
}

fn event_payload() -> EventPayload {
    EventPayload::from_validated_canonical_bytes(Arc::<[u8]>::from(&b"{}"[..]))
        .unwrap_or_else(|error| panic!("event payload failed: {error:?}"))
}

fn path(value: &str) -> CanonicalPath {
    CanonicalPath::new(value).unwrap_or_else(|error| panic!("path failed: {error}"))
}

fn position(value: u64) -> StructuralPosition {
    StructuralPosition::new(vec![value]).unwrap_or_else(|error| panic!("position failed: {error}"))
}

fn fresh(kind: IdentityKind, byte: u8) -> ProtocolIdentity {
    ProtocolIdentity::from_fresh_material(kind, [byte; 32])
        .unwrap_or_else(|error| panic!("identity failed: {error}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .unwrap_or_else(|error| panic!("fixture hex failed: {error}"));
            u8::from_str_radix(pair, 16)
                .unwrap_or_else(|error| panic!("fixture hex failed: {error}"))
        })
        .collect()
}

fn write_fixture_golden(root: &Path, fixtures: &BTreeMap<String, Vec<u8>>) {
    let fixtures = fixtures
        .iter()
        .map(|(format, bytes)| {
            serde_json::json!({
                "format": format,
                "fixture_hex": encode_hex(bytes),
            })
        })
        .collect::<Vec<_>>();
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "format": "gantry.public-format-goldens/v1",
        "fixtures": fixtures,
    }))
    .unwrap_or_else(|error| panic!("could not render public-format golden: {error}"));
    bytes.push(b'\n');
    fs::write(root.join(GOLDEN_PATH), bytes)
        .unwrap_or_else(|error| panic!("could not write {GOLDEN_PATH}: {error}"));
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    format!("{:x}", Sha256::digest(bytes))
}

fn specification_revision(root: &Path) -> String {
    use sha2::{Digest, Sha256};

    format!(
        "{:x}",
        Sha256::digest(
            fs::read(root.join("SPEC.md"))
                .unwrap_or_else(|error| panic!("could not read SPEC.md: {error}"))
        )
    )
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("could not decode {}: {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
