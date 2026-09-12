//! Machine-checked conformance for the agent fulfillment, assistant turn, tool, and
//! session model of `SPEC.md` Section 25, clauses `GNT-25.0` .. `GNT-25.10`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed agent model
//! together with the landed `GNT-3`, `GNT-19`, and `GNT-20` contracts it cites:
//! `GNT-25.0-agent-fulfillment-assistant-turns-tools-and-sessions`,
//! `GNT-25.1-agent-requirements-and-fulfillment`,
//! `GNT-25.2-fulfillment-preflight`,
//! `GNT-25.3-assistant-turns`,
//! `GNT-25.4-turn-validation-and-repair`,
//! `GNT-25.5-round-identity-and-durable-cuts`,
//! `GNT-25.6-tool-slots-and-tool-set-revisions`,
//! `GNT-25.7-source-handlers`,
//! `GNT-25.8-sessions-and-child-sessions`,
//! `GNT-25.9-streaming-and-progress`, and
//! `GNT-25.10-agent-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a provider, a
//! clock, a process identifier, a thread identity, a host path, an environment fact,
//! or a live host handle, and no test spawns a thread or waits on a handle. Slots,
//! descriptors, revisions, turns, prefixes, budgets, sessions, and streams are
//! explicit declarations, so every verdict here is reproducible from its own inputs.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::{Effect, RecoveryClass};
use gantry::ir::{
    AGENT_CLAUSES, AGENT_NON_CLAIM_ORDER, AGENT_NON_CLAIMS, AgentBindingRevision,
    AgentCrashCutClassification, AgentDiagnosticCode, AgentError, AgentNonClaim,
    AgentNonClaimAssertion, AgentRecoveryDecision, AgentRequirement, AuthorityRequirementId,
    BindingFact, CanonicalPath, CanonicalSignature, ChildSessionId, DiscoveryArtifact,
    DiscoveryPhase, DurableAgentCut, DurableAgentRecord, EffectSet, FinalResult,
    FulfillmentDescriptor, FulfillmentProperty, FulfillmentState, HandlerKind, HandlerUse,
    PreflightVerdict, ProviderNameMap, RawResponse, RejectedPrefix, RepairAttempt, RepairBudget,
    RepairOutcome, RepairPermit, RepairPolicy, RetryEligibility, RoundId, RoundState,
    SemanticStream, SessionDirective, SessionId, SessionReservations, StreamId, StreamKind,
    StreamSpec, ToolDescriptor, ToolInvocationRequest, ToolResultRecord, ToolResultVector,
    ToolSetRevision, ToolSlotId, ToolSlotKind, Turn, TurnKind, TurnOutcome, TurnValidationCause,
    TypeDescriptor, check_agent_non_claims, classify_original_turn, preflight, repair_turn,
    validate_raw_response,
};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming
/// the associated item requires an inference that cannot be resolved and compilation
/// fails. A `Clone` implementation for any affine agent value would stop this crate
/// compiling, which is exactly what `GNT-25.4`, `GNT-25.5`, and `GNT-25.7` forbid: a
/// rejected prefix, a repair permit, a repair attempt, and a single-use handler use are
/// affine, so one rejected prefix is produced once, consumed once by one repair attempt,
/// and can never be replayed or dispatched from a copy, and an `FnOnce` handler is never
/// invoked twice through a copy.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_name:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $(
                impl<T: ?Sized + $trait_name> AmbiguousIfImpl<Invalid> for T {}
            )+
            struct Invalid;
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl_any!(RejectedPrefix: Clone);
assert_not_impl_any!(RepairPermit: Clone);
assert_not_impl_any!(RepairAttempt: Clone);
assert_not_impl_any!(HandlerUse: Clone);

/// One canonical workflow path declared by a test fixture.
fn canonical(value: &str) -> CanonicalPath {
    match CanonicalPath::new(value) {
        Ok(path) => path,
        Err(error) => panic!("the declared path {value} is canonical: {error:?}"),
    }
}

/// One landed authority requirement of the declared capability family and signature
/// (`GNT-3-T-AUTHORITY-INSTANCES`).
fn authority(capability_family: &str) -> AuthorityRequirementId {
    let path = canonical("crate::agent::call");
    let signature = CanonicalSignature::function(&path, &[], &TypeDescriptor::STRING);
    match AuthorityRequirementId::new(
        &path,
        &signature,
        capability_family,
        RecoveryClass::Idempotent,
    ) {
        Ok(requirement) => requirement,
        Err(error) => panic!("the declared capability {capability_family} is valid: {error:?}"),
    }
}

/// One landed effect set of the declared effects (`GNT-3-T-EFFECTS`).
fn effects(declared: &[Effect]) -> EffectSet {
    let mut set = EffectSet::default();
    for effect in declared {
        set.insert(*effect);
    }
    set
}

/// One package-qualified tool slot declared by a test fixture.
fn slot(package: &str, name: &str) -> ToolSlotId {
    match ToolSlotId::derive(package, name) {
        Ok(slot) => slot,
        Err(error) => panic!("the declared slot {package}::{name} is valid: {error}"),
    }
}

/// One source-handler tool descriptor with caller-declared descriptor facts.
#[allow(clippy::too_many_arguments)] // one declared descriptor fact per parameter
fn descriptor_with(
    package: &str,
    name: &str,
    provider: &str,
    schema_digest: &str,
    declared_effects: &[Effect],
    authority_family: &str,
    recovery: RecoveryClass,
    retry: RetryEligibility,
) -> ToolDescriptor {
    match ToolDescriptor::new(
        slot(package, name),
        ToolSlotKind::SourceHandler,
        provider,
        schema_digest,
        effects(declared_effects),
        authority(authority_family),
        recovery,
        retry,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the declared descriptor {provider} is valid: {error}"),
    }
}

/// One source-handler tool descriptor declared by a test fixture.
fn descriptor(package: &str, name: &str, provider: &str, schema_digest: &str) -> ToolDescriptor {
    descriptor_with(
        package,
        name,
        provider,
        schema_digest,
        &[Effect::Prompt],
        "tools-call",
        RecoveryClass::Idempotent,
        RetryEligibility::Eligible,
    )
}

/// Orders descriptors into the canonical strictly increasing slot order.
fn ordered(mut descriptors: Vec<ToolDescriptor>) -> Vec<ToolDescriptor> {
    descriptors.sort_by(|left, right| left.slot().cmp(right.slot()));
    descriptors
}

/// One immutable tool-set revision declared by a test fixture.
fn build_tool_set(revision: u64, descriptors: Vec<ToolDescriptor>) -> ToolSetRevision {
    match ToolSetRevision::new(revision, ordered(descriptors)) {
        Ok(tool_set) => tool_set,
        Err(error) => panic!("the declared tool set is valid: {error}"),
    }
}

/// One declared tool-invocation request by position, slot, and schema digest.
fn request(position: u32, slot: &ToolSlotId, schema_digest: &str) -> ToolInvocationRequest {
    match ToolInvocationRequest::new(position, slot.clone(), schema_digest) {
        Ok(request) => request,
        Err(error) => panic!("the declared request at position {position} is valid: {error}"),
    }
}

/// One declared parent session identity.
fn session(name: &str) -> SessionId {
    match SessionId::new(name) {
        Ok(session) => session,
        Err(error) => panic!("the declared session {name} is valid: {error}"),
    }
}

/// One declared round identity of one session.
fn round_at(session: &SessionId, accepted_position: u32, ordinal: u64) -> RoundId {
    RoundId::derive(session, accepted_position, ordinal)
}

/// One declared fulfilled binding fact.
fn fact(property: FulfillmentProperty, state: FulfillmentState) -> BindingFact {
    match BindingFact::new(property, state) {
        Ok(fact) => fact,
        Err(error) => panic!(
            "the declared fact of {} is valid: {error}",
            property.wire_name()
        ),
    }
}

/// One declared binding revision with an empty explicit name map.
fn binding(provider: &str, revision: u64, facts: &[BindingFact]) -> AgentBindingRevision {
    match AgentBindingRevision::new(provider, revision, facts, ProviderNameMap::empty()) {
        Ok(binding) => binding,
        Err(error) => panic!("the declared binding {provider} is valid: {error}"),
    }
}

/// One settled successful tool result of one request position.
fn settled_result(position: u32) -> ToolResultRecord {
    match ToolResultRecord::new(position, "ok", false) {
        Ok(record) => record,
        Err(error) => panic!("the declared result at position {position} is valid: {error}"),
    }
}

/// Returns the typed refusal of one declared operation that must be refused.
fn refusal<T>(result: Result<T, AgentError>) -> AgentError {
    match result {
        Ok(_) => panic!("the declared operation must be refused"),
        Err(error) => error,
    }
}

/// Asserts one closed vocabulary is sorted by wire name and strictly decodes.
fn assert_vocabulary_closed<T>(
    members: &[T],
    wire_name: fn(T) -> &'static str,
    from_wire_name: fn(&str) -> Option<T>,
) where
    T: Copy + std::fmt::Debug + PartialEq,
{
    let mut prior: Option<&'static str> = None;
    for member in members {
        let wire = wire_name(*member);
        if let Some(previous) = prior {
            assert!(
                previous < wire,
                "the vocabulary must be sorted by wire name: {previous} then {wire}"
            );
        }
        assert_eq!(
            from_wire_name(wire),
            Some(*member),
            "the wire spelling `{wire}` must strictly decode"
        );
        assert_eq!(from_wire_name("not-a-member"), None);
        prior = Some(wire);
    }
}

/// The workspace root of this test crate.
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crates/gantry-conformance must live under the workspace root"),
    }
}

/// Reads one required fixture file.
fn read(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("could not read {}: {error}", path.display()),
    }
}

/// Returns the text of one anchored clause up to the next anchor.
fn clause_text(specification: &str, anchor: &str, next: Option<&str>) -> String {
    let start_marker = format!("<a id=\"{anchor}\"></a>");
    let start = match specification.find(&start_marker) {
        Some(index) => index + start_marker.len(),
        None => panic!("SPEC.md must publish the anchor {anchor}"),
    };
    let end = match next {
        Some(next) => {
            let next_marker = format!("<a id=\"{next}\"></a>");
            match specification[start..].find(&next_marker) {
                Some(offset) => start + offset,
                None => panic!("SPEC.md must publish the next anchor {next}"),
            }
        }
        None => specification.len(),
    };
    specification[start..end].to_owned()
}

#[test]
fn agent_fulfillment_section_scope_and_closed_vocabulary_is_published() {
    assert_eq!(
        AGENT_CLAUSES.len(),
        11,
        "Section 25 publishes eleven clause anchors"
    );
    let specification = read(&workspace_root().join("SPEC.md"));
    let mut prior = 0_usize;
    for (index, clause) in AGENT_CLAUSES.iter().enumerate() {
        let marker = format!("<a id=\"{clause}\"></a>");
        let position = match specification.find(&marker) {
            Some(position) => position,
            None => panic!("SPEC.md must publish the anchor {clause}"),
        };
        assert!(
            position > prior,
            "the anchors of Section 25 appear in clause order"
        );
        prior = position;
        let next = AGENT_CLAUSES.get(index + 1).copied();
        let body = clause_text(&specification, clause, next);
        assert!(
            !body.trim().is_empty(),
            "the clause {clause} has a normative body"
        );
    }
    let scope = clause_text(&specification, AGENT_CLAUSES[0], Some(AGENT_CLAUSES[1]));
    for term in [
        "agent requirement",
        "fulfillment descriptor",
        "binding revision",
        "canonical assistant turn",
        "tool-set revision",
        "semantic stream",
        "progress observation",
        "provider name map",
        "agent non-claim",
    ] {
        assert!(
            scope.contains(term),
            "the section vocabulary must name `{term}`"
        );
    }
    assert!(scope.contains("**Applicability.**"));
    assert!(scope.contains("**Boundary.**"));
    assert_vocabulary_closed(
        &FulfillmentProperty::ALL,
        FulfillmentProperty::wire_name,
        FulfillmentProperty::from_wire_name,
    );
    assert_vocabulary_closed(
        &FulfillmentState::ALL,
        FulfillmentState::wire_name,
        FulfillmentState::from_wire_name,
    );
    assert_vocabulary_closed(
        &PreflightVerdict::ALL,
        PreflightVerdict::wire_name,
        PreflightVerdict::from_wire_name,
    );
    assert_vocabulary_closed(
        &TurnKind::ALL,
        TurnKind::wire_name,
        TurnKind::from_wire_name,
    );
    assert_vocabulary_closed(
        &TurnValidationCause::ALL,
        TurnValidationCause::wire_name,
        TurnValidationCause::from_wire_name,
    );
    assert_vocabulary_closed(
        &RepairOutcome::ALL,
        RepairOutcome::wire_name,
        RepairOutcome::from_wire_name,
    );
    assert_vocabulary_closed(
        &ToolSlotKind::ALL,
        ToolSlotKind::wire_name,
        ToolSlotKind::from_wire_name,
    );
    assert_vocabulary_closed(
        &HandlerKind::ALL,
        HandlerKind::wire_name,
        HandlerKind::from_wire_name,
    );
    assert_vocabulary_closed(
        &SessionDirective::ALL,
        SessionDirective::wire_name,
        SessionDirective::from_wire_name,
    );
    assert_vocabulary_closed(
        &StreamKind::ALL,
        StreamKind::wire_name,
        StreamKind::from_wire_name,
    );
    assert_vocabulary_closed(
        &AgentNonClaim::ALL,
        AgentNonClaim::wire_name,
        AgentNonClaim::from_wire_name,
    );
    assert_vocabulary_closed(
        &DiscoveryPhase::ALL,
        DiscoveryPhase::wire_name,
        DiscoveryPhase::from_wire_name,
    );
    assert_vocabulary_closed(
        &RoundState::ALL,
        RoundState::wire_name,
        RoundState::from_wire_name,
    );
    assert_vocabulary_closed(
        &AgentCrashCutClassification::ALL,
        AgentCrashCutClassification::wire_name,
        AgentCrashCutClassification::from_wire_name,
    );
    for (rank, cut) in DurableAgentCut::ALL.into_iter().enumerate() {
        assert_eq!(cut.rank(), rank as u8, "the cut chain is ordered");
        assert_eq!(DurableAgentCut::from_wire_name(cut.wire_name()), Some(cut));
        assert_eq!(cut.requirement(), AGENT_CLAUSES[5]);
    }
    let mut spellings = BTreeSet::new();
    let mut prior_code: Option<&str> = None;
    for code in AgentDiagnosticCode::ALL {
        let spelling = code.as_str();
        if let Some(previous) = prior_code {
            assert!(
                previous < spelling,
                "the diagnostic registry is sorted: {previous} then {spelling}"
            );
        }
        assert!(
            spellings.insert(spelling),
            "one distinct code per condition"
        );
        assert!(!code.meaning().is_empty(), "every code publishes a meaning");
        assert!(
            AGENT_CLAUSES.contains(&code.requirement()),
            "every code names a clause of this section"
        );
        prior_code = Some(spelling);
    }
    assert_eq!(spellings.len(), AgentDiagnosticCode::ALL.len());
}

#[test]
fn agent_requirements_declare_machine_checkable_fulfillment_properties() {
    let error = refusal(FulfillmentDescriptor::new(&[]));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::EmptyFulfillmentDeclaration
    );
    assert_eq!(error.requirement(), AGENT_CLAUSES[1]);
    let error = refusal(FulfillmentDescriptor::wildcard());
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::WildcardFulfillmentDeclaration
    );
    let error = refusal(FulfillmentDescriptor::new(&[
        FulfillmentProperty::Tools,
        FulfillmentProperty::Tools,
    ]));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::DuplicateFulfillmentProperty
    );
    let error = refusal(FulfillmentDescriptor::new(&[
        FulfillmentProperty::Tools,
        FulfillmentProperty::Context,
    ]));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::NoncanonicalFulfillmentOrder
    );
    assert_eq!(error.requirement(), AGENT_CLAUSES[1]);
    let descriptor = match FulfillmentDescriptor::new(&[
        FulfillmentProperty::Context,
        FulfillmentProperty::Tools,
    ]) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the declared descriptor is valid: {error}"),
    };
    assert_eq!(
        descriptor.properties(),
        [FulfillmentProperty::Context, FulfillmentProperty::Tools],
        "the canonical declaration order is preserved exactly as declared"
    );
    assert_eq!(descriptor.len(), 2);
    assert!(descriptor.contains(FulfillmentProperty::Tools));
    assert!(!descriptor.contains(FulfillmentProperty::Streaming));
    assert!(!descriptor.is_empty());
    for property in FulfillmentProperty::ALL {
        assert_eq!(property.requirement(), AGENT_CLAUSES[1]);
    }
    let first = match AgentRequirement::new("pkg", "agent", descriptor.clone()) {
        Ok(requirement) => requirement,
        Err(error) => panic!("the declared requirement is valid: {error}"),
    };
    let second = match AgentRequirement::new("pkg", "agent", descriptor.clone()) {
        Ok(requirement) => requirement,
        Err(error) => panic!("the declared requirement is valid: {error}"),
    };
    assert_eq!(
        first.id(),
        second.id(),
        "equal declared inputs derive equal ids"
    );
    assert_eq!(first.package(), "pkg");
    assert_eq!(first.descriptor(), &descriptor);
    let other = match AgentRequirement::new("other", "agent", descriptor) {
        Ok(requirement) => requirement,
        Err(error) => panic!("the declared requirement is valid: {error}"),
    };
    assert_ne!(
        first.id(),
        other.id(),
        "the declaring package is part of the identity"
    );
    let error = refusal(AgentRequirement::new(
        "",
        "agent",
        first.descriptor().clone(),
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    assert_eq!(error.requirement(), AGENT_CLAUSES[1]);
}

#[test]
fn preflight_refuses_an_unsupported_property_and_names_it() {
    let descriptor = match FulfillmentDescriptor::new(&[
        FulfillmentProperty::Modalities,
        FulfillmentProperty::Retrieval,
        FulfillmentProperty::Tools,
    ]) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the declared descriptor is valid: {error}"),
    };
    let requirement = match AgentRequirement::new("pkg", "agent", descriptor) {
        Ok(requirement) => requirement,
        Err(error) => panic!("the declared requirement is valid: {error}"),
    };
    let partial = binding(
        "provider",
        1,
        &[
            fact(FulfillmentProperty::Modalities, FulfillmentState::Bound),
            fact(FulfillmentProperty::Tools, FulfillmentState::Unsupported),
        ],
    );
    let report = preflight(&requirement, &partial);
    assert_eq!(report.verdict(), PreflightVerdict::Unsupported);
    assert_eq!(report.unsupported(), Some(FulfillmentProperty::Tools));
    assert_eq!(report.missing(), Some(FulfillmentProperty::Retrieval));
    assert_eq!(report.refused_property(), Some(FulfillmentProperty::Tools));
    assert!(!report.is_complete());
    assert_eq!(report.verdicts().len(), 3);
    let error = refusal(report.require_complete());
    assert_eq!(error.code(), AgentDiagnosticCode::PreflightRefused);
    assert!(
        error.detail().contains("tools"),
        "the refusal names the exact unsupported property"
    );
    let incomplete = preflight(
        &requirement,
        &binding(
            "provider",
            2,
            &[fact(
                FulfillmentProperty::Modalities,
                FulfillmentState::Bound,
            )],
        ),
    );
    assert_eq!(incomplete.verdict(), PreflightVerdict::Incomplete);
    assert_eq!(
        incomplete.refused_property(),
        Some(FulfillmentProperty::Retrieval)
    );
    let error = refusal(incomplete.require_complete());
    assert!(
        error.detail().contains("retrieval"),
        "the refusal names the exact missing property"
    );
    let complete = preflight(
        &requirement,
        &binding(
            "provider",
            3,
            &[
                fact(FulfillmentProperty::Modalities, FulfillmentState::Bound),
                fact(FulfillmentProperty::Retrieval, FulfillmentState::Bound),
                fact(FulfillmentProperty::Tools, FulfillmentState::Bound),
            ],
        ),
    );
    assert_eq!(complete.verdict(), PreflightVerdict::Complete);
    assert!(complete.is_complete());
    assert!(complete.require_complete().is_ok());
    let error = refusal(BindingFact::new(
        FulfillmentProperty::Tools,
        FulfillmentState::Missing,
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::MissingBindingFactState);
    let error = refusal(AgentBindingRevision::new(
        "provider",
        4,
        &[
            fact(FulfillmentProperty::Tools, FulfillmentState::Bound),
            fact(FulfillmentProperty::Tools, FulfillmentState::Unsupported),
        ],
        ProviderNameMap::empty(),
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateBindingFact);
    let error = refusal(AgentBindingRevision::new(
        "provider",
        8,
        &[
            fact(FulfillmentProperty::Tools, FulfillmentState::Bound),
            fact(FulfillmentProperty::Modalities, FulfillmentState::Bound),
        ],
        ProviderNameMap::empty(),
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::NoncanonicalBindingFactOrder
    );
    assert_eq!(error.requirement(), AGENT_CLAUSES[2]);
    let read_slot = slot("pkg", "read");
    let name_map = match ProviderNameMap::new(&[("read_file", read_slot.clone())]) {
        Ok(name_map) => name_map,
        Err(error) => panic!("the declared name map is valid: {error}"),
    };
    match name_map.resolve("read_file") {
        Some(resolved) => assert_eq!(resolved.as_str(), read_slot.as_str()),
        None => panic!("the explicit provider name must resolve"),
    }
    assert!(
        name_map.resolve("Read File").is_none(),
        "a display spelling the map does not name never resolves"
    );
    let error = refusal(ProviderNameMap::new(&[("*", read_slot.clone())]));
    assert_eq!(error.code(), AgentDiagnosticCode::WildcardProviderName);
    let error = refusal(ProviderNameMap::new(&[
        ("read_file", read_slot.clone()),
        ("read_file", read_slot),
    ]));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateProviderName);
    let source = binding("provider", 5, &[]);
    let discovered = binding("provider", 6, &[]);
    let artifact = match DiscoveryArtifact::discover(DiscoveryPhase::Preflight, source, discovered)
    {
        Ok(artifact) => artifact,
        Err(error) => panic!("the declared discovery is valid: {error}"),
    };
    assert_eq!(artifact.phase(), DiscoveryPhase::Preflight);
    assert_eq!(artifact.source().revision(), 5);
    assert_eq!(artifact.discovered().revision(), 6);
    assert_eq!(artifact.into_revision().revision(), 6);
    let error = refusal(DiscoveryArtifact::discover(
        DiscoveryPhase::Analyze,
        binding("provider", 7, &[]),
        binding("provider", 7, &[]),
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::UnchangedDiscoveryArtifact
    );
}

#[test]
fn assistant_turns_are_exactly_final_or_nonempty_tools() {
    let read_slot = slot("pkg", "read");
    let write_slot = slot("pkg", "write");
    let read_schema = "schema:read:v1";
    let write_schema = "schema:write:v1";
    let tool_set = build_tool_set(
        1,
        vec![
            descriptor("pkg", "read", "read_file", read_schema),
            descriptor("pkg", "write", "write_file", write_schema),
        ],
    );
    let error = refusal(Turn::tools(Vec::new()));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyToolSet);
    assert_eq!(error.requirement(), AGENT_CLAUSES[3]);
    let error = refusal(Turn::mixed(
        "done",
        vec![request(0, &read_slot, read_schema)],
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::MixedFinalAndTools);
    let final_turn = match Turn::final_text("done") {
        Ok(turn) => turn,
        Err(error) => panic!("the declared final turn is valid: {error}"),
    };
    assert_eq!(final_turn.kind(), TurnKind::Final);
    assert!(final_turn.is_final());
    assert_eq!(final_turn.tool_requests().len(), 0);
    let tools_turn = match Turn::tools(vec![
        request(1, &write_slot, write_schema),
        request(0, &read_slot, read_schema),
    ]) {
        Ok(turn) => turn,
        Err(error) => panic!("the declared tool turn is valid: {error}"),
    };
    assert_eq!(tools_turn.kind(), TurnKind::Tools);
    assert_eq!(tools_turn.tool_requests()[0].position(), 0);
    assert_eq!(tools_turn.tool_requests()[1].position(), 1);
    let error = refusal(Turn::tools(vec![
        request(0, &read_slot, read_schema),
        request(0, &write_slot, write_schema),
    ]));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateToolPosition);
    let empty = validate_raw_response(&RawResponse::tools(Vec::new()), &tool_set);
    assert_eq!(empty.cause(), Some(TurnValidationCause::EmptyResponse));
    let empty_final = validate_raw_response(&RawResponse::text("   "), &tool_set);
    assert_eq!(
        empty_final.cause(),
        Some(TurnValidationCause::EmptyFinalResult)
    );
    let mixed = validate_raw_response(
        &RawResponse::mixed("done", vec![request(0, &read_slot, read_schema)]),
        &tool_set,
    );
    assert_eq!(mixed.cause(), Some(TurnValidationCause::MixedFinalAndTools));
    let refused = validate_raw_response(&RawResponse::refusal(), &tool_set);
    let malformed = validate_raw_response(&RawResponse::malformed(), &tool_set);
    assert_eq!(refused, TurnOutcome::Refused);
    assert_eq!(malformed, TurnOutcome::Malformed);
    assert_ne!(
        refused, malformed,
        "a refusal and a malformed response are distinct outcomes"
    );
    assert!(!refused.is_accepted());
    let unknown = validate_raw_response(
        &RawResponse::tools(vec![request(0, &slot("pkg", "missing"), read_schema)]),
        &tool_set,
    );
    assert_eq!(unknown.cause(), Some(TurnValidationCause::UnknownToolSlot));
    let mismatch = validate_raw_response(
        &RawResponse::tools(vec![request(0, &read_slot, "schema:other")]),
        &tool_set,
    );
    assert_eq!(mismatch.cause(), Some(TurnValidationCause::SchemaMismatch));
    let duplicate_slot = validate_raw_response(
        &RawResponse::tools(vec![
            request(0, &read_slot, read_schema),
            request(1, &read_slot, read_schema),
        ]),
        &tool_set,
    );
    assert_eq!(
        duplicate_slot.cause(),
        Some(TurnValidationCause::DuplicateToolSlot)
    );
    let outside_order = validate_raw_response(
        &RawResponse::tools(vec![
            request(0, &read_slot, read_schema),
            request(2, &write_slot, write_schema),
        ]),
        &tool_set,
    );
    assert_eq!(
        outside_order.cause(),
        Some(TurnValidationCause::PositionOutsideFrozenOrder)
    );
    let stale = validate_raw_response(
        &RawResponse::text("done").against(&build_tool_set(
            2,
            vec![descriptor("pkg", "read", "read_file", read_schema)],
        )),
        &tool_set,
    );
    assert_eq!(
        stale.cause(),
        Some(TurnValidationCause::StaleToolSetRevision)
    );
    let accepted = validate_raw_response(
        &RawResponse::tools(vec![
            request(1, &write_slot, write_schema),
            request(0, &read_slot, read_schema),
        ]),
        &tool_set,
    );
    match accepted.accepted_turn() {
        Some(turn) => {
            assert_eq!(turn.turn().kind(), TurnKind::Tools);
            assert_eq!(turn.turn().tool_requests().len(), 2);
            assert_eq!(turn.turn().tool_requests()[0].position(), 0);
        }
        None => panic!("the whole valid turn must be accepted"),
    }
    assert_eq!(
        TurnValidationCause::from_wire_name("authority-requirement-refused"),
        None,
        "the invocation authority requirement is refused by the GNT-25.6 diagnostic, not a turn cause"
    );
    assert_eq!(
        TurnValidationCause::from_wire_name("effect-exceeds-admission"),
        None,
        "the admitted effect set is refused by the GNT-25.6 diagnostic, not a turn cause"
    );
    assert_eq!(
        AgentDiagnosticCode::AuthorityRequirementRefused.requirement(),
        AGENT_CLAUSES[6]
    );
    assert_eq!(
        AgentDiagnosticCode::EffectExceedsAdmission.requirement(),
        AGENT_CLAUSES[6]
    );
    let mut spellings = BTreeSet::new();
    for cause in TurnValidationCause::ALL {
        assert!(
            spellings.insert(cause.as_str()),
            "each cause owns its spelling"
        );
    }
    assert_eq!(spellings.len(), TurnValidationCause::ALL.len());
}

#[test]
fn turn_repair_is_bounded_and_a_rejected_prefix_never_dispatches() {
    let read_slot = slot("pkg", "read");
    let schema = "schema:read:v1";
    let tool_set = build_tool_set(1, vec![descriptor("pkg", "read", "read_file", schema)]);
    let error = refusal(RepairPolicy::new(0));
    assert_eq!(error.code(), AgentDiagnosticCode::ZeroRepairBound);
    assert_eq!(error.requirement(), AGENT_CLAUSES[4]);
    let bounded = match RepairPolicy::new(2) {
        Ok(policy) => policy,
        Err(error) => panic!("the declared repair policy is valid: {error}"),
    };
    assert_eq!(bounded.max_attempts(), 2);
    let mut budget = RepairBudget::new(bounded);
    assert_eq!(budget.used(), 0);
    assert_eq!(budget.remaining(), 2);
    let first = match budget.admit_attempt() {
        Ok(permit) => permit,
        Err(error) => panic!("the first bounded attempt is admitted: {error}"),
    };
    assert_eq!(first.attempt(), 1);
    let second = match budget.admit_attempt() {
        Ok(permit) => permit,
        Err(error) => panic!("the second bounded attempt is admitted: {error}"),
    };
    assert_eq!(second.attempt(), 2);
    assert_eq!(budget.used(), 2);
    assert_eq!(budget.remaining(), 0);
    let error = refusal(budget.admit_attempt());
    assert_eq!(error.code(), AgentDiagnosticCode::RepairBoundExhausted);
    let invalid = RawResponse::tools(vec![request(0, &slot("pkg", "missing"), schema)]);
    let rejected = validate_raw_response(&invalid, &tool_set);
    assert_eq!(rejected.cause(), Some(TurnValidationCause::UnknownToolSlot));
    assert_eq!(classify_original_turn(&rejected), RepairOutcome::Refused);
    let prefix = RejectedPrefix::of(&invalid, TurnValidationCause::UnknownToolSlot);
    assert_eq!(prefix.request_count(), 1);
    assert_eq!(prefix.cause(), TurnValidationCause::UnknownToolSlot);
    assert_eq!(prefix.requests().len(), 1);
    let error = refusal(prefix.admit_dispatch());
    assert_eq!(error.code(), AgentDiagnosticCode::PrefixDispatchRefused);
    assert_eq!(error.requirement(), AGENT_CLAUSES[4]);
    let one_attempt = match RepairPolicy::new(1) {
        Ok(policy) => policy,
        Err(error) => panic!("the declared repair policy is valid: {error}"),
    };
    let mut budget = RepairBudget::new(one_attempt);
    let refused_repair = repair_turn(
        RejectedPrefix::of(&invalid, TurnValidationCause::UnknownToolSlot),
        &mut budget,
        &invalid,
        &tool_set,
    );
    assert_eq!(refused_repair, RepairOutcome::Refused);
    assert_eq!(budget.used(), 1);
    let exhausted = repair_turn(
        RejectedPrefix::of(&invalid, TurnValidationCause::UnknownToolSlot),
        &mut budget,
        &invalid,
        &tool_set,
    );
    assert_eq!(exhausted, RepairOutcome::Exhausted);
    let mut budget = RepairBudget::new(one_attempt);
    let repaired = repair_turn(
        RejectedPrefix::of(&invalid, TurnValidationCause::UnknownToolSlot),
        &mut budget,
        &RawResponse::tools(vec![request(0, &read_slot, schema)]),
        &tool_set,
    );
    assert_eq!(repaired, RepairOutcome::Repaired);
    let accepted = validate_raw_response(
        &RawResponse::tools(vec![request(0, &read_slot, schema)]),
        &tool_set,
    );
    assert_eq!(classify_original_turn(&accepted), RepairOutcome::Accepted);
}

#[test]
fn rounds_have_stable_identity_and_durable_cuts_without_repeats() {
    let parent = session("session-a");
    let other_session = session("session-b");
    let round = round_at(&parent, 0, 0);
    assert_eq!(round.as_str(), round_at(&parent, 0, 0).as_str());
    assert_ne!(round.as_str(), round_at(&parent, 0, 1).as_str());
    assert_ne!(round.as_str(), round_at(&parent, 1, 0).as_str());
    assert_ne!(round.as_str(), round_at(&other_session, 0, 0).as_str());
    let error = refusal(DurableAgentCut::Raw.advance(DurableAgentCut::ToolResults));
    assert_eq!(error.code(), AgentDiagnosticCode::CutSkip);
    let error = refusal(DurableAgentCut::ToolResults.advance(DurableAgentCut::Raw));
    assert_eq!(error.code(), AgentDiagnosticCode::CutRegression);
    assert_eq!(
        DurableAgentCut::Raw.advance(DurableAgentCut::Raw),
        Ok(DurableAgentCut::Raw),
        "advancing to the same cut stutters and commits nothing twice"
    );
    assert_eq!(
        DurableAgentCut::Raw.advance(DurableAgentCut::Accepted),
        Ok(DurableAgentCut::Accepted)
    );
    assert_eq!(
        DurableAgentCut::Accepted.advance(DurableAgentCut::ToolResults),
        Ok(DurableAgentCut::ToolResults)
    );
    assert_eq!(
        DurableAgentCut::ToolResults.advance(DurableAgentCut::Final),
        Ok(DurableAgentCut::Final)
    );
    assert_eq!(
        RoundState::AwaitingRaw.advance(RoundState::Validating),
        Ok(RoundState::Validating)
    );
    assert_eq!(
        RoundState::Validating.advance(RoundState::Accepted),
        Ok(RoundState::Accepted)
    );
    assert_eq!(
        RoundState::Accepted.advance(RoundState::Final),
        Ok(RoundState::Final)
    );
    let error = refusal(RoundState::Final.advance(RoundState::Dispatching));
    assert_eq!(error.code(), AgentDiagnosticCode::IllegalRoundTransition);
    let read_slot = slot("pkg", "read");
    let write_slot = slot("pkg", "write");
    let read_schema = "schema:read:v1";
    let write_schema = "schema:write:v1";
    let tool_set = build_tool_set(
        1,
        vec![
            descriptor("pkg", "read", "read_file", read_schema),
            descriptor("pkg", "write", "write_file", write_schema),
        ],
    );
    let raw = RawResponse::tools(vec![
        request(0, &read_slot, read_schema),
        request(1, &write_slot, write_schema),
    ]);
    let accepted = validate_raw_response(&raw, &tool_set);
    let accepted_turn = match accepted.accepted_turn() {
        Some(turn) => turn.clone(),
        None => panic!("the whole valid turn must be accepted"),
    };
    let final_turn = match Turn::final_text("done") {
        Ok(turn) => turn,
        Err(error) => panic!("the declared final turn is valid: {error}"),
    };
    let mut record = DurableAgentRecord::open(round.clone(), &raw);
    assert_eq!(record.round(), &round);
    assert_eq!(record.cut(), DurableAgentCut::Raw);
    assert!(record.verify_presented_raw(&raw).is_ok());
    assert_eq!(
        record.crash_cut(),
        AgentCrashCutClassification::RawCommitted
    );
    assert_eq!(record.resume(), AgentRecoveryDecision::RawValidation);
    assert!(record.accepted_turn().is_none());
    let error = refusal(record.verify_presented_turn(&final_turn));
    assert_eq!(error.code(), AgentDiagnosticCode::CutNotCommitted);
    let vector = match ToolResultVector::settle(&[settled_result(1), settled_result(0)], 2) {
        Ok(vector) => vector,
        Err(error) => panic!("the declared settlement is valid: {error}"),
    };
    let error = refusal(record.commit_tool_results(vector.clone()));
    assert_eq!(error.code(), AgentDiagnosticCode::IllegalRoundTransition);
    assert!(record.commit_accepted(accepted_turn.clone()).is_ok());
    assert_eq!(record.cut(), DurableAgentCut::Accepted);
    assert!(
        record.verify_presented_raw(&raw).is_ok(),
        "the committed raw witness survives the accepted cut"
    );
    assert_eq!(
        record.crash_cut(),
        AgentCrashCutClassification::AcceptedCommitted
    );
    assert_eq!(
        record.resume(),
        AgentRecoveryDecision::AcceptedDispatch { next_position: 0 },
        "recovery resumes child dispatch at the first unsettled request position"
    );
    assert_eq!(record.resume().next_position(), Some(0));
    assert!(record.verify_presented_turn(accepted_turn.turn()).is_ok());
    let error = refusal(record.verify_presented_turn(&final_turn));
    assert_eq!(error.code(), AgentDiagnosticCode::CommittedValueDiffers);
    let error = refusal(record.commit_accepted(accepted_turn.clone()));
    assert_eq!(error.code(), AgentDiagnosticCode::CutAlreadyCommitted);
    assert_eq!(
        record
            .accepted_turn()
            .map(|turn| turn.turn().tool_requests().len()),
        Some(2),
        "the committed accepted turn is preserved without repeating it"
    );
    let premature = match FinalResult::new("done") {
        Ok(final_result) => final_result,
        Err(error) => panic!("the declared final result is valid: {error}"),
    };
    let error = refusal(record.commit_final(premature));
    assert_eq!(error.code(), AgentDiagnosticCode::IllegalRoundTransition);
    assert!(record.commit_tool_results(vector).is_ok());
    assert_eq!(record.cut(), DurableAgentCut::ToolResults);
    assert_eq!(
        record.crash_cut(),
        AgentCrashCutClassification::ToolResultsCommitted
    );
    assert_eq!(record.resume(), AgentRecoveryDecision::FinalAssembly);
    assert_eq!(
        record.settled_results().map(ToolResultVector::positions),
        Some(vec![0, 1]),
        "the settled positions are preserved in canonical request order"
    );
    let committed = match FinalResult::new("done") {
        Ok(final_result) => final_result,
        Err(error) => panic!("the declared final result is valid: {error}"),
    };
    assert!(record.commit_final(committed.clone()).is_ok());
    assert_eq!(record.cut(), DurableAgentCut::Final);
    assert_eq!(
        record.crash_cut(),
        AgentCrashCutClassification::FinalCommitted
    );
    assert_eq!(record.resume(), AgentRecoveryDecision::CommittedFinal);
    assert_eq!(record.final_result(), Some(&committed));
    assert!(record.verify_presented_final(&committed).is_ok());
    let other = match FinalResult::new("other") {
        Ok(final_result) => final_result,
        Err(error) => panic!("the declared final result is valid: {error}"),
    };
    let error = refusal(record.verify_presented_final(&other));
    assert_eq!(error.code(), AgentDiagnosticCode::CommittedValueDiffers);
    let error = refusal(record.commit_final(committed));
    assert_eq!(error.code(), AgentDiagnosticCode::CutAlreadyCommitted);
    let final_raw = RawResponse::text("done");
    let mut final_only = DurableAgentRecord::open(round_at(&parent, 1, 2), &final_raw);
    let final_turn_accepted = match validate_raw_response(&final_raw, &tool_set).accepted_turn() {
        Some(turn) => turn.clone(),
        None => panic!("the final turn must be accepted"),
    };
    assert!(final_only.commit_accepted(final_turn_accepted).is_ok());
    let final_only_result = match FinalResult::new("done") {
        Ok(final_result) => final_result,
        Err(error) => panic!("the declared final result is valid: {error}"),
    };
    assert!(final_only.commit_final(final_only_result).is_ok());
    assert_eq!(final_only.cut(), DurableAgentCut::Final);
}

#[test]
fn tool_slots_are_package_qualified_and_tool_sets_are_immutable() {
    let error = refusal(ToolSlotId::derive("", "read"));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    assert_eq!(error.requirement(), AGENT_CLAUSES[1]);
    let error = refusal(ToolSlotId::derive("pkg", "   "));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    let read = descriptor("pkg", "read", "read_file", "schema:read:v1");
    let write = descriptor("pkg", "write", "write_file", "schema:write:v1");
    let error = refusal(ToolSetRevision::new(
        1,
        ordered(vec![
            descriptor("pkg", "read", "same", "schema:read:v1"),
            descriptor("pkg", "write", "same", "schema:write:v1"),
        ]),
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateProviderName);
    let error = refusal(ToolSetRevision::new(
        1,
        ordered(vec![read.clone(), read.clone()]),
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateToolSlot);
    let mut descending = ordered(vec![read.clone(), write.clone()]);
    descending.reverse();
    let error = refusal(ToolSetRevision::new(1, descending));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::NoncanonicalDescriptorOrder
    );
    let rebuilt = build_tool_set(1, vec![read.clone(), write.clone()]);
    let mut frozen = build_tool_set(1, vec![read.clone(), write.clone()]);
    assert_eq!(frozen.id(), rebuilt.id());
    let changed = build_tool_set(
        1,
        vec![
            descriptor("pkg", "read", "read_file", "schema:read:v2"),
            write.clone(),
        ],
    );
    assert_ne!(frozen.id(), changed.id());
    let id = frozen.id().clone();
    let error =
        refusal(frozen.add_descriptor(descriptor("pkg", "extra", "extra_file", "schema:extra:v1")));
    assert_eq!(error.code(), AgentDiagnosticCode::ImmutableToolSetRevision);
    assert_eq!(error.requirement(), AGENT_CLAUSES[6]);
    assert_eq!(frozen.descriptors().len(), 2);
    assert_eq!(frozen.id(), &id);
    assert_eq!(frozen.revision(), 1);
    assert!(frozen.descriptor_for(read.slot()).is_some());
    assert!(frozen.descriptor_for(&slot("pkg", "missing")).is_none());
    assert!(
        frozen
            .admit_invocation(&request(0, read.slot(), "schema:read:v1"))
            .is_ok()
    );
    let error =
        refusal(frozen.admit_invocation(&request(0, &slot("pkg", "missing"), "schema:read:v1")));
    assert_eq!(error.code(), AgentDiagnosticCode::UnknownToolSlot);
    let error = refusal(frozen.admit_invocation(&request(0, read.slot(), "schema:other")));
    assert_eq!(error.code(), AgentDiagnosticCode::SchemaMismatch);
    let error = refusal(read.check_effects(EffectSet::default()));
    assert_eq!(error.code(), AgentDiagnosticCode::EffectExceedsAdmission);
    assert!(read.check_effects(effects(&[Effect::Prompt])).is_ok());
    let error = refusal(read.check_authority(false));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::AuthorityRequirementRefused
    );
    assert!(read.check_authority(true).is_ok());
    assert!(read.admits_schema("schema:read:v1"));
    assert!(!read.admits_schema("schema:read:v2"));
    assert_eq!(read.kind(), ToolSlotKind::SourceHandler);
    assert_eq!(read.recovery(), RecoveryClass::Idempotent);
    assert_eq!(read.retry(), RetryEligibility::Eligible);
    assert_eq!(read.effects(), effects(&[Effect::Prompt]));
}

#[test]
fn source_handlers_keep_callable_semantics_and_ordered_settlement() {
    let read_slot = slot("pkg", "read");
    let mut single_use = HandlerUse::admit(HandlerKind::FnOnce, read_slot.clone());
    assert_eq!(single_use.kind(), HandlerKind::FnOnce);
    assert_eq!(single_use.slot(), &read_slot);
    assert!(!single_use.is_consumed());
    assert!(single_use.call().is_ok());
    assert!(single_use.is_consumed());
    assert_eq!(single_use.calls(), 1);
    let error = refusal(single_use.call());
    assert_eq!(error.code(), AgentDiagnosticCode::HandlerAlreadyConsumed);
    assert_eq!(error.requirement(), AGENT_CLAUSES[7]);
    assert_eq!(
        single_use.calls(),
        1,
        "a refused replay never consumes the handler twice"
    );
    let mut shared = HandlerUse::admit(HandlerKind::Fn, read_slot.clone());
    for _ in 0..3 {
        assert!(shared.call().is_ok());
    }
    assert_eq!(shared.calls(), 3);
    assert!(!shared.is_consumed());
    let mut exclusive = HandlerUse::admit(HandlerKind::FnMut, read_slot);
    assert!(exclusive.call().is_ok());
    assert!(exclusive.call().is_ok());
    assert_eq!(exclusive.calls(), 2);
    assert!(!exclusive.is_consumed());
    assert!(HandlerKind::Fn.admits_repeated_invocations());
    assert!(HandlerKind::FnMut.admits_repeated_invocations());
    assert!(!HandlerKind::FnOnce.admits_repeated_invocations());
    let first = settled_result(0);
    let second = settled_result(1);
    let third = match ToolResultRecord::new(2, "failed", true) {
        Ok(record) => record,
        Err(error) => panic!("the declared result is valid: {error}"),
    };
    let completion_order =
        match ToolResultVector::settle(&[third.clone(), first.clone(), second.clone()], 3) {
            Ok(vector) => vector,
            Err(error) => panic!("the declared settlement is valid: {error}"),
        };
    let another_order =
        match ToolResultVector::settle(&[second.clone(), third.clone(), first.clone()], 3) {
            Ok(vector) => vector,
            Err(error) => panic!("the declared settlement is valid: {error}"),
        };
    assert_eq!(
        completion_order, another_order,
        "settlement is independent of completion order"
    );
    assert_eq!(completion_order.positions(), vec![0, 1, 2]);
    assert_eq!(completion_order.len(), 3);
    assert!(!completion_order.is_empty());
    assert_eq!(completion_order.results()[0].code(), "ok");
    assert!(!completion_order.results()[0].failed());
    assert!(completion_order.results()[2].failed());
    let error = refusal(ToolResultVector::settle(&[first.clone(), first.clone()], 1));
    assert_eq!(error.code(), AgentDiagnosticCode::DuplicateToolResult);
    let error = refusal(ToolResultVector::settle(std::slice::from_ref(&first), 2));
    assert_eq!(error.code(), AgentDiagnosticCode::MissingToolResult);
    let error = refusal(ToolResultVector::settle(&[settled_result(3)], 3));
    assert_eq!(error.code(), AgentDiagnosticCode::UnknownToolPosition);
    let error = refusal(ToolResultRecord::new(0, "", false));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    assert_eq!(error.requirement(), AGENT_CLAUSES[7]);
}

#[test]
fn sessions_reserve_the_parent_and_derive_stable_children() {
    let error = refusal(SessionId::new(""));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    assert_eq!(error.requirement(), AGENT_CLAUSES[8]);
    let parent = session("parent");
    let other_parent = session("other");
    let round = round_at(&parent, 0, 0);
    let other_round = round_at(&parent, 1, 1);
    let mut registry = SessionReservations::new();
    let error = refusal(registry.reserve(&parent, &round, 0));
    assert_eq!(error.code(), AgentDiagnosticCode::NoOpenToolRequests);
    let reservation = match registry.reserve(&parent, &round, 2) {
        Ok(reservation) => reservation,
        Err(error) => panic!("the declared reservation is valid: {error}"),
    };
    assert!(registry.is_reserved(&parent));
    assert!(registry.holds(&parent, &round));
    assert!(!registry.holds(&parent, &other_round));
    assert!(!registry.is_reserved(&other_parent));
    assert_eq!(reservation.parent(), &parent);
    assert_eq!(reservation.round(), &round);
    assert_eq!(reservation.open_tool_requests(), 2);
    assert!(!reservation.is_released(&registry));
    let error = refusal(registry.reserve(&parent, &round, 1));
    assert_eq!(error.code(), AgentDiagnosticCode::SecondReservation);
    assert_eq!(reservation.directive(true), SessionDirective::RefuseReentry);
    assert_eq!(reservation.directive(false), SessionDirective::DeriveChild);
    let error = refusal(reservation.reenter_parent());
    assert_eq!(error.code(), AgentDiagnosticCode::ParentReentryRefused);
    assert_eq!(error.requirement(), AGENT_CLAUSES[8]);
    let child_two = match reservation.derive_child(&registry, 2) {
        Ok(child) => child,
        Err(error) => panic!("the declared child is valid: {error}"),
    };
    let child_two_again = match reservation.derive_child(&registry, 2) {
        Ok(child) => child,
        Err(error) => panic!("the declared child is valid: {error}"),
    };
    assert_eq!(
        child_two.id(),
        child_two_again.id(),
        "a repeated derivation returns the same stable child identity"
    );
    assert_eq!(child_two.ordinal(), 2);
    assert_eq!(child_two.parent(), &parent);
    assert_ne!(child_two.id().as_str(), parent.as_str());
    let child_three = match reservation.derive_child(&registry, 3) {
        Ok(child) => child,
        Err(error) => panic!("the declared child is valid: {error}"),
    };
    assert_ne!(child_two.id(), child_three.id());
    assert_ne!(child_two.id(), &ChildSessionId::derive(&other_parent, 2));
    // The registry is the single authority: its release refuses derivation through the
    // outstanding handle before the handle itself was ever released.
    assert!(registry.release(&parent).is_ok());
    assert!(!registry.is_reserved(&parent));
    assert!(reservation.is_released(&registry));
    let error = refusal(reservation.derive_child(&registry, 4));
    assert_eq!(error.code(), AgentDiagnosticCode::ReservationReleased);
    assert_eq!(error.requirement(), AGENT_CLAUSES[8]);
    assert_eq!(registry.directive(&parent, true), SessionDirective::Resume);
    assert_eq!(registry.directive(&parent, false), SessionDirective::Admit);
    let error = refusal(registry.release(&parent));
    assert_eq!(error.code(), AgentDiagnosticCode::ReservationReleased);
    // A handle releases through the registry, and the removed reservation derives no
    // child afterwards and cannot be released twice.
    let second = match registry.reserve(&parent, &other_round, 1) {
        Ok(reservation) => reservation,
        Err(error) => panic!("the declared reservation is valid: {error}"),
    };
    assert!(second.derive_child(&registry, 1).is_ok());
    assert!(second.release(&mut registry).is_ok());
    assert!(!registry.is_reserved(&parent));
    assert!(second.is_released(&registry));
    let error = refusal(second.release(&mut registry));
    assert_eq!(error.code(), AgentDiagnosticCode::ReservationReleased);
    let error = refusal(second.derive_child(&registry, 1));
    assert_eq!(error.code(), AgentDiagnosticCode::ReservationReleased);
    assert_eq!(registry.directive(&parent, true), SessionDirective::Resume);
    assert_eq!(registry.directive(&parent, false), SessionDirective::Admit);
}

#[test]
fn semantic_streams_are_bounded_and_progress_is_nonsemantic() {
    let error = refusal(StreamId::new(""));
    assert_eq!(error.code(), AgentDiagnosticCode::EmptyDeclaredIdentity);
    assert_eq!(error.requirement(), AGENT_CLAUSES[9]);
    let id = match StreamId::new("tokens") {
        Ok(id) => id,
        Err(error) => panic!("the declared stream is valid: {error}"),
    };
    let owner = authority("tools-call");
    let other_owner = authority("other-tools");
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), None, Some(4), Some(16)),
        &owner,
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::UntypedSemanticStream);
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Progress), Some(4), Some(16)),
        &owner,
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::NonsemanticStreamPresentedAsSemantic
    );
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Semantic), Some(4), None),
        &owner,
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::UnboundedSemanticStream);
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Semantic), None, None),
        &owner,
    ));
    assert_eq!(error.code(), AgentDiagnosticCode::UnboundedSemanticStream);
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Progress), None, None),
        &owner,
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::NonsemanticStreamPresentedAsSemantic
    );
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Semantic), Some(4), Some(16)),
        &owner,
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::UnsafeSemanticStreamAuthority
    );
    assert_eq!(error.requirement(), AGENT_CLAUSES[9]);
    let error = refusal(SemanticStream::admit(
        StreamSpec::new(id.clone(), Some(StreamKind::Semantic), Some(4), Some(16))
            .with_authority(&other_owner),
        &owner,
    ));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::UnsafeSemanticStreamAuthority
    );
    let spec =
        StreamSpec::new(id, Some(StreamKind::Semantic), Some(4), Some(16)).with_authority(&owner);
    assert_eq!(spec.authority(), Some(&owner));
    let mut stream = match SemanticStream::admit(spec, &owner) {
        Ok(stream) => stream,
        Err(error) => panic!("the declared stream is valid: {error}"),
    };
    assert_eq!(stream.budget().max_items(), 4);
    assert_eq!(stream.budget().max_bytes(), 16);
    assert_eq!(stream.position(), 0);
    assert!(stream.admit_observation(4, 16).is_ok());
    let error = refusal(stream.admit_observation(5, 16));
    assert_eq!(error.code(), AgentDiagnosticCode::StreamBudgetExceeded);
    let error = refusal(stream.admit_observation(4, 17));
    assert_eq!(error.code(), AgentDiagnosticCode::StreamBudgetExceeded);
    assert!(
        stream
            .budget()
            .admit(StreamKind::Progress, u64::MAX, u64::MAX)
            .is_ok(),
        "nonsemantic progress never consumes the semantic budget"
    );
    assert!(!StreamKind::Progress.is_semantic());
    assert!(!StreamKind::Progress.affects_source_result());
    assert!(!StreamKind::Progress.advances_durable_cut());
    assert!(!StreamKind::Progress.grants_approval());
    assert!(StreamKind::Semantic.affects_source_result());
    assert!(StreamKind::Semantic.advances_durable_cut());
    assert!(!StreamKind::Semantic.grants_approval());
    assert!(stream.commit_position(1).is_ok());
    assert_eq!(stream.position(), 1);
    let error = refusal(stream.commit_position(1));
    assert_eq!(error.code(), AgentDiagnosticCode::StreamPositionRegression);
    let error = refusal(stream.commit_position(0));
    assert_eq!(error.code(), AgentDiagnosticCode::StreamPositionRegression);
    assert!(stream.commit_position(2).is_ok());
    assert_eq!(stream.position(), 2);
    // GNT-25.9 progress is nonsemantic: admission refuses any claim to settle an
    // accepted turn or a tool result, and both accessors are permanently false.
    let progress_record = DurableAgentRecord::open(
        round_at(&session("progress"), 0, 0),
        &RawResponse::text("done"),
    );
    let signal = match progress_record.admit_progress(false, false) {
        Ok(signal) => signal,
        Err(error) => panic!("an unclaiming progress observation is admitted: {error}"),
    };
    assert!(!signal.claims_accepted_turn());
    assert!(!signal.claims_tool_result());
    let error = refusal(progress_record.admit_progress(true, false));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::ProgressSettlementClaimRefused
    );
    assert_eq!(error.requirement(), AGENT_CLAUSES[9]);
    let error = refusal(progress_record.admit_progress(false, true));
    assert_eq!(
        error.code(),
        AgentDiagnosticCode::ProgressSettlementClaimRefused
    );
}

#[test]
fn agent_non_claims_are_closed_and_never_presented_as_guarantees() {
    assert_eq!(AgentNonClaim::ALL.len(), AGENT_NON_CLAIMS.len());
    assert_eq!(AGENT_NON_CLAIM_ORDER, AgentNonClaim::ALL);
    let mut statements = BTreeSet::new();
    for claim in AgentNonClaim::ALL {
        assert_eq!(claim.requirement(), AGENT_CLAUSES[10]);
        assert!(!claim.statement().is_empty());
        assert!(
            statements.insert(claim.statement()),
            "each non-claim publishes its own statement"
        );
    }
    assert_eq!(statements.len(), AGENT_NON_CLAIMS.len());
    assert!(
        check_agent_non_claims(&[AgentNonClaimAssertion::new(
            AgentNonClaim::PrefixDispatch,
            false,
        )])
        .is_ok()
    );
    let error = refusal(check_agent_non_claims(&[
        AgentNonClaimAssertion::new(AgentNonClaim::PrefixDispatch, false),
        AgentNonClaimAssertion::new(AgentNonClaim::MidLoopToolMutation, true),
    ]));
    assert_eq!(error.code(), AgentDiagnosticCode::NonClaimAsGuarantee);
    assert_eq!(error.requirement(), AGENT_CLAUSES[10]);
    assert!(error.detail().contains("mid-loop-tool-mutation"));
    let specification = read(&workspace_root().join("SPEC.md"));
    let body = clause_text(&specification, AGENT_CLAUSES[10], None);
    assert!(
        body.contains("closed vocabulary"),
        "the non-claims are a closed vocabulary"
    );
    assert!(body.contains("provider field name"));
    assert!(body.contains("rejected prefix"));
    assert!(body.contains("synthetic"));
    assert!(body.contains("mid-loop"));
    assert!(body.contains("display name"));
}

#[test]
fn partial_tool_result_settlement_is_refused_against_the_committed_turn() {
    // A two-request accepted turn settles only when both request positions settle: a
    // vector built with a caller-supplied expected count of one must not commit a
    // partial turn as a whole one, and the tool-result cut must stay uncommitted.
    let read_slot = slot("pkg", "read");
    let write_slot = slot("pkg", "write");
    let read_schema = "schema:read:v1";
    let write_schema = "schema:write:v1";
    let tool_set = build_tool_set(
        1,
        vec![
            descriptor("pkg", "read", "read_file", read_schema),
            descriptor("pkg", "write", "write_file", write_schema),
        ],
    );
    let parent = session("partial-settlement");
    let raw = RawResponse::tools(vec![
        request(0, &read_slot, read_schema),
        request(1, &write_slot, write_schema),
    ]);
    let accepted = validate_raw_response(&raw, &tool_set);
    let accepted_turn = match accepted.accepted_turn() {
        Some(turn) => turn.clone(),
        None => panic!("the whole valid turn must be accepted"),
    };
    let mut record = DurableAgentRecord::open(round_at(&parent, 0, 0), &raw);
    assert!(record.commit_accepted(accepted_turn).is_ok());
    assert_eq!(record.cut(), DurableAgentCut::Accepted);
    let partial = match ToolResultVector::settle(&[settled_result(0)], 1) {
        Ok(vector) => vector,
        Err(error) => panic!("the undeclared partial settlement is constructible: {error}"),
    };
    let error = refusal(record.commit_tool_results(partial));
    assert_eq!(error.code(), AgentDiagnosticCode::MissingToolResult);
    assert_eq!(error.requirement(), AGENT_CLAUSES[7]);
    assert_eq!(
        record.cut(),
        DurableAgentCut::Accepted,
        "a refused partial settlement leaves the tool-result cut uncommitted"
    );
    assert!(record.settled_results().is_none());
    let unknown = match ToolResultVector::settle(
        &[settled_result(0), settled_result(1), settled_result(2)],
        3,
    ) {
        Ok(vector) => vector,
        Err(error) => panic!("the undeclared settlement is constructible: {error}"),
    };
    let error = refusal(record.commit_tool_results(unknown));
    assert_eq!(error.code(), AgentDiagnosticCode::UnknownToolPosition);
    assert_eq!(record.cut(), DurableAgentCut::Accepted);
    let complete = match ToolResultVector::settle(&[settled_result(1), settled_result(0)], 2) {
        Ok(vector) => vector,
        Err(error) => panic!("the declared settlement is valid: {error}"),
    };
    assert!(record.commit_tool_results(complete).is_ok());
    assert_eq!(record.cut(), DurableAgentCut::ToolResults);
    assert_eq!(
        record.settled_results().map(ToolResultVector::positions),
        Some(vec![0, 1])
    );
}

#[test]
fn tool_set_revision_identity_covers_every_declared_descriptor_fact() {
    // SPEC.md GNT-25.6 refuses a widened effect set and a mutated authority, recovery,
    // or retry fact as a mid-loop mutation; the frozen revision id must therefore differ
    // when any of them differs, so a raw response naming the frozen id is refused
    // against the widened revision.
    let schema = "schema:read:v1";
    let frozen = build_tool_set(1, vec![descriptor("pkg", "read", "read_file", schema)]);
    let widened_effects = build_tool_set(
        1,
        vec![descriptor_with(
            "pkg",
            "read",
            "read_file",
            schema,
            &[Effect::Prompt, Effect::Spawn],
            "tools-call",
            RecoveryClass::Idempotent,
            RetryEligibility::Eligible,
        )],
    );
    assert_ne!(frozen.id(), widened_effects.id());
    let other_authority = build_tool_set(
        1,
        vec![descriptor_with(
            "pkg",
            "read",
            "read_file",
            schema,
            &[Effect::Prompt],
            "other-tools",
            RecoveryClass::Idempotent,
            RetryEligibility::Eligible,
        )],
    );
    assert_ne!(frozen.id(), other_authority.id());
    let other_recovery = build_tool_set(
        1,
        vec![descriptor_with(
            "pkg",
            "read",
            "read_file",
            schema,
            &[Effect::Prompt],
            "tools-call",
            RecoveryClass::NonIdempotent,
            RetryEligibility::Eligible,
        )],
    );
    assert_ne!(frozen.id(), other_recovery.id());
    let other_retry = build_tool_set(
        1,
        vec![descriptor_with(
            "pkg",
            "read",
            "read_file",
            schema,
            &[Effect::Prompt],
            "tools-call",
            RecoveryClass::Idempotent,
            RetryEligibility::Ineligible,
        )],
    );
    assert_ne!(frozen.id(), other_retry.id());
    let raw = RawResponse::text("done").against(&frozen);
    assert!(
        validate_raw_response(&raw, &frozen).is_accepted(),
        "the frozen revision accepts its own raw response"
    );
    assert_eq!(
        validate_raw_response(&raw, &widened_effects).cause(),
        Some(TurnValidationCause::StaleToolSetRevision),
        "a raw response naming the frozen id is refused against the widened-effect revision"
    );
}

#[test]
fn raw_cut_commits_a_witness_and_refuses_another_presentation() {
    // The raw cut records the presented raw response: the same response verifies, an
    // equal independently constructed response verifies, and a different presented
    // response is refused rather than resumed from.
    let read_slot = slot("pkg", "read");
    let schema = "schema:read:v1";
    let tool_set = build_tool_set(1, vec![descriptor("pkg", "read", "read_file", schema)]);
    let parent = session("raw-witness");
    let raw = RawResponse::tools(vec![request(0, &read_slot, schema)]);
    let accepted = validate_raw_response(&raw, &tool_set);
    let accepted_turn = match accepted.accepted_turn() {
        Some(turn) => turn.clone(),
        None => panic!("the whole valid turn must be accepted"),
    };
    let mut record = DurableAgentRecord::open(round_at(&parent, 0, 0), &raw);
    assert_eq!(record.cut(), DurableAgentCut::Raw);
    assert!(record.verify_presented_raw(&raw).is_ok());
    let equal = RawResponse::tools(vec![request(0, &read_slot, schema)]);
    assert!(
        record.verify_presented_raw(&equal).is_ok(),
        "an equal declared raw response verifies against the witness"
    );
    for other in [
        RawResponse::text("done"),
        RawResponse::refusal(),
        RawResponse::malformed(),
        RawResponse::tools(vec![request(0, &read_slot, "schema:read:v2")]),
    ] {
        let error = refusal(record.verify_presented_raw(&other));
        assert_eq!(error.code(), AgentDiagnosticCode::CommittedValueDiffers);
        assert_eq!(error.requirement(), AGENT_CLAUSES[5]);
    }
    assert!(record.commit_accepted(accepted_turn).is_ok());
    assert!(
        record.verify_presented_raw(&raw).is_ok(),
        "the raw witness survives later cuts"
    );
    let error = refusal(record.verify_presented_raw(&RawResponse::text("done")));
    assert_eq!(error.code(), AgentDiagnosticCode::CommittedValueDiffers);
}
