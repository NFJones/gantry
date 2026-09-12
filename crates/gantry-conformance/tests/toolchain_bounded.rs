//! Machine-checked conformance for the bounded untrusted compilation and cache model of
//! `SPEC.md` Section 26, clauses `GNT-26.0` .. `GNT-26.14`.
//!
//! These tests exercise the public `gantry::ir` surface of the landed toolchain model,
//! including the module-qualified `gantry::ir::toolchain::ToolchainIdentity` that owns the
//! content of the toolchain identity field `GNT-17.11-target-artifact-binding` binds
//! opaquely, together with the landed `GNT-17.9`, `GNT-17.11`, and `GNT-4.17` contracts it
//! cites:
//! `GNT-26.0-bounded-untrusted-compilation-and-cache-semantics`,
//! `GNT-26.1-untrusted-input-inventory`,
//! `GNT-26.2-stage-and-unit-vocabulary`,
//! `GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff`,
//! `GNT-26.4-structural-expansion-bounds`,
//! `GNT-26.5-completion-evidence-and-atomic-publication`,
//! `GNT-26.6-cancellation-settlement`,
//! `GNT-26.7-artifact-loader-validation`,
//! `GNT-26.8-cache-identity`,
//! `GNT-26.9-cache-validation-and-poisoning`,
//! `GNT-26.10-clean-incremental-equivalence`,
//! `GNT-26.11-editor-work-fencing`,
//! `GNT-26.12-generator-confinement`,
//! `GNT-26.13-toolchain-identity`, and
//! `GNT-26.14-compilation-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a clock, a host path,
//! an environment variable, a locale, a process identifier, a thread identity, an installed
//! program, or a live host handle, and no test spawns a thread or waits on a handle. Digests
//! are derived here from declared seeds, so every verdict below is reproducible from its own
//! inputs.

use gantry::ir::toolchain::ToolchainIdentity;
use gantry::ir::{
    ArtifactLoader, ArtifactRefusalReason, BudgetObservation, BudgetUnit, BuildHostCapability,
    COMPILATION_NON_CLAIM_ORDER, COMPILATION_NON_CLAIMS, CacheEntry, CacheKey, CacheKeyInputs,
    CacheLimits, CacheObservation, CacheValidation, CancellationSettlement,
    CancellationSettlementKind, CanonicalOutput, CompilationActivity, CompilationError,
    CompilationNonClaim, CompilationNonClaimAssertion, CompletionEvidence, Cutoff, CutoffReason,
    DeclaredDigest, DeclaredGeneratorInput, DeclaredGeneratorOutput, DeclaredRunnerCapability,
    EditorSession, EditorWork, FrontierKey, FrontierKind, FrontierOutcome, GeneratedOutputHash,
    GeneratorGrant, GeneratorIdentityFold, MAXIMUM_STAGE_LIMIT, PresentedArtifact, SealedArtifact,
    SealedAuthorityClosure, StageBudget, StageConfiguration, StageProgress, StageRun,
    StructuralFrontier, TOOLCHAIN_CLAUSES, TargetDescriptorDigest, ToolchainBudget,
    ToolchainComponent, ToolchainComponentKind, ToolchainDiagnosticCode, ToolchainIdentityInputs,
    ToolchainStage, UntrustedInput, UntrustedInputInventory, UntrustedInputKind, ValidatedReuse,
    check_clean_incremental_equivalence, check_compilation_non_claims,
    refuse_publication_after_cutoff,
};
use sha2::{Digest, Sha256};

/// Compile-time proof that one type implements none of the listed traits.
///
/// A blanket implementation and a trait-bounded implementation both apply, so naming the
/// associated item requires an inference that cannot be resolved and compilation fails. A
/// `Clone` implementation for any affine compilation value would stop this crate compiling,
/// which is exactly what `GNT-26.3`, `GNT-26.5`, `GNT-26.6`, `GNT-26.9`, and `GNT-26.11`
/// forbid: a stage run and a cutoff are consumed by the charge that cut the stage off, so a
/// cut-off run leaves no value that could be finished, completion evidence is produced once
/// and consumed once, a cache entry cannot be copied out of its poison latch, and a
/// superseded editor session cannot keep publishing stale facts.
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

assert_not_impl_any!(StageRun: Clone);
assert_not_impl_any!(Cutoff: Clone);
assert_not_impl_any!(CompletionEvidence: Clone);
assert_not_impl_any!(CancellationSettlement: Clone);
assert_not_impl_any!(CacheEntry: Clone);
assert_not_impl_any!(EditorSession: Clone);

/// Returns one declared digest derived from one declared seed.
fn digest(seed: &str) -> DeclaredDigest {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    DeclaredDigest::from_digest(bytes)
}

/// Returns one landed target descriptor digest derived from one declared seed.
fn target_descriptor(seed: &str) -> TargetDescriptorDigest {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    TargetDescriptorDigest::from_digest(bytes)
}

/// Returns one landed generated-output hash derived from one declared seed.
fn output_hash(seed: &str) -> GeneratedOutputHash {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    GeneratedOutputHash::from_digest(bytes)
}

/// Returns one stage budget declaring one limit for every unit the stage charges.
fn budget_of(stage: ToolchainStage, limit: u64) -> StageBudget {
    let declared = stage
        .applicable_units()
        .iter()
        .map(|unit| (*unit, limit))
        .collect::<Vec<_>>();
    match StageBudget::new(stage, &declared) {
        Ok(budget) => budget,
        Err(error) => panic!(
            "the declared limits of the `{}` stage are valid: {error}",
            stage.wire_name()
        ),
    }
}

/// Returns one toolchain budget with one stage budget for every given stage.
fn budget(limits_revision: u64, stages: &[ToolchainStage], limit: u64) -> ToolchainBudget {
    let declared = stages
        .iter()
        .map(|stage| budget_of(*stage, limit))
        .collect::<Vec<_>>();
    match ToolchainBudget::new(limits_revision, &declared) {
        Ok(budget) => budget,
        Err(error) => panic!("the declared toolchain budget is valid: {error}"),
    }
}

/// Charges one unit of one affine stage run, returning the cutoff that consumed it.
fn charge(run: StageRun, unit: BudgetUnit, observed: u64) -> Result<StageRun, Cutoff> {
    match run.check(unit, observed) {
        StageProgress::WithinBudget(run) => Ok(run),
        StageProgress::CutOff(cutoff) => Err(cutoff),
        StageProgress::Refused(error) => panic!("the charged unit is admitted: {error}"),
    }
}

/// Returns the code of one declared refusal, failing the test when the action was admitted.
fn refusal<T>(result: Result<T, CompilationError>) -> ToolchainDiagnosticCode {
    match result {
        Ok(_) => panic!("a declared refusal is expected here"),
        Err(error) => {
            assert!(
                TOOLCHAIN_CLAUSES.contains(&error.requirement()),
                "every refusal names a clause of Section 26: {}",
                error.requirement()
            );
            error.code()
        }
    }
}

/// Returns one untrusted input of one declared kind, name, and seed.
fn input(kind: UntrustedInputKind, name: &str, seed: &str) -> UntrustedInput {
    match UntrustedInput::new(kind, name, digest(seed).as_str()) {
        Ok(input) => input,
        Err(error) => panic!("the declared input {name} is valid: {error}"),
    }
}

/// Returns one declared cache key over one declared digest seed and limits revision.
fn cache_key(seed: &str, limits_revision: u64) -> CacheKey {
    let configuration = match StageConfiguration::new(&[ToolchainStage::Parse]) {
        Ok(configuration) => configuration,
        Err(error) => panic!("the declared stage configuration is valid: {error}"),
    };
    let inputs = match CacheKeyInputs::new(
        digest(seed),
        digest("manifest"),
        &["default"],
        target_descriptor("target"),
        &[digest("dependency")],
        digest("toolchain"),
        limits_revision,
        configuration,
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared cache key inputs are valid: {error}"),
    };
    CacheKey::derive(inputs)
}

/// Returns one admitted stage run, failing the test when the budget refuses to begin it.
fn begin(budget: &ToolchainBudget, stage: ToolchainStage) -> StageRun {
    match budget.begin_stage(stage) {
        Ok(run) => run,
        Err(error) => panic!(
            "the declared budget admits the `{}` stage: {error}",
            stage.wire_name()
        ),
    }
}

/// Returns one canonical structural key, failing the test when it is undeclarable.
fn key(kind: FrontierKind, identity: &str) -> FrontierKey {
    match FrontierKey::new(kind, identity) {
        Ok(key) => key,
        Err(error) => panic!("the declared key {identity} is canonical: {error}"),
    }
}

/// `GNT-26.0-bounded-untrusted-compilation-and-cache-semantics` publishes the section's
/// closed vocabulary: the fifteen clause anchors, the fourteen stages, the five units, and one
/// frozen diagnostic code per condition, each code anchored to exactly one clause of the
/// section. A vocabulary that admitted a fifteenth stage, a sixth unit, or a code owned by no
/// clause would let this section promise work it cannot bound or name.
#[test]
fn bounded_compilation_section_scope_and_closed_vocabulary_is_published() {
    assert_eq!(
        TOOLCHAIN_CLAUSES.len(),
        15,
        "Section 26 has fifteen clauses"
    );
    assert!(
        TOOLCHAIN_CLAUSES
            .iter()
            .all(|clause| clause.starts_with("GNT-26.")),
        "every clause anchor of this section is a GNT-26 anchor"
    );
    for index in 0_u32..15 {
        let anchor = format!("GNT-26.{index}-");
        assert_eq!(
            TOOLCHAIN_CLAUSES
                .iter()
                .filter(|clause| clause.starts_with(&anchor))
                .count(),
            1,
            "clause GNT-26.{index} is published exactly once"
        );
    }

    assert_eq!(
        ToolchainStage::ALL.len(),
        14,
        "the stage vocabulary is closed"
    );
    let stage_names = ToolchainStage::ALL.map(ToolchainStage::wire_name);
    assert_eq!(
        stage_names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        ToolchainStage::ALL.len(),
        "every stage spelling is declared exactly once"
    );
    for stage in ToolchainStage::ALL {
        assert_eq!(
            ToolchainStage::from_wire_name(stage.wire_name()),
            Some(stage),
            "every stage spelling round trips"
        );
        assert_eq!(
            stage.requirement(),
            "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff"
        );
    }
    assert_eq!(ToolchainStage::from_wire_name("preprocessing"), None);

    assert_eq!(BudgetUnit::ALL.len(), 5, "the unit vocabulary is closed");
    let unit_names = BudgetUnit::ALL.map(BudgetUnit::wire_name);
    assert_eq!(
        unit_names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        BudgetUnit::ALL.len(),
        "every unit spelling is declared exactly once"
    );
    for unit in BudgetUnit::ALL {
        assert_eq!(BudgetUnit::from_wire_name(unit.wire_name()), Some(unit));
        assert_eq!(unit.requirement(), "GNT-26.2-stage-and-unit-vocabulary");
    }
    assert_eq!(BudgetUnit::from_wire_name("wall-clock"), None);

    assert_eq!(
        ToolchainDiagnosticCode::ALL.len(),
        62,
        "the diagnostic registry is frozen at one code per condition"
    );
    let code_names = ToolchainDiagnosticCode::ALL.map(ToolchainDiagnosticCode::wire_name);
    assert!(
        code_names.windows(2).all(|window| window[0] < window[1]),
        "codes are declared in sorted wire-name order"
    );
    for code in ToolchainDiagnosticCode::ALL {
        assert_eq!(
            ToolchainDiagnosticCode::from_wire_name(code.wire_name()),
            Some(code)
        );
        assert!(code.wire_name().starts_with("toolchain-"));
        assert!(
            TOOLCHAIN_CLAUSES.contains(&code.requirement()),
            "every code is owned by a clause of Section 26: {}",
            code.wire_name()
        );
    }
    assert_eq!(
        ToolchainDiagnosticCode::from_wire_name("toolchain-stage-cut-off"),
        Some(ToolchainDiagnosticCode::StageCutOff)
    );
}

/// `GNT-26.1-untrusted-input-inventory` declares every input one activity observes, derives one
/// inventory digest from declared kinds, names, and digests alone, and refuses an input whose
/// digest differs or whose kind or name is undeclared. An input that could be read without being
/// declared, or substituted under another declared identity, would make the inventory a promise
/// the activity does not keep.
#[test]
fn untrusted_inputs_are_closed_declared_and_never_ambient() {
    assert_eq!(UntrustedInputKind::ALL.len(), 10);
    let kind_names = UntrustedInputKind::ALL.map(UntrustedInputKind::wire_name);
    assert!(kind_names.windows(2).all(|window| window[0] < window[1]));
    for (rank, kind) in UntrustedInputKind::ALL.iter().enumerate() {
        assert_eq!(kind.rank(), rank, "rank is the canonical ordering key");
        assert_eq!(
            UntrustedInputKind::from_wire_name(kind.wire_name()),
            Some(*kind)
        );
        assert_eq!(kind.requirement(), "GNT-26.1-untrusted-input-inventory");
    }
    assert_eq!(
        UntrustedInputKind::from_wire_name("environment"),
        None,
        "an ambient input kind is not a member of the closed vocabulary"
    );

    let declared = [
        input(UntrustedInputKind::Manifest, "package", "manifest"),
        input(UntrustedInputKind::Source, "main.gnt", "source"),
        input(UntrustedInputKind::TargetDescriptor, "descriptor", "target"),
    ];
    let inventory = match UntrustedInputInventory::new(&declared) {
        Ok(inventory) => inventory,
        Err(error) => panic!("the declared inventory is canonical: {error}"),
    };
    assert_eq!(inventory.inputs().len(), 3);
    assert!(inventory.admits(UntrustedInputKind::Source));
    assert!(!inventory.admits(UntrustedInputKind::Lockfile));

    let same = match UntrustedInputInventory::new(&declared) {
        Ok(inventory) => inventory,
        Err(error) => panic!("the declared inventory is canonical: {error}"),
    };
    assert_eq!(
        inventory.digest(),
        same.digest(),
        "equal declared inputs produce equal inventory digests"
    );
    let changed = [
        input(UntrustedInputKind::Manifest, "package", "manifest"),
        input(UntrustedInputKind::Source, "main.gnt", "other-source"),
        input(UntrustedInputKind::TargetDescriptor, "descriptor", "target"),
    ];
    let other = match UntrustedInputInventory::new(&changed) {
        Ok(inventory) => inventory,
        Err(error) => panic!("the declared inventory is canonical: {error}"),
    };
    assert_ne!(
        inventory.digest(),
        other.digest(),
        "a changed declared digest changes the inventory digest"
    );

    assert_eq!(inventory.admit(&declared[0]), Ok(()));
    assert_eq!(
        refusal(inventory.admit(&input(
            UntrustedInputKind::Source,
            "main.gnt",
            "stale-source"
        ))),
        ToolchainDiagnosticCode::DeclaredInputDigestDiffer,
        "a presented input with another digest is refused rather than substituted"
    );
    assert_eq!(
        refusal(inventory.admit(&input(UntrustedInputKind::Lockfile, "lockfile", "lockfile"))),
        ToolchainDiagnosticCode::UndeclaredUntrustedInput,
        "an undeclared input is never read"
    );

    let empty: [UntrustedInput; 0] = [];
    assert_eq!(
        refusal(UntrustedInputInventory::new(&empty)),
        ToolchainDiagnosticCode::EmptyInputInventory
    );
    let duplicate = [declared[0].clone(), declared[0].clone()];
    assert_eq!(
        refusal(UntrustedInputInventory::new(&duplicate)),
        ToolchainDiagnosticCode::DuplicateDeclaredInput
    );
    let unordered = [declared[1].clone(), declared[0].clone()];
    assert_eq!(
        refusal(UntrustedInputInventory::new(&unordered)),
        ToolchainDiagnosticCode::NoncanonicalInputOrder
    );
}

/// `GNT-26.2-stage-and-unit-vocabulary` binds each stage to exactly the units it charges, so a
/// limit for a unit the stage does not charge is refused rather than charged anyway and a charge
/// in an unadmitted unit is refused rather than moved to another unit. A stage could otherwise
/// declare or charge work no budget bounds.
#[test]
fn stage_and_unit_vocabulary_is_closed_and_every_stage_names_its_units() {
    let expected = [
        (
            ToolchainStage::Parse,
            vec![
                BudgetUnit::Depth,
                BudgetUnit::Count,
                BudgetUnit::Bytes,
                BudgetUnit::Work,
            ],
        ),
        (
            ToolchainStage::NameResolution,
            vec![BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work],
        ),
        (
            ToolchainStage::TypeEffectChecking,
            vec![
                BudgetUnit::Depth,
                BudgetUnit::Count,
                BudgetUnit::Work,
                BudgetUnit::Memory,
            ],
        ),
        (
            ToolchainStage::TraitSolving,
            vec![BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work],
        ),
        (
            ToolchainStage::GenericInstantiation,
            vec![
                BudgetUnit::Depth,
                BudgetUnit::Count,
                BudgetUnit::Work,
                BudgetUnit::Memory,
            ],
        ),
        (
            ToolchainStage::SchemaConstruction,
            vec![
                BudgetUnit::Depth,
                BudgetUnit::Count,
                BudgetUnit::Bytes,
                BudgetUnit::Work,
            ],
        ),
        (
            ToolchainStage::AuthorityClosure,
            vec![BudgetUnit::Count, BudgetUnit::Work, BudgetUnit::Memory],
        ),
        (
            ToolchainStage::Linking,
            vec![
                BudgetUnit::Count,
                BudgetUnit::Bytes,
                BudgetUnit::Work,
                BudgetUnit::Memory,
            ],
        ),
        (
            ToolchainStage::Optimization,
            vec![
                BudgetUnit::Depth,
                BudgetUnit::Count,
                BudgetUnit::Work,
                BudgetUnit::Memory,
            ],
        ),
        (
            ToolchainStage::Documentation,
            vec![BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work],
        ),
        (
            ToolchainStage::DiagnosticRendering,
            vec![BudgetUnit::Count, BudgetUnit::Bytes],
        ),
        (
            ToolchainStage::GenerationIngestion,
            vec![BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work],
        ),
        (
            ToolchainStage::CacheValidation,
            vec![BudgetUnit::Count, BudgetUnit::Bytes, BudgetUnit::Work],
        ),
        (
            ToolchainStage::EditorIndexing,
            vec![BudgetUnit::Depth, BudgetUnit::Count, BudgetUnit::Work],
        ),
    ];
    assert_eq!(expected.len(), ToolchainStage::ALL.len());
    for (stage, units) in expected {
        assert_eq!(
            stage.applicable_units(),
            units.as_slice(),
            "the `{}` stage charges exactly these units",
            stage.wire_name()
        );
        assert!(
            stage
                .applicable_units()
                .windows(2)
                .all(|window| window[0] < window[1]),
            "the charged units are declared in canonical order"
        );
        assert!(
            stage
                .applicable_units()
                .iter()
                .all(|unit| BudgetUnit::ALL.contains(unit)),
            "every charged unit is a member of the closed vocabulary"
        );
    }

    assert_eq!(
        refusal(StageBudget::new(
            ToolchainStage::Parse,
            &[(BudgetUnit::Memory, 8)]
        )),
        ToolchainDiagnosticCode::InapplicableStageLimit,
        "parsing does not charge memory"
    );
    let admitted = budget(1, &[ToolchainStage::Parse], 8);
    let run = begin(&admitted, ToolchainStage::Parse);
    match run.check(BudgetUnit::Memory, 1) {
        StageProgress::Refused(error) => assert_eq!(
            error.code(),
            ToolchainDiagnosticCode::InapplicableStageLimit,
            "an unadmitted unit is refused rather than charged to another unit"
        ),
        _ => panic!("an unadmitted unit is refused"),
    }
}

/// `GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff` refuses an absent or zero limit before
/// a stage runs, refuses a limit above `2^63 - 1`, reports the first exceedance as one typed
/// cutoff, and consumes the run so no cut-off value can be finished. A stage that could run
/// unbounded or publish after a cutoff would break the fail-closed contract of the section.
#[test]
fn stage_budgets_refuse_absent_or_zero_limits_and_cut_off_fail_closed() {
    assert_eq!(
        refusal(StageBudget::new(
            ToolchainStage::Parse,
            &[(BudgetUnit::Depth, 0)]
        )),
        ToolchainDiagnosticCode::ZeroStageLimit
    );
    assert_eq!(
        refusal(StageBudget::new(
            ToolchainStage::Parse,
            &[(BudgetUnit::Depth, MAXIMUM_STAGE_LIMIT + 1)]
        )),
        ToolchainDiagnosticCode::StageLimitTooLarge
    );
    let none: [(BudgetUnit, u64); 0] = [];
    assert_eq!(
        refusal(StageBudget::new(ToolchainStage::Parse, &none)),
        ToolchainDiagnosticCode::EmptyStageBudget
    );
    assert_eq!(
        refusal(StageBudget::new(
            ToolchainStage::Parse,
            &[(BudgetUnit::Depth, 4), (BudgetUnit::Depth, 4)]
        )),
        ToolchainDiagnosticCode::DuplicateBudgetUnit
    );
    assert_eq!(
        refusal(StageBudget::new(
            ToolchainStage::Parse,
            &[(BudgetUnit::Work, 4), (BudgetUnit::Depth, 4)]
        )),
        ToolchainDiagnosticCode::NoncanonicalBudgetUnitOrder
    );
    assert_eq!(
        refusal(ToolchainBudget::new(
            0,
            &[budget_of(ToolchainStage::Parse, 4)]
        )),
        ToolchainDiagnosticCode::ZeroLimitsRevision
    );
    let no_stages: [StageBudget; 0] = [];
    assert_eq!(
        refusal(ToolchainBudget::new(1, &no_stages)),
        ToolchainDiagnosticCode::EmptyStageBudget
    );
    assert_eq!(
        refusal(ToolchainBudget::new(
            1,
            &[
                budget_of(ToolchainStage::Parse, 4),
                budget_of(ToolchainStage::Parse, 4)
            ]
        )),
        ToolchainDiagnosticCode::DuplicateStageBudget
    );
    assert_eq!(
        refusal(ToolchainBudget::new(
            1,
            &[
                budget_of(ToolchainStage::TypeEffectChecking, 4),
                budget_of(ToolchainStage::Parse, 4)
            ]
        )),
        ToolchainDiagnosticCode::NoncanonicalStageBudgetOrder
    );

    let declared = budget(3, &[ToolchainStage::Parse], 8);
    assert_eq!(declared.limits_revision(), 3);
    assert_eq!(
        refusal(declared.begin_stage(ToolchainStage::TraitSolving)),
        ToolchainDiagnosticCode::StageBudgetUnadmitted,
        "a stage with no admitted budget does not run"
    );
    let partial = match StageBudget::new(
        ToolchainStage::Parse,
        &[(BudgetUnit::Depth, 4), (BudgetUnit::Count, 4)],
    ) {
        Ok(budget) => budget,
        Err(error) => panic!("the declared partial budget is valid: {error}"),
    };
    let partial_budget = match ToolchainBudget::new(1, &[partial]) {
        Ok(budget) => budget,
        Err(error) => panic!("the declared partial budget is valid: {error}"),
    };
    assert_eq!(
        refusal(partial_budget.begin_stage(ToolchainStage::Parse)),
        ToolchainDiagnosticCode::AbsentStageLimit,
        "an absent limit is refused before the stage runs"
    );

    let run = begin(&declared, ToolchainStage::Parse);
    let run = match charge(run, BudgetUnit::Work, 8) {
        Ok(run) => run,
        Err(cutoff) => panic!("a charge within budget does not cut the stage off: {cutoff:?}"),
    };
    assert_eq!(run.charges(), 1);
    assert_eq!(run.declared_limit(BudgetUnit::Work), Some(8));
    let evidence = run.finish();
    assert_eq!(evidence.stage(), ToolchainStage::Parse);
    assert_eq!(evidence.limits_revision(), 3);
    assert_eq!(evidence.charges(), 1);

    let second = begin(&declared, ToolchainStage::Parse);
    let cutoff = match charge(second, BudgetUnit::Work, 9) {
        Ok(run) => panic!(
            "a charge beyond the declared limit cuts the stage off instead of continuing: {}",
            run.charges()
        ),
        Err(cutoff) => cutoff,
    };
    assert_eq!(cutoff.reason(), CutoffReason::Limit);
    assert_eq!(cutoff.stage(), ToolchainStage::Parse);
    assert_eq!(cutoff.unit(), BudgetUnit::Work);
    assert_eq!(cutoff.limit(), 8);
    assert_eq!(cutoff.observed(), 9);
    assert_eq!(
        cutoff.requirement(),
        "GNT-26.3-finite-stage-budgets-and-fail-closed-cutoff"
    );
    assert!(cutoff.describe().contains("cut off"));
    assert_eq!(
        refusal(Cutoff::exceeded(BudgetObservation::new(
            ToolchainStage::Parse,
            BudgetUnit::Work,
            8,
            8
        ))),
        ToolchainDiagnosticCode::BudgetUnexceeded,
        "a cutoff is never reported for a charge within budget"
    );
    assert!(!BudgetObservation::new(ToolchainStage::Parse, BudgetUnit::Work, 8, 6).is_exceeded());
    assert_eq!(
        BudgetObservation::new(ToolchainStage::Parse, BudgetUnit::Work, 8, 6).remaining(),
        2
    );

    // `GNT-26.3` decides that a stage runs at most once per activity: one activity admits one run
    // of one stage and refuses a second admission of that stage.
    let mut activity = CompilationActivity::new(budget(3, &[ToolchainStage::Parse], 8));
    assert_eq!(activity.budget().limits_revision(), 3);
    let admitted = match activity.begin_stage(ToolchainStage::Parse) {
        Ok(run) => run,
        Err(error) => panic!("the admitted activity begins its stage: {error}"),
    };
    assert_eq!(admitted.stage(), ToolchainStage::Parse);
    assert_eq!(admitted.declared_limit(BudgetUnit::Work), Some(8));
    assert_eq!(activity.admitted_stages(), vec![ToolchainStage::Parse]);
    assert_eq!(
        refusal(activity.begin_stage(ToolchainStage::Parse)),
        ToolchainDiagnosticCode::StageAlreadyRun,
        "a stage runs at most once per activity"
    );
    assert_eq!(
        refusal(activity.begin_stage(ToolchainStage::TraitSolving)),
        ToolchainDiagnosticCode::StageBudgetUnadmitted,
        "an activity runs only the stages its admitted budget declares"
    );
}

/// `GNT-26.4-structural-expansion-bounds` decides cycles from interned canonical keys on the
/// current open path, reuses a closed key without charging it again, and refuses a node deeper
/// than the declared maximum before retaining it. A cycle decided by stack overflow, a deadline,
/// or memory exhaustion would be a host fact and could leave partial structure behind.
#[test]
fn structural_expansion_detects_cycles_and_refuses_depth_without_native_stack() {
    assert_eq!(FrontierOutcome::ALL.len(), 4);
    let names = FrontierOutcome::ALL.map(FrontierOutcome::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    for outcome in FrontierOutcome::ALL {
        assert_eq!(
            FrontierOutcome::from_wire_name(outcome.wire_name()),
            Some(outcome)
        );
        assert_eq!(
            outcome.requirement(),
            "GNT-26.4-structural-expansion-bounds"
        );
    }
    assert!(FrontierOutcome::Cycle.is_refusal());
    assert!(FrontierOutcome::DepthRefused.is_refusal());
    assert!(!FrontierOutcome::New.is_refusal());
    assert!(!FrontierOutcome::Reused.is_refusal());
    assert_eq!(FrontierKind::ALL.len(), 6);
    assert_eq!(
        refusal(FrontierKey::new(FrontierKind::SchemaNode, "")),
        ToolchainDiagnosticCode::InvalidDeclaredName
    );
    assert_eq!(
        refusal(StructuralFrontier::new(0)),
        ToolchainDiagnosticCode::FrontierZeroDepth
    );

    let mut frontier = match StructuralFrontier::new(2) {
        Ok(frontier) => frontier,
        Err(error) => panic!("the declared frontier is valid: {error}"),
    };
    let root = key(FrontierKind::GenericInstantiation, "root");
    let child = key(FrontierKind::GenericInstantiation, "child");
    let deep = key(FrontierKind::GenericInstantiation, "deep");
    assert_eq!(frontier.maximum_depth(), 2);
    assert_eq!(frontier.intern(root.clone(), 1), FrontierOutcome::New);
    assert_eq!(frontier.intern(child.clone(), 2), FrontierOutcome::New);
    assert_eq!(frontier.open_keys(), 2);
    assert_eq!(
        frontier.intern(root.clone(), 1),
        FrontierOutcome::Cycle,
        "a repeated open key is a structural cycle"
    );
    assert_eq!(
        frontier.intern(root.clone(), 3),
        FrontierOutcome::Cycle,
        "a repeated open key is a structural cycle even beyond the declared maximum depth"
    );
    assert_eq!(
        frontier.intern(deep.clone(), 3),
        FrontierOutcome::DepthRefused,
        "a depth beyond the declared maximum is refused, not reported as a cycle"
    );
    assert_eq!(frontier.interned(), 2, "a refusal interns nothing");
    frontier.close(&child);
    assert_eq!(frontier.open_keys(), 1);
    assert_eq!(
        frontier.intern(child.clone(), 2),
        FrontierOutcome::Reused,
        "a closed key is reused rather than re-expanded"
    );
    assert_eq!(
        frontier.intern(child.clone(), 3),
        FrontierOutcome::Reused,
        "a closed key is reused even beyond the declared maximum depth"
    );
    assert_eq!(frontier.interned(), 2, "a reused key is not charged again");

    let mut unbounded = match StructuralFrontier::new(u64::MAX) {
        Ok(frontier) => frontier,
        Err(error) => panic!("the declared frontier is valid: {error}"),
    };
    assert_eq!(unbounded.maximum_depth(), u64::MAX);
    assert_eq!(
        unbounded.intern(key(FrontierKind::SchemaNode, "ceiling"), u64::MAX),
        FrontierOutcome::New,
        "a depth at the numeric ceiling is representable rather than truncated"
    );
    let mut deepest = match StructuralFrontier::new(MAXIMUM_STAGE_LIMIT) {
        Ok(frontier) => frontier,
        Err(error) => panic!("the declared frontier is valid: {error}"),
    };
    assert_eq!(deepest.maximum_depth(), MAXIMUM_STAGE_LIMIT);
    assert_eq!(
        deepest.intern(
            key(FrontierKind::SchemaNode, "deepest"),
            MAXIMUM_STAGE_LIMIT
        ),
        FrontierOutcome::New,
        "the greatest declared stage limit is a representable frontier depth"
    );
    assert_eq!(
        deepest.intern(
            key(FrontierKind::SchemaNode, "deeper"),
            MAXIMUM_STAGE_LIMIT + 1
        ),
        FrontierOutcome::DepthRefused,
        "a depth beyond the greatest declared stage limit is refused, not truncated"
    );

    let cutoff = Cutoff::structural_cycle(BudgetObservation::new(
        ToolchainStage::GenericInstantiation,
        BudgetUnit::Count,
        8,
        9,
    ));
    assert_eq!(cutoff.reason(), CutoffReason::StructuralCycle);
    assert_eq!(cutoff.requirement(), "GNT-26.4-structural-expansion-bounds");
    assert_eq!(
        CutoffReason::from_wire_name("structural-cycle"),
        Some(CutoffReason::StructuralCycle)
    );
    assert_eq!(CutoffReason::from_wire_name("stack-overflow"), None);
}

/// Returns one declared cache key with caller-declared identity inputs.
// The declared inputs are the closed identity vocabulary of `GNT-26.8-cache-identity`, so the
// helper is kept explicit rather than collapsed into a builder that could omit an input.
#[allow(clippy::too_many_arguments)]
fn declared_key(
    source: &str,
    manifest: &str,
    features: &[&str],
    target: &str,
    dependencies: &[DeclaredDigest],
    toolchain: &str,
    limits_revision: u64,
    stages: &[ToolchainStage],
) -> Result<CacheKey, CompilationError> {
    let configuration = StageConfiguration::new(stages)?;
    let inputs = CacheKeyInputs::new(
        digest(source),
        digest(manifest),
        features,
        target_descriptor(target),
        dependencies,
        digest(toolchain),
        limits_revision,
        configuration,
    )?;
    Ok(CacheKey::derive(inputs))
}

/// Returns one declared cache observation over one reusing activity's declared cache key.
///
/// The observation carries the entry's presented structure, byte length, and digests and every
/// declared identity input of the reusing activity, so a validation that compares fewer inputs
/// than the key declares is observable here rather than hidden by the helper.
fn declared_observation(
    reusing: &CacheKey,
    canonical_structure: bool,
    byte_length: u64,
    recorded_digest: &DeclaredDigest,
    observed_digest: &DeclaredDigest,
) -> CacheObservation {
    let inputs = reusing.inputs();
    CacheObservation::new(
        canonical_structure,
        byte_length,
        recorded_digest.clone(),
        observed_digest.clone(),
        inputs.source_digest().clone(),
        inputs.manifest_digest().clone(),
        inputs.features().to_vec(),
        inputs.target_selection().clone(),
        inputs.dependency_interface_digests().to_vec(),
        inputs.toolchain_identity().clone(),
        inputs.limits_revision(),
        inputs.stage_configuration().clone(),
    )
}

/// Returns one admitted reuse of one entry, failing the test when the entry is refused.
fn reuse_of(
    entry: &CacheEntry,
    limits: &CacheLimits,
    observation: &CacheObservation,
) -> ValidatedReuse {
    match entry.reuse(limits, observation) {
        Ok(reuse) => reuse,
        Err(error) => panic!("the declared entry is valid and reusable: {error}"),
    }
}

/// Returns one declared digest of one cache entry seed.
fn entry_digest(seed: &str) -> DeclaredDigest {
    digest(seed)
}

/// `GNT-26.5-completion-evidence-and-atomic-publication` mints completion evidence only for a run
/// that never left its budget, requires that affine evidence in the only constructors of a sealed
/// artifact and a sealed authority closure, and refuses publication from a cutoff. A cut-off run
/// that could publish, or evidence that could be duplicated, would let an activity publish partial
/// semantics or partial authority.
#[test]
fn only_a_finished_run_mints_completion_evidence_that_seals_artifacts() {
    let declared = budget(7, &[ToolchainStage::SchemaConstruction], 4);
    let evidence = begin(&declared, ToolchainStage::SchemaConstruction).finish();
    assert_eq!(evidence.stage(), ToolchainStage::SchemaConstruction);
    assert_eq!(evidence.limits_revision(), 7);
    assert_eq!(evidence.charges(), 0);

    let artifact = SealedArtifact::publish(evidence, digest("artifact"));
    assert_eq!(artifact.stage(), ToolchainStage::SchemaConstruction);
    assert_eq!(artifact.digest(), &digest("artifact"));

    let closure = SealedAuthorityClosure::seal(
        begin(&declared, ToolchainStage::SchemaConstruction).finish(),
        digest("closure"),
    );
    assert_eq!(closure.stage(), ToolchainStage::SchemaConstruction);
    assert_eq!(closure.digest(), &digest("closure"));

    let left = begin(&declared, ToolchainStage::SchemaConstruction).finish();
    let right = begin(&declared, ToolchainStage::SchemaConstruction).finish();
    assert_eq!(
        left.witness(),
        right.witness(),
        "equal declared runs mint equal evidence witnesses"
    );

    let cut_off = match charge(
        begin(&declared, ToolchainStage::SchemaConstruction),
        BudgetUnit::Count,
        5,
    ) {
        Ok(_) => panic!("a charge beyond the declared limit cuts the stage off"),
        Err(cutoff) => cutoff,
    };
    assert_eq!(
        refusal(refuse_publication_after_cutoff(&cut_off)),
        ToolchainDiagnosticCode::MissingCompletionEvidence,
        "a cutoff carries no completion evidence and publishes nothing"
    );
}

/// `GNT-26.6-cancellation-settlement` settles one cancellation request exactly once with one
/// typed settlement, refuses to report a cancellation as a limit exceedance or a cycle, and
/// mints no completion evidence for the work it discards. A cancellation that could publish or be
/// reported as another cutoff reason would misreport the landed shutdown and cancellation
/// contract.
#[test]
fn cancellation_settles_once_typed_and_never_publishes_partial_work() {
    assert_eq!(CancellationSettlementKind::ALL.len(), 3);
    let names = CancellationSettlementKind::ALL.map(CancellationSettlementKind::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    for kind in CancellationSettlementKind::ALL {
        assert_eq!(
            CancellationSettlementKind::from_wire_name(kind.wire_name()),
            Some(kind)
        );
        assert_eq!(kind.requirement(), "GNT-26.6-cancellation-settlement");
    }

    let not_started = CancellationSettlement::not_started(ToolchainStage::Linking);
    assert_eq!(not_started.stage(), ToolchainStage::Linking);
    assert_eq!(not_started.kind(), CancellationSettlementKind::NotStarted);
    assert!(!not_started.ran_stage_work());
    assert!(!not_started.is_published());
    assert!(not_started.cutoff().is_none());
    assert_eq!(
        refusal(not_started.into_evidence()),
        ToolchainDiagnosticCode::MissingCompletionEvidence
    );

    let cancellation = Cutoff::cancellation(BudgetObservation::new(
        ToolchainStage::Linking,
        BudgetUnit::Work,
        16,
        9,
    ));
    assert_eq!(cancellation.reason(), CutoffReason::Cancellation);
    assert_eq!(
        cancellation.requirement(),
        "GNT-26.6-cancellation-settlement"
    );
    let settled = match CancellationSettlement::cut_off(cancellation) {
        Ok(settled) => settled,
        Err(error) => panic!("a cancellation cutoff settles a cancellation: {error}"),
    };
    assert_eq!(settled.kind(), CancellationSettlementKind::CutOff);
    assert_eq!(settled.stage(), ToolchainStage::Linking);
    assert!(settled.ran_stage_work());
    assert!(!settled.is_published());
    assert_eq!(settled.cutoff().map(Cutoff::unit), Some(BudgetUnit::Work));
    assert_eq!(
        refusal(settled.into_evidence()),
        ToolchainDiagnosticCode::MissingCompletionEvidence,
        "a cancellation settlement mints no completion evidence for discarded work"
    );

    let limit_cutoff = match Cutoff::exceeded(BudgetObservation::new(
        ToolchainStage::Linking,
        BudgetUnit::Work,
        8,
        9,
    )) {
        Ok(cutoff) => cutoff,
        Err(error) => panic!("the declared exceedance is a cutoff: {error}"),
    };
    assert_eq!(
        refusal(CancellationSettlement::cut_off(limit_cutoff)),
        ToolchainDiagnosticCode::CancellationSettlementRefused,
        "a limit exceedance is never reported as a cancellation"
    );

    let finished_budget = budget(1, &[ToolchainStage::Linking], 8);
    let finished = CancellationSettlement::already_finished(
        begin(&finished_budget, ToolchainStage::Linking).finish(),
    );
    assert_eq!(finished.kind(), CancellationSettlementKind::AlreadyFinished);
    assert!(finished.is_published());
    assert!(
        finished.ran_stage_work(),
        "an already-finished stage ran its work before the request"
    );
    let retained = match finished.into_evidence() {
        Ok(evidence) => evidence,
        Err(error) => panic!("a finished stage keeps its completion evidence: {error}"),
    };
    assert_eq!(retained.stage(), ToolchainStage::Linking);
    assert_eq!(retained.limits_revision(), 1);
    assert_eq!(
        retained.charges(),
        0,
        "the retained evidence is the witness the finished run minted"
    );
    let published = SealedArtifact::publish(retained, digest("artifact"));
    assert_eq!(
        published.stage(),
        ToolchainStage::Linking,
        "cancellation changed nothing, so the finished stage still publishes its artifact"
    );

    // `GNT-26.6` decides that a cancellation request settles exactly once per stage, and
    // `GNT-26.3` decides that a stage settled by a cancellation cutoff never runs again in that
    // activity.
    let mut activity = CompilationActivity::new(budget(2, &[ToolchainStage::Linking], 8));
    let started = match activity.begin_stage(ToolchainStage::Linking) {
        Ok(run) => run,
        Err(error) => panic!("the admitted activity begins its stage: {error}"),
    };
    assert_eq!(started.stage(), ToolchainStage::Linking);
    assert_eq!(activity.admitted_stages(), vec![ToolchainStage::Linking]);
    let running = Cutoff::cancellation(BudgetObservation::new(
        ToolchainStage::Linking,
        BudgetUnit::Work,
        16,
        9,
    ));
    let settlement = match CancellationSettlement::cut_off(running) {
        Ok(settlement) => settlement,
        Err(error) => panic!("a cancellation cutoff settles a cancellation: {error}"),
    };
    let recorded = match activity.settle(settlement) {
        Ok(settled) => settled,
        Err(error) => panic!("the first settlement of a stage is admitted: {error}"),
    };
    assert_eq!(recorded.kind(), CancellationSettlementKind::CutOff);
    assert_eq!(
        refusal(recorded.into_evidence()),
        ToolchainDiagnosticCode::MissingCompletionEvidence
    );
    assert_eq!(activity.settled_stages(), vec![ToolchainStage::Linking]);
    let second = match CancellationSettlement::cut_off(Cutoff::cancellation(
        BudgetObservation::new(ToolchainStage::Linking, BudgetUnit::Work, 16, 9),
    )) {
        Ok(settlement) => settlement,
        Err(error) => panic!("a cancellation cutoff settles a cancellation: {error}"),
    };
    assert_eq!(
        refusal(activity.settle(second)),
        ToolchainDiagnosticCode::StageAlreadySettled,
        "a cancellation request settles exactly once per stage"
    );
    assert_eq!(
        refusal(activity.begin_stage(ToolchainStage::Linking)),
        ToolchainDiagnosticCode::StageAlreadyRun,
        "a stage settled by a cancellation cutoff never runs again in that activity"
    );
    assert_eq!(
        refusal(activity.settle(CancellationSettlement::not_started(
            ToolchainStage::TraitSolving
        ))),
        ToolchainDiagnosticCode::StageBudgetUnadmitted,
        "a settlement that names a stage outside the activity is refused"
    );

    // `GNT-26.6` settles a running stage: a cancellation cutoff that names a stage the
    // activity never admitted is refused rather than recorded, while a not-started
    // settlement of an admitted stage stays admissible.
    let mut never_admitted = CompilationActivity::new(budget(2, &[ToolchainStage::Parse], 8));
    let cancellation = match CancellationSettlement::cut_off(Cutoff::cancellation(
        BudgetObservation::new(ToolchainStage::Parse, BudgetUnit::Work, 16, 4),
    )) {
        Ok(settlement) => settlement,
        Err(error) => panic!("a cancellation cutoff settles a cancellation: {error}"),
    };
    assert_eq!(
        refusal(never_admitted.settle(cancellation)),
        ToolchainDiagnosticCode::StageBudgetUnadmitted,
        "a cancellation cutoff cannot settle a stage that never ran"
    );
    assert!(
        never_admitted
            .settle(CancellationSettlement::not_started(ToolchainStage::Parse))
            .is_ok(),
        "a not-started settlement of an admitted stage stays admissible"
    );
}

/// `GNT-26.7-artifact-loader-validation` validates version, structure, canonical references,
/// limit, digest, and referenced identities in one declared order, and each failed check refuses
/// with its own reason and code and yields no fact. A loader that merged reasons or partially
/// trusted a refused artifact would let an unvalidated precomputed fact reach a later stage.
#[test]
fn artifact_loader_refuses_each_typed_reason_before_trusting_facts() {
    assert_eq!(ArtifactRefusalReason::ALL.len(), 6);
    let names = ArtifactRefusalReason::ALL.map(ArtifactRefusalReason::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    let mut codes = std::collections::BTreeSet::new();
    for reason in ArtifactRefusalReason::ALL {
        assert_eq!(
            ArtifactRefusalReason::from_wire_name(reason.wire_name()),
            Some(reason)
        );
        assert_eq!(reason.requirement(), "GNT-26.7-artifact-loader-validation");
        assert!(
            codes.insert(reason.code()),
            "each refusal reason owns one code"
        );
    }
    assert_eq!(codes.len(), 6);

    let known = [digest("dependency-a"), digest("dependency-b")];
    let loader = match ArtifactLoader::new(1, 1024, &known) {
        Ok(loader) => loader,
        Err(error) => panic!("the declared loader is valid: {error}"),
    };
    assert_eq!(loader.supported_version(), 1);
    assert_eq!(loader.maximum_bytes(), 1024);
    assert!(loader.knows_reference(&known[0]));
    assert!(!loader.knows_reference(&digest("undeclared")));

    let entry = digest("artifact");
    let valid = PresentedArtifact::new(1, true, 64, entry.clone(), entry.clone(), &known);
    let loaded = match loader.load(&valid) {
        Ok(loaded) => loaded,
        Err(error) => panic!("the declared artifact is accepted: {error}"),
    };
    assert_eq!(loaded.version(), 1);
    assert_eq!(loaded.digest(), &entry);
    assert_eq!(loaded.references().len(), 2);

    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            2,
            true,
            64,
            entry.clone(),
            entry.clone(),
            &known
        ))),
        ToolchainDiagnosticCode::ArtifactVersionUnsupported
    );
    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            1,
            false,
            64,
            entry.clone(),
            entry.clone(),
            &known
        ))),
        ToolchainDiagnosticCode::ArtifactStructureMalformed
    );
    let unsorted = [digest("dependency-b"), digest("dependency-a")];
    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            1,
            true,
            64,
            entry.clone(),
            entry.clone(),
            &unsorted
        ))),
        ToolchainDiagnosticCode::ArtifactReferencesNoncanonical
    );
    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            1,
            true,
            4096,
            entry.clone(),
            entry.clone(),
            &known
        ))),
        ToolchainDiagnosticCode::ArtifactLimitExceeded
    );
    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            1,
            true,
            64,
            digest("declared"),
            digest("observed"),
            &known
        ))),
        ToolchainDiagnosticCode::ArtifactDigestMismatch
    );
    assert_eq!(
        refusal(loader.load(&PresentedArtifact::new(
            1,
            true,
            64,
            entry.clone(),
            entry.clone(),
            &[digest("undeclared")]
        ))),
        ToolchainDiagnosticCode::ArtifactReferenceUnknown
    );
    assert_eq!(
        refusal(ArtifactLoader::new(0, 1024, &known)),
        ToolchainDiagnosticCode::ZeroLoaderConfiguration
    );
    assert_eq!(
        refusal(ArtifactLoader::new(1, 0, &known)),
        ToolchainDiagnosticCode::ZeroLoaderConfiguration
    );
}

/// `GNT-26.8-cache-identity` derives one canonical key over exactly the declared identity inputs,
/// so every declared input change is a key change and the declared order of the canonical sets is
/// never part of the key. A key that omitted an input, or that depended on declaration order,
/// would let a result be reused under an identity it was not computed for.
#[test]
fn cache_keys_cover_every_declared_input_and_change_with_each() {
    let base = declared_key(
        "source",
        "manifest",
        &["alpha", "beta"],
        "target",
        &[digest("dependency-a"), digest("dependency-b")],
        "toolchain",
        3,
        &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
    );
    let baseline = match base {
        Ok(key) => key,
        Err(error) => panic!("the declared cache key inputs are valid: {error}"),
    };
    let baseline_digest = baseline.digest().clone();
    let key_digest = |key: Result<CacheKey, CompilationError>| match key {
        Ok(key) => key.digest().clone(),
        Err(error) => panic!("the declared cache key inputs are valid: {error}"),
    };

    assert_eq!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "equal declared inputs derive an equal key"
    );
    assert_eq!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["beta", "alpha"],
            "target",
            &[digest("dependency-b"), digest("dependency-a")],
            "toolchain",
            3,
            &[ToolchainStage::TypeEffectChecking, ToolchainStage::Parse],
        )),
        "the declared order of the canonical sets is never part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "other-source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the source digest is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "other-manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the manifest digest is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the feature set is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "other-target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the target selection is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a")],
            "toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the dependency interface digests are part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "other-toolchain",
            3,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the toolchain identity is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            4,
            &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
        )),
        "the limits revision is part of the key"
    );
    assert_ne!(
        baseline_digest,
        key_digest(declared_key(
            "source",
            "manifest",
            &["alpha", "beta"],
            "target",
            &[digest("dependency-a"), digest("dependency-b")],
            "toolchain",
            3,
            &[ToolchainStage::Parse],
        )),
        "the stage configuration is part of the key"
    );

    let configuration = match StageConfiguration::new(&[ToolchainStage::Parse]) {
        Ok(configuration) => configuration,
        Err(error) => panic!("the declared stage configuration is valid: {error}"),
    };
    let omitted = DeclaredDigest::from_digest([0_u8; 32]);
    assert_eq!(
        refusal(CacheKeyInputs::new(
            omitted.clone(),
            digest("manifest"),
            &[],
            target_descriptor("target"),
            &[],
            digest("toolchain"),
            1,
            configuration.clone(),
        )),
        ToolchainDiagnosticCode::IncompleteCacheKey,
        "an omitted required digest is refused rather than keyed"
    );
    assert_eq!(
        refusal(CacheKeyInputs::new(
            digest("source"),
            digest("manifest"),
            &[],
            target_descriptor("target"),
            &[],
            digest("toolchain"),
            0,
            configuration,
        )),
        ToolchainDiagnosticCode::ZeroLimitsRevision
    );
    let no_stages: [ToolchainStage; 0] = [];
    assert_eq!(
        refusal(StageConfiguration::new(&no_stages)),
        ToolchainDiagnosticCode::EmptyStageConfiguration
    );
}

/// `GNT-26.9-cache-validation-and-poisoning` decides one closed verdict in one declared order,
/// refuses reuse of every non-valid verdict, and latches poisoning so that a poisoned entry
/// refuses reuse until it is replaced under a different key. A latch that could be cleared, or a
/// replacement that reused the poisoned key, would let an untrusted fact be reused under the
/// identity it was poisoned for.
#[test]
fn cache_validation_reports_each_verdict_and_the_poison_latch_refuses_reuse() {
    assert_eq!(CacheValidation::ALL.len(), 6);
    let names = CacheValidation::ALL.map(CacheValidation::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    for verdict in CacheValidation::ALL {
        assert_eq!(
            CacheValidation::from_wire_name(verdict.wire_name()),
            Some(verdict)
        );
        assert_eq!(
            verdict.requirement(),
            "GNT-26.9-cache-validation-and-poisoning"
        );
        assert_eq!(
            verdict.is_reusable(),
            verdict == CacheValidation::Valid,
            "only a valid verdict admits reuse"
        );
    }
    assert_eq!(CacheValidation::Valid.refusal_code(), None);
    assert_eq!(
        CacheValidation::Stale.refusal_code(),
        Some(ToolchainDiagnosticCode::CacheEntryStale)
    );
    for verdict in CacheValidation::ALL {
        if verdict != CacheValidation::Valid {
            let code = match verdict.refusal_code() {
                Some(code) => code,
                None => panic!("every non-valid verdict refuses a reuse"),
            };
            assert_eq!(
                code.requirement(),
                "GNT-26.9-cache-validation-and-poisoning",
                "the refusal of a non-valid verdict is owned by the cache-validation clause"
            );
        }
    }

    let limits = match CacheLimits::new(128) {
        Ok(limits) => limits,
        Err(error) => panic!("the declared cache limit is valid: {error}"),
    };
    assert_eq!(limits.maximum_entry_bytes(), 128);
    assert_eq!(
        refusal(CacheLimits::new(0)),
        ToolchainDiagnosticCode::CacheLimitZero
    );

    let mut entry = CacheEntry::new(cache_key("source", 3));
    let recorded = entry_digest("entry");
    let valid = declared_observation(entry.key(), true, 64, &recorded, &recorded);
    assert_eq!(entry.validate(&limits, &valid), CacheValidation::Valid);
    let admitted = reuse_of(&entry, &limits, &valid);
    assert_eq!(admitted.key_digest(), entry.key().digest());
    assert_eq!(
        admitted.requirement(),
        "GNT-26.10-clean-incremental-equivalence"
    );
    assert!(!entry.is_poisoned());

    let malformed = declared_observation(entry.key(), false, 64, &recorded, &recorded);
    assert_eq!(
        entry.validate(&limits, &malformed),
        CacheValidation::Malformed
    );
    assert_eq!(
        refusal(entry.reuse(&limits, &malformed)),
        ToolchainDiagnosticCode::CacheEntryMalformed,
        "the validating reuse call mints no reuse from a malformed entry"
    );
    let oversized = declared_observation(entry.key(), true, 4096, &recorded, &recorded);
    assert_eq!(
        entry.validate(&limits, &oversized),
        CacheValidation::Oversized
    );
    assert_eq!(
        refusal(entry.reuse(&limits, &oversized)),
        ToolchainDiagnosticCode::CacheEntryOversized
    );
    let mismatch = declared_observation(
        entry.key(),
        true,
        64,
        &digest("recorded"),
        &digest("observed"),
    );
    assert_eq!(
        entry.validate(&limits, &mismatch),
        CacheValidation::DigestMismatch
    );
    assert_eq!(
        refusal(entry.reuse(&limits, &mismatch)),
        ToolchainDiagnosticCode::CacheEntryDigestMismatch
    );
    // One falsifiable stale case per declared identity input of `GNT-26.8-cache-identity`: each
    // reusing key differs from the entry's key in exactly one declared input, and every one of
    // them is stale rather than reusable.
    let base = match declared_key(
        "source",
        "manifest",
        &["alpha", "beta"],
        "target",
        &[digest("dependency-a"), digest("dependency-b")],
        "toolchain",
        3,
        &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
    ) {
        Ok(key) => key,
        Err(error) => panic!("the declared cache key inputs are valid: {error}"),
    };
    let differing = [
        (
            "the source digest",
            declared_key(
                "other-source",
                "manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the manifest digest",
            declared_key(
                "source",
                "other-manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the feature set",
            declared_key(
                "source",
                "manifest",
                &["alpha"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the target selection",
            declared_key(
                "source",
                "manifest",
                &["alpha", "beta"],
                "other-target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the dependency interface digests",
            declared_key(
                "source",
                "manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a")],
                "toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the toolchain identity",
            declared_key(
                "source",
                "manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "other-toolchain",
                3,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the limits revision",
            declared_key(
                "source",
                "manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                4,
                &[ToolchainStage::Parse, ToolchainStage::TypeEffectChecking],
            ),
        ),
        (
            "the stage configuration",
            declared_key(
                "source",
                "manifest",
                &["alpha", "beta"],
                "target",
                &[digest("dependency-a"), digest("dependency-b")],
                "toolchain",
                3,
                &[ToolchainStage::Parse],
            ),
        ),
    ];
    let observing = CacheEntry::new(base.clone());
    for (declared_input, reusing) in differing {
        let reusing = match reusing {
            Ok(key) => key,
            Err(error) => panic!("the declared cache key inputs are valid: {error}"),
        };
        let observation = declared_observation(&reusing, true, 64, &recorded, &recorded);
        assert_eq!(
            observing.validate(&limits, &observation),
            CacheValidation::Stale,
            "a changed {declared_input} makes the entry stale for the reusing activity"
        );
        assert_eq!(
            refusal(observing.reuse(&limits, &observation)),
            ToolchainDiagnosticCode::CacheEntryStale,
            "a changed {declared_input} produces no reuse"
        );
    }
    assert_eq!(
        observing.validate(
            &limits,
            &declared_observation(&base, true, 64, &recorded, &recorded)
        ),
        CacheValidation::Valid,
        "a reusing activity with equal declared inputs reuses the entry"
    );

    entry.poison();
    assert!(entry.is_poisoned());
    assert!(entry.refuses_key(&cache_key("source", 3)));
    assert_eq!(
        entry.validate(&limits, &valid),
        CacheValidation::Poisoned,
        "the latch is reported before every other outcome"
    );
    assert_eq!(
        refusal(entry.reuse(&limits, &valid)),
        ToolchainDiagnosticCode::CacheEntryPoisoned,
        "the latch refuses reuse even for an entry whose declared checks would be valid"
    );
    entry.poison();
    assert!(
        entry.is_poisoned(),
        "poisoning latches and is never one-way clear"
    );

    let poisoned_key = entry.key().clone();
    assert_eq!(
        refusal(entry.replace(poisoned_key)),
        ToolchainDiagnosticCode::PoisonedKeyReused,
        "a poisoned key cannot be presented for its own replacement"
    );
    assert!(
        entry.is_poisoned(),
        "a refused replacement leaves the latch set"
    );
    assert_eq!(
        entry.replace(cache_key("replacement", 3)),
        Ok(()),
        "a replacement under a new key publishes one clean entry"
    );
    assert!(!entry.is_poisoned());
    assert_eq!(entry.validate(&limits, &valid), CacheValidation::Stale);
    assert!(entry.refuses_key(&cache_key("source", 3)));
    assert_eq!(
        refusal(entry.replace(cache_key("source", 3))),
        ToolchainDiagnosticCode::PoisonedKeyReused,
        "a retained poisoned key is refused after a replacement, so A -> B -> A cannot republish A"
    );
    assert_eq!(
        entry.key(),
        &cache_key("replacement", 3),
        "a refused replacement leaves this entry, its key, and its retained keys as they were"
    );
    let fresh = CacheEntry::new(cache_key("source", 3));
    assert!(!fresh.is_poisoned());
    assert!(
        !fresh.refuses_key(&cache_key("source", 3)),
        "a fresh entry under a poisoned key is a different entry that carries no latch"
    );
    assert_eq!(
        fresh.validate(
            &limits,
            &declared_observation(fresh.key(), true, 64, &recorded, &recorded)
        ),
        CacheValidation::Valid,
        "nothing makes a poisoned key globally untrustworthy for another entry"
    );
}

/// `GNT-26.10-clean-incremental-equivalence` compares one clean and one incremental build over
/// their canonical encodings in canonical stage order, so mixed cached and recomputed stages do
/// not change the output, and a divergence is refused and named rather than resolved. A comparison
/// that depended on stage order or preferred one build would hide a stale reused entry.
///
/// Returns the refusal of one declared divergence, failing the test when the builds are equal.
fn divergence(clean: &CanonicalOutput, incremental: &CanonicalOutput) -> CompilationError {
    match check_clean_incremental_equivalence(clean, incremental) {
        Ok(()) => panic!("a divergent incremental build is refused, not reported as equal"),
        Err(error) => error,
    }
}

/// Asserts that one divergence names its clause and both compared output digests.
///
/// `GNT-26.10` requires a divergence to be reported rather than resolved, and a report that
/// omitted one of the two digests it compared would name a divergence without naming what
/// diverged. The detail is returned so a caller can assert the remaining names.
fn assert_divergence_names_both_output_digests(
    clean: &CanonicalOutput,
    incremental: &CanonicalOutput,
) -> String {
    let error = divergence(clean, incremental);
    assert_eq!(
        error.code(),
        ToolchainDiagnosticCode::CleanIncrementalDivergence
    );
    assert_eq!(
        error.requirement(),
        "GNT-26.10-clean-incremental-equivalence"
    );
    let detail = error.detail().to_owned();
    assert!(
        detail.contains(clean.digest().as_str()),
        "every divergence detail names the clean output digest: {detail}"
    );
    assert!(
        detail.contains(incremental.digest().as_str()),
        "every divergence detail names the incremental output digest: {detail}"
    );
    detail
}

#[test]
fn clean_and_incremental_builds_publish_identical_canonical_output() {
    let clean = match CanonicalOutput::new(
        digest("artifact"),
        digest("closure"),
        &[
            (ToolchainStage::Parse, digest("parse")),
            (ToolchainStage::TypeEffectChecking, digest("types")),
        ],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    let incremental = match CanonicalOutput::new(
        digest("artifact"),
        digest("closure"),
        &[
            (ToolchainStage::TypeEffectChecking, digest("types")),
            (ToolchainStage::Parse, digest("parse")),
        ],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    assert_eq!(
        clean.stages(),
        incremental.stages(),
        "the per-stage outputs are compared in canonical stage order"
    );
    assert_eq!(clean.artifact(), &digest("artifact"));
    assert_eq!(clean.authority(), &digest("closure"));
    assert_eq!(clean.canonical_bytes(), incremental.canonical_bytes());
    assert_eq!(clean.digest(), incremental.digest());
    assert_eq!(
        check_clean_incremental_equivalence(&clean, &incremental),
        Ok(()),
        "one clean and one incremental build under the same declared inputs are equal"
    );

    assert_eq!(
        refusal(CanonicalOutput::new(
            digest("artifact"),
            digest("closure"),
            &[
                (ToolchainStage::Parse, digest("parse")),
                (ToolchainStage::Parse, digest("other-parse")),
            ],
        )),
        ToolchainDiagnosticCode::DuplicateStageOutput
    );

    let diverged = match CanonicalOutput::new(
        digest("artifact"),
        digest("closure"),
        &[
            (ToolchainStage::Parse, digest("parse")),
            (ToolchainStage::TypeEffectChecking, digest("other-types")),
        ],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    match check_clean_incremental_equivalence(&clean, &diverged) {
        Ok(()) => panic!("a divergent incremental build is refused, not reported as equal"),
        Err(error) => assert_eq!(
            error.code(),
            ToolchainDiagnosticCode::CleanIncrementalDivergence
        ),
    }
    let detail = assert_divergence_names_both_output_digests(&clean, &diverged);
    assert!(
        detail.contains("type-effect-checking"),
        "the divergence names the first differing stage: {detail}"
    );
    assert!(
        detail.contains(digest("types").as_str())
            && detail.contains(digest("other-types").as_str()),
        "a differing stage digest is reported with both stage digests: {detail}"
    );

    let other_artifact = match CanonicalOutput::new(
        digest("other-artifact"),
        digest("closure"),
        &[
            (ToolchainStage::Parse, digest("parse")),
            (ToolchainStage::TypeEffectChecking, digest("types")),
        ],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    let detail = assert_divergence_names_both_output_digests(&clean, &other_artifact);
    assert!(
        detail.contains("artifact digest"),
        "a different published artifact digest names that field: {detail}"
    );
    let other_closure = match CanonicalOutput::new(
        digest("artifact"),
        digest("other-closure"),
        &[
            (ToolchainStage::Parse, digest("parse")),
            (ToolchainStage::TypeEffectChecking, digest("types")),
        ],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    let detail = assert_divergence_names_both_output_digests(&clean, &other_closure);
    assert!(
        detail.contains("authority-closure digest"),
        "a different published authority closure names that field: {detail}"
    );
    let missing = match CanonicalOutput::new(
        digest("artifact"),
        digest("closure"),
        &[(ToolchainStage::Parse, digest("parse"))],
    ) {
        Ok(output) => output,
        Err(error) => panic!("the declared canonical output is valid: {error}"),
    };
    let detail = assert_divergence_names_both_output_digests(&clean, &missing);
    assert!(
        detail.contains("type-effect-checking"),
        "a stage published by one build only is named: {detail}"
    );
    let detail = assert_divergence_names_both_output_digests(&missing, &clean);
    assert!(
        detail.contains("type-effect-checking"),
        "the comparison is symmetric and names the stage either way: {detail}"
    );

    // `GNT-26.10` admits reuse of a cached stage only for an entry `GNT-26.9` reports valid, and
    // the validated reuse of this model is mintable only by a call that performs the validation.
    let limits = match CacheLimits::new(64) {
        Ok(limits) => limits,
        Err(error) => panic!("the declared cache limit is valid: {error}"),
    };
    let entry = CacheEntry::new(cache_key("source", 3));
    let recorded = entry_digest("entry");
    let reuse = reuse_of(
        &entry,
        &limits,
        &declared_observation(entry.key(), true, 64, &recorded, &recorded),
    );
    assert_eq!(reuse.key_digest(), entry.key().digest());
    assert_eq!(
        refusal(entry.reuse(
            &limits,
            &declared_observation(
                &cache_key("other-source", 3),
                true,
                64,
                &recorded,
                &recorded
            )
        )),
        ToolchainDiagnosticCode::CacheEntryStale,
        "an entry whose declared checks do not report valid cannot produce a reuse"
    );
}

/// `GNT-26.11-editor-work-fencing` publishes only the work of the session's own generation and
/// supersedes a session by consuming it, so obsolete work never publishes and a superseded session
/// keeps no capability to publish. A session that could publish a stale generation would install
/// facts its own analysis did not produce, and a successor generation is computed with checked
/// arithmetic so one generation is never reused as another.
#[test]
fn stale_editor_generations_cannot_publish_facts() {
    assert_eq!(
        refusal(EditorSession::new(0)),
        ToolchainDiagnosticCode::ZeroEditorGeneration
    );
    let session = match EditorSession::new(2) {
        Ok(session) => session,
        Err(error) => panic!("the declared editor session is valid: {error}"),
    };
    assert_eq!(session.generation(), 2);
    let current = EditorWork::new(2, digest("facts"));
    let published = match session.publish(&current) {
        Ok(published) => published,
        Err(error) => panic!("the work of the current generation publishes: {error}"),
    };
    assert_eq!(published.generation(), 2);
    assert_eq!(published.facts_digest(), &digest("facts"));

    let obsolete = EditorWork::new(1, digest("obsolete-facts"));
    assert_eq!(
        refusal(session.publish(&obsolete)),
        ToolchainDiagnosticCode::StaleEditorGeneration,
        "obsolete work never publishes"
    );
    let future = EditorWork::new(3, digest("future-facts"));
    assert_eq!(
        refusal(session.publish(&future)),
        ToolchainDiagnosticCode::StaleEditorGeneration,
        "work of an unadmitted generation is refused until its own session admits it"
    );

    let successor = match session.supersede() {
        Ok(successor) => successor,
        Err(error) => panic!("the declared session has a strictly newer successor: {error}"),
    };
    assert_eq!(successor.generation(), 3);
    assert_eq!(
        refusal(successor.publish(&current)),
        ToolchainDiagnosticCode::StaleEditorGeneration,
        "a superseded generation cannot publish"
    );
    assert_eq!(
        successor.publish(&future).map(|facts| facts.generation()),
        Ok(3),
        "the successor publishes its own generation"
    );

    // `GNT-26.11` forbids reusing a generation: the successor of the numerically greatest
    // generation does not exist, so it is refused rather than computed as an equal generation.
    let ceiling = match EditorSession::new(u64::MAX) {
        Ok(session) => session,
        Err(error) => panic!("the declared editor session is valid: {error}"),
    };
    assert_eq!(ceiling.generation(), u64::MAX);
    assert_eq!(
        refusal(ceiling.supersede()),
        ToolchainDiagnosticCode::EditorGenerationExhausted,
        "a generation at the numeric ceiling has no successor rather than an equal one"
    );
    let penultimate = match EditorSession::new(u64::MAX - 1) {
        Ok(session) => session,
        Err(error) => panic!("the declared editor session is valid: {error}"),
    };
    let reached_ceiling = match penultimate.supersede() {
        Ok(successor) => successor,
        Err(error) => panic!("the penultimate generation has a successor: {error}"),
    };
    assert_eq!(reached_ceiling.generation(), u64::MAX);
    assert_eq!(
        refusal(reached_ceiling.supersede()),
        ToolchainDiagnosticCode::EditorGenerationExhausted,
        "the successor of the penultimate generation is the ceiling and has no successor"
    );
}

/// `GNT-26.12-generator-confinement` admits only declared build-host capabilities, declared inputs,
/// and declared outputs, refuses ambient and execution-target authority, requires the explicit
/// runner capability to run a produced executable, and binds the declared input digests and output
/// hashes into the grant identity. A generator that could read or exercise what its grant does not
/// declare would put an ambient host fact into artifact identity.
#[test]
fn generators_are_confined_to_declared_capabilities_inputs_and_outputs() {
    let declared = BuildHostCapability::ReadDeclaredInputs;
    let undeclared = BuildHostCapability::InvokeDeclaredToolchain;
    assert!(
        BuildHostCapability::ALL.len() > 1,
        "the landed build-host vocabulary has more than one member"
    );
    let schema = match DeclaredGeneratorInput::new("schema", digest("input")) {
        Ok(input) => input,
        Err(error) => panic!("the declared generator input is valid: {error}"),
    };
    let stale_schema = match DeclaredGeneratorInput::new("schema", digest("other-input")) {
        Ok(input) => input,
        Err(error) => panic!("the declared generator input is valid: {error}"),
    };
    let undeclared_input = match DeclaredGeneratorInput::new("secret", digest("secret")) {
        Ok(input) => input,
        Err(error) => panic!("the declared generator input is valid: {error}"),
    };
    let generated = match DeclaredGeneratorOutput::new("generated", output_hash("output")) {
        Ok(output) => output,
        Err(error) => panic!("the declared generator output is valid: {error}"),
    };
    let other_generated = match DeclaredGeneratorOutput::new("generated", output_hash("other")) {
        Ok(output) => output,
        Err(error) => panic!("the declared generator output is valid: {error}"),
    };
    let grant = match GeneratorGrant::declare(
        &[BuildHostCapability::WriteDeclaredOutputs, declared],
        std::slice::from_ref(&schema),
        std::slice::from_ref(&generated),
    ) {
        Ok(grant) => grant,
        Err(error) => panic!("the declared generator grant is valid: {error}"),
    };
    assert_eq!(
        grant.capabilities(),
        [declared, BuildHostCapability::WriteDeclaredOutputs],
        "granted capabilities are one canonical set of the closed vocabulary"
    );
    assert_eq!(grant.inputs().len(), 1);
    assert_eq!(grant.outputs().len(), 1);
    assert_eq!(grant.admit_capability(declared), Ok(()));
    assert_eq!(
        refusal(grant.admit_capability(undeclared)),
        ToolchainDiagnosticCode::UndeclaredGeneratorCapability,
        "an undeclared capability is not exercised merely because the host provides it"
    );
    assert_eq!(grant.admit_input(&schema), Ok(()));
    assert_eq!(
        refusal(grant.admit_input(&stale_schema)),
        ToolchainDiagnosticCode::UndeclaredGeneratorInput
    );
    assert_eq!(
        refusal(grant.admit_input(&undeclared_input)),
        ToolchainDiagnosticCode::UndeclaredGeneratorInput,
        "an undeclared input is never read"
    );
    assert_eq!(grant.admit_output(&generated), Ok(()));
    assert_eq!(
        refusal(grant.admit_output(&other_generated)),
        ToolchainDiagnosticCode::UndeclaredGeneratorOutput,
        "an undeclared output hash is refused rather than written"
    );
    assert_eq!(
        refusal(grant.admit_execution_target_authority()),
        ToolchainDiagnosticCode::ExecutionTargetAuthorityRefused,
        "a generator never receives execution-target authority"
    );
    assert_eq!(
        refusal(grant.refuse_ambient_capability("network-bind")),
        ToolchainDiagnosticCode::AmbientAuthorityRefused,
        "an ambient capability outside the closed vocabulary is refused"
    );
    assert_eq!(
        refusal(grant.run_produced_executable(None, digest("run"))),
        ToolchainDiagnosticCode::RunnerCapabilityMissing,
        "running a produced executable is never implied by the grant"
    );
    let runner = match DeclaredRunnerCapability::new("local-runner") {
        Ok(runner) => runner,
        Err(error) => panic!("the declared runner capability is valid: {error}"),
    };
    let recorded = match grant.run_produced_executable(Some(&runner), digest("run")) {
        Ok(recorded) => recorded,
        Err(error) => panic!("the declared runner capability admits the run: {error}"),
    };
    assert_eq!(recorded.name(), "runner-capability:local-runner");
    assert_eq!(
        recorded.digest(),
        &digest("run"),
        "an admitted run becomes one recorded build input"
    );

    // `GNT-26.12` decides that an admitted run becomes one recorded build input that enters
    // artifact identity: the fold admits one run per recorded input, in recorded-name order, and
    // refuses a repeated run and a run this grant never admitted.
    let admitted = match grant.admit_run(Some(&runner), digest("run")) {
        Ok(admitted) => admitted,
        Err(error) => panic!("the declared runner capability admits the run: {error}"),
    };
    assert_eq!(admitted.input().name(), "runner-capability:local-runner");
    assert_eq!(admitted.input().digest(), &digest("run"));
    assert_eq!(admitted.grant_identity(), &grant.identity());
    assert_eq!(
        refusal(grant.admit_run(None, digest("run"))),
        ToolchainDiagnosticCode::RunnerCapabilityMissing,
        "an admitted run requires the explicit runner capability"
    );

    let mut identity_fold = GeneratorIdentityFold::open(&grant);
    assert_eq!(identity_fold.grant_identity(), &grant.identity());
    let folded = match identity_fold.fold(&admitted) {
        Ok(digest) => digest,
        Err(error) => panic!("the admitted run enters this grant's artifact identity: {error}"),
    };
    assert_ne!(
        folded,
        grant.identity(),
        "the folded identity carries the recorded build inputs"
    );
    assert_eq!(identity_fold.inputs().len(), 1);
    assert_eq!(
        identity_fold.inputs()[0].0.as_ref(),
        "runner-capability:local-runner"
    );
    assert_eq!(identity_fold.inputs()[0].1, digest("run"));
    assert_eq!(
        refusal(identity_fold.fold(&admitted)),
        ToolchainDiagnosticCode::DuplicateRecordedBuildInput,
        "one admitted run enters artifact identity exactly once"
    );
    assert_eq!(
        identity_fold.inputs().len(),
        1,
        "a refused fold retains no second recorded build input"
    );

    let other_input_grant = match GeneratorGrant::declare(
        &[declared],
        std::slice::from_ref(&schema),
        std::slice::from_ref(&generated),
    ) {
        Ok(grant) => grant,
        Err(error) => panic!("the declared generator grant is valid: {error}"),
    };
    let foreign = match other_input_grant.admit_run(Some(&runner), digest("foreign-run")) {
        Ok(admitted) => admitted,
        Err(error) => panic!("the declared runner capability admits the run: {error}"),
    };
    assert_eq!(
        refusal(identity_fold.fold(&foreign)),
        ToolchainDiagnosticCode::UnadmittedGeneratorRun,
        "a run the grant never admitted does not enter its artifact identity"
    );
    let second_runner = match DeclaredRunnerCapability::new("remote-runner") {
        Ok(runner) => runner,
        Err(error) => panic!("the declared runner capability is valid: {error}"),
    };
    let second = match grant.admit_run(Some(&second_runner), digest("second-run")) {
        Ok(admitted) => admitted,
        Err(error) => panic!("the declared runner capability admits the run: {error}"),
    };
    let extended = match identity_fold.fold(&second) {
        Ok(digest) => digest,
        Err(error) => panic!("a second admitted run enters this grant's identity: {error}"),
    };
    assert_ne!(
        folded, extended,
        "a second admitted run changes the folded artifact identity"
    );
    assert_eq!(identity_fold.inputs().len(), 2);
    assert_eq!(
        identity_fold.inputs()[0].0.as_ref(),
        "runner-capability:local-runner",
        "the folded recorded build inputs are held in recorded-name order"
    );

    let changed_output = match GeneratorGrant::declare(
        &[declared],
        std::slice::from_ref(&schema),
        &[other_generated],
    ) {
        Ok(grant) => grant,
        Err(error) => panic!("the declared generator grant is valid: {error}"),
    };
    assert_ne!(
        grant.identity(),
        changed_output.identity(),
        "a changed declared output hash changes artifact identity"
    );
    let added_input = match GeneratorGrant::declare(
        &[declared],
        &[schema.clone(), undeclared_input],
        std::slice::from_ref(&generated),
    ) {
        Ok(grant) => grant,
        Err(error) => panic!("the declared generator grant is valid: {error}"),
    };
    assert_ne!(
        grant.identity(),
        added_input.identity(),
        "an added declared input changes artifact identity"
    );

    let no_capabilities: [BuildHostCapability; 0] = [];
    assert_eq!(
        refusal(GeneratorGrant::declare(&no_capabilities, &[], &[])),
        ToolchainDiagnosticCode::EmptyGeneratorCapabilities
    );
    assert_eq!(
        refusal(GeneratorGrant::declare(
            &[declared],
            &[schema.clone(), schema],
            &[]
        )),
        ToolchainDiagnosticCode::DuplicateGeneratorInput
    );
    assert_eq!(
        refusal(GeneratorGrant::declare(
            &[declared],
            &[],
            &[generated.clone(), generated]
        )),
        ToolchainDiagnosticCode::DuplicateGeneratorOutput
    );
}

/// `GNT-26.13-toolchain-identity` derives one versioned digest over the sorted component digests,
/// the limits revision, and the target descriptor digest, so it is total and injective over those
/// declared inputs and independent of the order the components were declared in. This is the
/// content of the field `GNT-17.11-target-artifact-binding` binds opaquely, so a change of content
/// must change artifact identity.
#[test]
fn toolchain_identity_changes_when_a_component_or_the_limits_revision_changes() {
    assert_eq!(ToolchainComponentKind::ALL.len(), 12);
    let names = ToolchainComponentKind::ALL.map(ToolchainComponentKind::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    for kind in ToolchainComponentKind::ALL {
        assert_eq!(
            ToolchainComponentKind::from_wire_name(kind.wire_name()),
            Some(kind)
        );
    }

    let parser = ToolchainComponent::new(ToolchainComponentKind::Parser, digest("parser"));
    let linker = ToolchainComponent::new(ToolchainComponentKind::Linker, digest("linker"));
    let inputs = match ToolchainIdentityInputs::new(
        1,
        &[parser.clone(), linker.clone()],
        3,
        target_descriptor("target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    assert_eq!(inputs.version(), 1);
    assert_eq!(inputs.limits_revision(), 3);
    assert_eq!(inputs.components().len(), 2);
    assert_eq!(inputs.target_descriptor(), &target_descriptor("target"));
    let identity = ToolchainIdentity::derive(&inputs);
    assert_eq!(identity.version(), 1);
    assert_eq!(identity.digest_hex().len(), 64);
    assert_ne!(
        identity.digest(),
        &digest("parser"),
        "the identity digest is derived under its own domain separator"
    );

    let reordered = match ToolchainIdentityInputs::new(
        1,
        &[linker.clone(), parser.clone()],
        3,
        target_descriptor("target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    assert_eq!(
        identity,
        ToolchainIdentity::derive(&reordered),
        "the declared order of the components is never part of the identity"
    );

    let other_component = match ToolchainIdentityInputs::new(
        1,
        &[
            ToolchainComponent::new(ToolchainComponentKind::Parser, digest("other-parser")),
            linker.clone(),
        ],
        3,
        target_descriptor("target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    assert_ne!(
        identity,
        ToolchainIdentity::derive(&other_component),
        "a changed component digest changes the identity"
    );
    let other_revision = match ToolchainIdentityInputs::new(
        1,
        &[parser.clone(), linker.clone()],
        4,
        target_descriptor("target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    assert_ne!(
        identity,
        ToolchainIdentity::derive(&other_revision),
        "a changed limits revision changes the identity"
    );
    let other_target = match ToolchainIdentityInputs::new(
        1,
        &[parser.clone(), linker.clone()],
        3,
        target_descriptor("other-target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    assert_ne!(
        identity,
        ToolchainIdentity::derive(&other_target),
        "a changed target descriptor digest changes the identity"
    );
    let other_version = match ToolchainIdentityInputs::new(
        2,
        &[parser.clone(), linker.clone()],
        3,
        target_descriptor("target"),
    ) {
        Ok(inputs) => inputs,
        Err(error) => panic!("the declared toolchain identity inputs are valid: {error}"),
    };
    let versioned = ToolchainIdentity::derive(&other_version);
    assert_ne!(identity, versioned, "the identity carries its version");
    assert_eq!(versioned.version(), 2);

    assert_eq!(
        refusal(ToolchainIdentityInputs::new(
            0,
            std::slice::from_ref(&parser),
            1,
            target_descriptor("target")
        )),
        ToolchainDiagnosticCode::ZeroToolchainIdentityVersion
    );
    let no_components: [ToolchainComponent; 0] = [];
    assert_eq!(
        refusal(ToolchainIdentityInputs::new(
            1,
            &no_components,
            1,
            target_descriptor("target")
        )),
        ToolchainDiagnosticCode::EmptyToolchainComponents
    );
    assert_eq!(
        refusal(ToolchainIdentityInputs::new(
            1,
            &[parser.clone(), parser.clone()],
            1,
            target_descriptor("target")
        )),
        ToolchainDiagnosticCode::DuplicateToolchainComponent
    );
    assert_eq!(
        refusal(ToolchainIdentityInputs::new(
            1,
            &[parser],
            0,
            target_descriptor("target")
        )),
        ToolchainDiagnosticCode::ZeroLimitsRevision
    );
}

/// `GNT-26.14-compilation-non-claims` publishes a closed non-claim vocabulary and refuses to
/// present a non-claim as a guarantee. A non-claim reported as a guarantee would promise a limit
/// the section explicitly does not promise, such as bounded termination or kernel sandboxing, and
/// each published statement restates its clause's non-claim rather than inverting it.
#[test]
fn compilation_non_claims_are_closed_and_never_presented_as_guarantees() {
    assert_eq!(CompilationNonClaim::ALL.len(), 8);
    assert_eq!(COMPILATION_NON_CLAIMS.len(), 8);
    assert_eq!(COMPILATION_NON_CLAIM_ORDER, CompilationNonClaim::ALL);
    let names = CompilationNonClaim::ALL.map(CompilationNonClaim::wire_name);
    assert!(names.windows(2).all(|window| window[0] < window[1]));
    for (index, claim) in CompilationNonClaim::ALL.iter().enumerate() {
        assert_eq!(
            CompilationNonClaim::from_wire_name(claim.wire_name()),
            Some(*claim)
        );
        assert_eq!(claim.requirement(), "GNT-26.14-compilation-non-claims");
        assert_eq!(claim.statement(), COMPILATION_NON_CLAIMS[index]);
        assert!(!claim.statement().is_empty());
    }

    // `GNT-26.14` publishes the section's non-claims, so a statement MUST restate the non-claim
    // its clause makes: the bounded-termination statement states that the section makes no
    // promise about termination rather than promising it.
    let bounded_termination = CompilationNonClaim::BoundedTermination.statement();
    assert_eq!(bounded_termination, COMPILATION_NON_CLAIMS[1]);
    assert!(
        bounded_termination
            .contains("makes no promise that any declared input set finishes inside them"),
        "the statement matches the clause's non-claim: {bounded_termination}"
    );
    assert!(
        !bounded_termination.contains("promises that no declared input set finishes"),
        "the statement must not promise the termination the clause disclaims: {bounded_termination}"
    );

    let honest =
        CompilationNonClaim::ALL.map(|claim| CompilationNonClaimAssertion::new(claim, false));
    assert_eq!(
        check_compilation_non_claims(&honest),
        Ok(()),
        "published limits are not guarantees"
    );
    let overstated = [CompilationNonClaimAssertion::new(
        CompilationNonClaim::BoundedTermination,
        true,
    )];
    assert_eq!(
        refusal(check_compilation_non_claims(&overstated)),
        ToolchainDiagnosticCode::NonClaimAsGuarantee
    );
    assert_eq!(
        overstated[0].claim(),
        CompilationNonClaim::BoundedTermination
    );
    assert!(overstated[0].is_presented_as_guarantee());
}
