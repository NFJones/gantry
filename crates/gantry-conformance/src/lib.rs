//! External conformance harness for Gantry's supported public surfaces.
//!
//! The harness deliberately depends on the facade rather than importing
//! private implementation crates. It validates evidence and runs adapter
//! contract cases, but it never generates canonical protocol artifacts or
//! becomes a semantic authority for Gantry.

use std::collections::{BTreeMap, BTreeSet};

pub mod concurrent_executor;
pub mod journal;
pub mod scripted;
pub mod services;

/// Evidence classes understood by profile and release gates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvidenceKind {
    /// Executable source or protocol fixture.
    Fixture,
    /// Exact expected portable bytes or values.
    Golden,
    /// Canonical protocol or generated-binding check.
    Protocol,
    /// Reviewed requirement-ledger evidence.
    Requirement,
    /// Supported integration-adapter contract case.
    AdapterContract,
    /// Facade feature-combination evidence.
    FeatureMatrix,
    /// External consumer use of the supported public API.
    PublicApi,
    /// Publication skeleton or immutable publication evidence.
    Publication,
    /// Checked semantic argument, model, or replay evidence.
    ProofModel,
}

/// Whether evidence is usable through a supported contract surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceVisibility {
    /// Evidence exercises the supported `gantry` facade.
    PublicFacade,
    /// Evidence exercises a supported adapter contract.
    AdapterContract,
    /// Evidence exists only through a workspace-private implementation path.
    PrivateOnly,
}

/// Freshness and completion state of one evidence record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceState {
    /// Current executable or independently checked evidence.
    Verified,
    /// A declared location without completed evidence.
    Placeholder,
    /// Evidence bound to an older source, specification, or artifact revision.
    Stale,
}

/// One immutable evidence entry supplied to a gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord<'a> {
    /// Stable evidence identifier.
    pub id: &'a str,
    /// Evidence class.
    pub kind: EvidenceKind,
    /// Supported surface through which behavior is exercised.
    pub visibility: EvidenceVisibility,
    /// Completion and freshness state.
    pub state: EvidenceState,
    /// Exact source or specification revision to which the evidence is bound.
    pub revision: &'a str,
}

/// Why a gate rejected its supplied evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateEvidenceError {
    /// An evidence identifier is empty.
    EmptyId,
    /// More than one record uses the same identifier.
    DuplicateId(String),
    /// A required evidence identifier is absent.
    Missing(String),
    /// A placeholder was supplied as completed evidence.
    Placeholder(String),
    /// Evidence is stale or bound to another revision.
    Stale(String),
    /// Evidence is reachable only through a private implementation path.
    PrivateOnly(String),
}

/// A validated, deterministically ordered gate evidence index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateEvidenceIndex<'a> {
    /// Exact revision shared by all accepted evidence.
    pub revision: &'a str,
    /// Accepted records ordered by stable evidence identifier.
    pub records: Vec<EvidenceRecord<'a>>,
}

/// Validates that a gate has complete, current, nonprivate evidence.
pub fn validate_gate_evidence<'a>(
    revision: &'a str,
    required_ids: &[&str],
    records: &[EvidenceRecord<'a>],
) -> Result<GateEvidenceIndex<'a>, Vec<GateEvidenceError>> {
    let mut errors = Vec::new();
    let mut by_id = BTreeMap::new();
    for record in records {
        if record.id.is_empty() {
            errors.push(GateEvidenceError::EmptyId);
            continue;
        }
        if by_id.insert(record.id, record.clone()).is_some() {
            errors.push(GateEvidenceError::DuplicateId(record.id.to_owned()));
        }
        match record.state {
            EvidenceState::Verified => {}
            EvidenceState::Placeholder => {
                errors.push(GateEvidenceError::Placeholder(record.id.to_owned()));
            }
            EvidenceState::Stale => {
                errors.push(GateEvidenceError::Stale(record.id.to_owned()));
            }
        }
        if record.revision != revision {
            errors.push(GateEvidenceError::Stale(record.id.to_owned()));
        }
        if record.visibility == EvidenceVisibility::PrivateOnly {
            errors.push(GateEvidenceError::PrivateOnly(record.id.to_owned()));
        }
    }
    for required in required_ids {
        if !by_id.contains_key(required) {
            errors.push(GateEvidenceError::Missing((*required).to_owned()));
        }
    }
    errors.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
    errors.dedup();
    if errors.is_empty() {
        Ok(GateEvidenceIndex {
            revision,
            records: by_id.into_values().collect(),
        })
    } else {
        Err(errors)
    }
}

/// One executable adapter or public-surface contract case.
pub struct ContractCase<A> {
    /// Stable case identifier.
    pub id: &'static str,
    /// Case implementation against the supplied adapter or facade.
    pub run: fn(&A) -> Result<(), String>,
}

/// Failure returned by one contract case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractFailure {
    /// Stable case identifier.
    pub id: &'static str,
    /// Structured case failure detail.
    pub detail: String,
}

/// Runs every contract case without stopping after the first failure.
pub fn run_contract_cases<A>(
    adapter: &A,
    cases: &[ContractCase<A>],
) -> Result<(), Vec<ContractFailure>> {
    let mut failures = Vec::new();
    let mut ids = BTreeSet::new();
    for case in cases {
        if case.id.is_empty() || !ids.insert(case.id) {
            failures.push(ContractFailure {
                id: case.id,
                detail: "contract case identifier is empty or duplicated".to_owned(),
            });
            continue;
        }
        if let Err(detail) = (case.run)(adapter) {
            failures.push(ContractFailure {
                id: case.id,
                detail,
            });
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Facade feature selection observed by an external consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FacadeFeatureSelection {
    /// Frontend capability was compiled.
    pub frontend: bool,
    /// Analyzer capability was compiled.
    pub analyzer: bool,
    /// Sequential evaluator capability was compiled.
    pub evaluator: bool,
    /// Concurrent refinement was compiled.
    pub concurrent: bool,
    /// Durable refinement was compiled.
    pub durable: bool,
}

/// Validates the additive facade feature implications.
pub fn validate_facade_features(features: FacadeFeatureSelection) -> Result<(), &'static str> {
    if features.analyzer && !features.frontend {
        return Err("analyzer requires frontend");
    }
    if features.evaluator && !features.analyzer {
        return Err("evaluator requires analyzer");
    }
    if features.concurrent && !features.evaluator {
        return Err("concurrent requires evaluator");
    }
    if features.durable && !features.evaluator {
        return Err("durable requires evaluator");
    }
    Ok(())
}

/// Canonical publication skeleton validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationSkeletonError {
    /// The publication-index version is not exactly 1.0.
    UnsupportedVersion,
    /// A required stable artifact is missing.
    MissingArtifact(String),
    /// A stable artifact identifier appears more than once.
    DuplicateArtifact(String),
    /// The skeleton claims an undeclared artifact before its owner exists.
    UnexpectedArtifact(String),
}

/// Validates the Phase 0 publication skeleton without claiming completeness.
pub fn validate_publication_skeleton(
    major: u64,
    minor: u64,
    artifact_ids: &[&str],
) -> Result<(), Vec<PublicationSkeletonError>> {
    const REQUIRED: &[&str] = &[
        "gantry.authoring",
        "gantry.conformance",
        "gantry.embedding",
        "gantry.ir",
        "gantry.journal",
        "gantry.spec",
        "gantry.values",
    ];
    let mut errors = Vec::new();
    if (major, minor) != (1, 0) {
        errors.push(PublicationSkeletonError::UnsupportedVersion);
    }
    let mut actual = BTreeSet::new();
    for id in artifact_ids {
        if !actual.insert(*id) {
            errors.push(PublicationSkeletonError::DuplicateArtifact(
                (*id).to_owned(),
            ));
        }
        if !REQUIRED.contains(id) {
            errors.push(PublicationSkeletonError::UnexpectedArtifact(
                (*id).to_owned(),
            ));
        }
    }
    for required in REQUIRED {
        if !actual.contains(required) {
            errors.push(PublicationSkeletonError::MissingArtifact(
                (*required).to_owned(),
            ));
        }
    }
    errors.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
