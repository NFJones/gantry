//! Durable sequence-one start coordination over the shared pre-execution path.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use gantry_core::canonical_json::CanonicalJson;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{
    IdentityKind, ResumeStartFailureCategory, SinkClass, StartFailureCategory,
};
use gantry_core::protocol::ProtocolSelection;
use gantry_core::strict_json::{JsonLimits, JsonNode, JsonNodeId, StrictJsonDocument};
use gantry_host::embedding::EmbeddingOperation;
use gantry_host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalCommitRequestV1,
    JournalError, JournalEvidenceReferenceV1, JournalId, JournalOwnerOperationV1,
    JournalOwnershipToken, JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1,
};
use gantry_runtime::{
    AdmissionKind, DurableCommitCutV1, DurableEvidenceError, DurableExecutionStartV3,
    DurableExecutionStateV1, DurableLogicalEvidenceV3, ExecutionHandle, LogicalSessionRegistryV1,
    Machine, OperationAdmission, RecoveredDurableStateV1, SessionCreationModeV1,
    recover_authoritative_prefix_with_retained_program,
};

use crate::interpreter::{decode_logical_value, root_task_identity};
use crate::start::{
    PreparedExecutionStart, StartExecutionCoordinator, decode_mapping_revisions, require_resolved,
};
use crate::{
    AnalyzePackageError, AnalyzePackageRequest, AnalyzePackageResult, AnalyzePackageStatus,
    DurableLifecycleCoordinator, DurableOwnedExecution, MappingRevisions, StartExecutionAccepted,
    StartExecutionFailure, StartExecutionRequest,
};

/// Durable new-execution request retaining the embedder-supplied journal target.
pub struct DurableStartExecutionRequest<'a> {
    /// Stable fresh journal target.
    pub journal_id: JournalId,
    /// Shared package, protocol, entry, session, and preflight request.
    pub start: StartExecutionRequest<'a>,
}

/// Accepted durable execution after sequence one became authoritative.
pub struct DurableStartExecutionAccepted {
    pub(crate) start: StartExecutionAccepted,
    pub(crate) owned: Arc<DurableOwnedExecution>,
    #[cfg(feature = "concurrent")]
    pub(crate) execution_budget: gantry_runtime::ExecutionBudget,
    journal_id: JournalId,
    pub(crate) ownership_token: JournalOwnershipToken,
    pub(crate) execution_start_evidence_id: gantry_core::identity::ProtocolIdentity,
}

impl DurableStartExecutionAccepted {
    /// Returns the stable journal accepted by the durable start.
    #[must_use]
    pub const fn journal_id(&self) -> &JournalId {
        &self.journal_id
    }

    /// Returns the accepted execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.start.execution_id()
    }

    /// Returns the sole in-process observation and control handle.
    #[must_use]
    pub const fn handle(&self) -> &ExecutionHandle {
        self.start.handle()
    }

    /// Returns the fenced token for deterministic storage-protocol fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_ownership_token(&self) -> &JournalOwnershipToken {
        &self.ownership_token
    }

    /// Returns the sequence-one evidence identity for protocol fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_execution_start_evidence_id(&self) -> ProtocolIdentity {
        self.execution_start_evidence_id
    }

    /// Copies retained owner state for committed-prefix conformance assertions.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_retained_projection(&self) -> Option<RecoveredDurableStateV1> {
        self.owned.test_retained_projection()
    }
}

/// Durable start rejection retaining the journal identity and release outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStartExecutionFailure {
    /// Stable target supplied by the embedder even when startup failed.
    pub journal_id: JournalId,
    /// Exact ordinary start category and code at the failing boundary.
    pub failure: StartExecutionFailure,
    /// Owner-release failure retained separately from the start category.
    pub release_error: Option<JournalError>,
}

/// Durable start result whose accepted variant exists only after sequence one commits.
pub enum DurableStartExecutionResult {
    /// Sequence one committed and lifecycle acceptance succeeded.
    Accepted(Box<DurableStartExecutionAccepted>),
    /// Startup failed without returning an accepted execution identity.
    Rejected(DurableStartExecutionFailure),
}

pub(crate) enum DurableRegistrationEvent {
    Marked(ProtocolIdentity),
    #[cfg(feature = "test-support")]
    Accepted(ExecutionHandle),
    Published(Arc<DurableOwnedExecution>),
    Abandoned(ProtocolIdentity),
}

/// Existing durable execution request, with optional candidate source for compatibility auditing.
pub struct DurableResumeExecutionRequest<'a> {
    /// Stable journal whose authoritative prefix is resumed.
    pub journal_id: JournalId,
    /// Exact protocol tuple recorded by sequence one; resume never renegotiates it.
    pub protocol_selection: &'a ProtocolSelection,
    /// Optional candidate package checked against the retained canonical-IR identity.
    pub candidate_package_root: Option<&'a Path>,
    /// Optional execution identity assertion supplied by the embedder.
    pub expected_execution_id: Option<ProtocolIdentity>,
    /// Current sink plan used for required-sink compatibility and activity-event settlement.
    pub event_delivery: Option<&'a gantry_observe::SinkPlan>,
}

/// Candidate-source provenance observed while accepting a durable resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableResumeSourceComparison {
    /// Resume used only retained durable package and executable evidence.
    SourceFree,
    /// Candidate source reproduced both canonical IR and the original source manifest.
    ExactManifest,
    /// Candidate source reproduced canonical IR but differed cosmetically in its manifest.
    CosmeticManifestDifference,
}

/// Authenticated analyzer artifacts retained by the accepted durable execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRetainedArtifacts {
    canonical_ir: Arc<[u8]>,
    canonical_ir_identity: Arc<str>,
    generated_schemas: Arc<[u8]>,
    generated_schemas_identity: Arc<str>,
    manifest: Arc<[u8]>,
    manifest_identity: Arc<str>,
    source_map: Arc<[u8]>,
    source_map_identity: Arc<str>,
}

impl DurableRetainedArtifacts {
    /// Returns the exact retained canonical analysis IR bytes.
    #[must_use]
    pub fn canonical_ir(&self) -> &[u8] {
        &self.canonical_ir
    }

    /// Returns the authenticated canonical analysis IR identity.
    #[must_use]
    pub fn canonical_ir_identity(&self) -> &str {
        &self.canonical_ir_identity
    }

    /// Returns the exact retained concrete generated-schema object.
    #[must_use]
    pub fn generated_schemas(&self) -> &[u8] {
        &self.generated_schemas
    }

    /// Returns the authenticated generated-schema object identity.
    #[must_use]
    pub fn generated_schemas_identity(&self) -> &str {
        &self.generated_schemas_identity
    }

    /// Returns the exact retained package-source audit manifest.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Returns the authenticated package-source manifest identity.
    #[must_use]
    pub fn manifest_identity(&self) -> &str {
        &self.manifest_identity
    }

    /// Returns the exact retained canonical source-map bytes.
    #[must_use]
    pub fn source_map(&self) -> &[u8] {
        &self.source_map
    }

    /// Returns the authenticated canonical source-map identity.
    #[must_use]
    pub fn source_map_identity(&self) -> &str {
        &self.source_map_identity
    }
}

/// Accepted recovered execution after compatibility and dependency preflight settled.
#[derive(Clone, Debug)]
pub struct DurableResumeExecutionAccepted {
    /// Stable accepted execution identity recovered from sequence one.
    execution_id: ProtocolIdentity,
    /// In-process observation and cancellation handle accepted at the resume boundary.
    handle: ExecutionHandle,
    pub(crate) owned: Arc<DurableOwnedExecution>,
    pub(crate) recovered: RecoveredDurableStateV1,
    /// Stable journal target retained by the accepted execution.
    journal_id: JournalId,
    pub(crate) ownership_token: JournalOwnershipToken,
    /// Optional completed candidate-source package activity.
    candidate_package_activity: Option<Box<AnalyzePackageResult>>,
    /// Whether source was omitted, exact, or cosmetically different.
    source_comparison: DurableResumeSourceComparison,
    /// Exact authenticated analysis artifacts retained without reparsing source.
    retained_artifacts: DurableRetainedArtifacts,
}

impl DurableResumeExecutionAccepted {
    /// Returns the accepted execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> ProtocolIdentity {
        self.execution_id
    }

    /// Returns the sole in-process observation and control handle.
    #[must_use]
    pub const fn handle(&self) -> &ExecutionHandle {
        &self.handle
    }

    /// Returns the durable journal resumed by this operation.
    #[must_use]
    pub const fn journal_id(&self) -> &JournalId {
        &self.journal_id
    }

    /// Returns the read-only candidate-source provenance comparison.
    #[must_use]
    pub const fn source_comparison(&self) -> DurableResumeSourceComparison {
        self.source_comparison
    }

    /// Returns the read-only authenticated artifacts retained for recovery.
    #[must_use]
    pub const fn retained_artifacts(&self) -> &DurableRetainedArtifacts {
        &self.retained_artifacts
    }

    /// Returns whether resume performed a candidate-source package activity.
    #[must_use]
    pub const fn candidate_package_was_analyzed(&self) -> bool {
        self.candidate_package_activity.is_some()
    }

    /// Returns recovered state for deterministic recovery-protocol fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_recovered(&self) -> &RecoveredDurableStateV1 {
        &self.recovered
    }

    /// Returns the fenced token for deterministic storage-protocol fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub const fn test_ownership_token(&self) -> &JournalOwnershipToken {
        &self.ownership_token
    }
}

/// Durable resume rejection retaining the primary failure and separate owner-release outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableResumeExecutionFailure {
    /// Stable journal target supplied by the embedder.
    pub journal_id: JournalId,
    /// Exact portable resume-start failure category.
    pub category: ResumeStartFailureCategory,
    /// Stable category-local failure code.
    pub code: Arc<str>,
    /// Completed candidate-source activity when analysis reached a judgment.
    pub candidate_package_activity: Option<Box<AnalyzePackageResult>>,
    /// Owner-release failure retained separately from the primary failure.
    pub release_error: Option<JournalError>,
}

/// Durable resume union whose accepted variant exists only after all pre-acceptance work settles.
#[derive(Clone, Debug)]
pub enum DurableResumeExecutionResult {
    /// Existing recovered interpretation was accepted into this interpreter lifecycle.
    Accepted(Box<DurableResumeExecutionAccepted>),
    /// Resume was rejected without mutating the authoritative journal prefix.
    Rejected(DurableResumeExecutionFailure),
}

/// Fully reconstructed resume state whose lifecycle identity is still unpublished.
pub(crate) struct PreparedDurableResume {
    pub(crate) admission: OperationAdmission,
    pub(crate) execution_id: ProtocolIdentity,
    pub(crate) activity_id: ProtocolIdentity,
    pub(crate) recovered: RecoveredDurableStateV1,
    pub(crate) journal_id: JournalId,
    pub(crate) ownership_token: JournalOwnershipToken,
    pub(crate) candidate_package_activity: Option<AnalyzePackageResult>,
    pub(crate) source_comparison: DurableResumeSourceComparison,
    pub(crate) retained_artifacts: DurableRetainedArtifacts,
    pub(crate) mapping_revisions: MappingRevisions,
    pub(crate) event_delivery: gantry_observe::SinkPlan,
    pub(crate) pending_revision: Option<DurableExecutionStateV1>,
}

/// Durable composition of shared preflight, fenced storage, and lifecycle acceptance.
pub struct DurableStartExecutionCoordinator<'a> {
    start: StartExecutionCoordinator<'a>,
    configuration: &'a gantry_runtime::InterpreterConfiguration,
    storage: Arc<dyn JournalStorage>,
}

impl<'a> DurableStartExecutionCoordinator<'a> {
    /// Binds the shared start coordinator to one journal adapter.
    #[must_use]
    pub fn new(
        start: StartExecutionCoordinator<'a>,
        configuration: &'a gantry_runtime::InterpreterConfiguration,
        storage: Arc<dyn JournalStorage>,
    ) -> Self {
        Self {
            start,
            configuration,
            storage,
        }
    }

    /// Acquires a fresh target, commits sequence one, then accepts the execution lifecycle.
    pub async fn start(
        &self,
        request: DurableStartExecutionRequest<'_>,
    ) -> DurableStartExecutionResult {
        self.start_with_registration(request, |_| {}).await
    }

    pub(crate) async fn start_with_registration<F>(
        &self,
        request: DurableStartExecutionRequest<'_>,
        mut registration: F,
    ) -> DurableStartExecutionResult
    where
        F: FnMut(DurableRegistrationEvent),
    {
        let journal_id = request.journal_id;
        let selection = request.start.protocol_selection.clone();
        let required_sinks = request.start.event_delivery.cloned().unwrap_or_default();
        let ownership = match self
            .storage
            .acquire_owner(AcquireJournalOwnerV1 {
                journal_id: journal_id.clone(),
                operation: JournalOwnerOperationV1::Start,
            })
            .await
        {
            Ok(ownership) => ownership,
            Err(error) => {
                return rejected(
                    journal_id,
                    start_failure(
                        StartFailureCategory::InitialJournalOwnership,
                        error.code.wire_name(),
                    ),
                    None,
                );
            }
        };

        let prefix = match self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: journal_id.clone(),
            })
            .await
        {
            Ok(prefix) => prefix,
            Err(error) => {
                return self
                    .reject_and_release(
                        journal_id,
                        ownership.token,
                        start_failure(
                            StartFailureCategory::InitialJournalOwnership,
                            error.code.wire_name(),
                        ),
                    )
                    .await;
            }
        };
        if !fresh_prefix(&prefix) {
            return self
                .reject_and_release(
                    journal_id,
                    ownership.token,
                    start_failure(
                        StartFailureCategory::InitialJournalOwnership,
                        "journal-not-fresh",
                    ),
                )
                .await;
        }

        let mut prepared = match self.start.prepare(request.start).await {
            Ok(prepared) => prepared,
            Err(failure) => {
                return self
                    .reject_and_release(journal_id, ownership.token, failure)
                    .await;
            }
        };
        let execution_start =
            match build_execution_start(&prepared, self.configuration, &selection, &required_sinks)
            {
                Ok(start) => start,
                Err(failure) => {
                    return self
                        .reject_and_release(journal_id, ownership.token, failure)
                        .await;
                }
            };
        let local_id = match BatchLocalEvidenceId::new("execution-start") {
            Ok(local_id) => local_id,
            Err(_) => {
                return self
                    .reject_and_release(
                        journal_id,
                        ownership.token,
                        start_failure(StartFailureCategory::Internal, "execution-start-invariant"),
                    )
                    .await;
            }
        };
        let body = match execution_start.unfinalized(local_id.clone()) {
            Ok(body) => body,
            Err(_) => {
                return self
                    .reject_and_release(
                        journal_id,
                        ownership.token,
                        start_failure(StartFailureCategory::Internal, "execution-start-invariant"),
                    )
                    .await;
            }
        };
        let batch = match JournalBatchV1::new(vec![body], Vec::new()) {
            Ok(batch) => batch,
            Err(_) => {
                return self
                    .reject_and_release(
                        journal_id,
                        ownership.token,
                        start_failure(StartFailureCategory::Internal, "execution-start-invariant"),
                    )
                    .await;
            }
        };
        if let Err(failure) = prepared.reserve_state() {
            return self
                .reject_and_release(journal_id, ownership.token, failure)
                .await;
        }
        let receipt = match self
            .storage
            .commit(JournalCommitRequestV1 {
                journal_id: journal_id.clone(),
                ownership_token: ownership.token.clone(),
                batch,
            })
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                return self
                    .reject_and_release(
                        journal_id,
                        ownership.token,
                        start_failure(
                            StartFailureCategory::ExecutionStartPersistence,
                            error.code.wire_name(),
                        ),
                    )
                    .await;
            }
        };
        let Some(entry) = receipt.entries.first() else {
            return self
                .reject_and_release(
                    journal_id,
                    ownership.token,
                    start_failure(StartFailureCategory::Internal, "execution-start-receipt"),
                )
                .await;
        };
        if receipt.first_sequence != 1
            || receipt.last_sequence != 1
            || receipt.entries.len() != 1
            || entry.sequence != 1
            || entry.batch_local_id != local_id
            || entry.evidence_id.kind() != IdentityKind::Evidence
        {
            return self
                .reject_and_release(
                    journal_id,
                    ownership.token,
                    start_failure(StartFailureCategory::Internal, "execution-start-receipt"),
                )
                .await;
        }
        let evidence_id = entry.evidence_id;
        let execution_id = execution_start.execution_id();
        let recovered = RecoveredDurableStateV1::from_committed_start(
            execution_start,
            evidence_id,
            entry.sequence,
        )
        .unwrap_or_else(|_| unreachable!("validated sequence one reconstructs its own state"));
        registration(DurableRegistrationEvent::Marked(execution_id));
        match prepared.accept_reserved_state() {
            Ok(start) => {
                #[cfg(feature = "test-support")]
                registration(DurableRegistrationEvent::Accepted(start.handle.clone()));
                #[cfg(feature = "concurrent")]
                let execution_budget = recovered.machine().execution_budget();
                let lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&self.storage));
                let owned = lifecycle
                    .own_committed_start(
                        journal_id.clone(),
                        ownership.token.clone(),
                        start.handle.clone(),
                        recovered,
                        required_sinks.clone(),
                    )
                    .unwrap_or_else(|_| {
                        unreachable!("committed start and accepted handle have one identity")
                    });
                registration(DurableRegistrationEvent::Published(Arc::clone(&owned)));
                DurableStartExecutionResult::Accepted(Box::new(DurableStartExecutionAccepted {
                    start,
                    owned,
                    #[cfg(feature = "concurrent")]
                    execution_budget,
                    journal_id,
                    ownership_token: ownership.token,
                    execution_start_evidence_id: evidence_id,
                }))
            }
            Err(failure) => {
                registration(DurableRegistrationEvent::Abandoned(execution_id));
                self.reject_and_release(journal_id, ownership.token, failure)
                    .await
            }
        }
    }

    /// Acquires an existing journal, validates compatibility, and accepts recovery directly.
    pub async fn resume(
        &self,
        request: DurableResumeExecutionRequest<'_>,
    ) -> DurableResumeExecutionResult {
        self.resume_with_handoff(request, |prepared| self.accept_prepared_resume(prepared))
            .await
    }

    /// Completes resume preflight while leaving lifecycle publication to one atomic handoff.
    pub(crate) async fn resume_with_handoff<F, Fut>(
        &self,
        request: DurableResumeExecutionRequest<'_>,
        handoff: F,
    ) -> DurableResumeExecutionResult
    where
        F: FnOnce(PreparedDurableResume) -> Fut,
        Fut: Future<Output = DurableResumeExecutionResult>,
    {
        let journal_id = request.journal_id;
        let ownership = match self
            .storage
            .acquire_owner(AcquireJournalOwnerV1 {
                journal_id: journal_id.clone(),
                operation: JournalOwnerOperationV1::Resume,
            })
            .await
        {
            Ok(ownership) => ownership,
            Err(error) => {
                return resume_rejected(
                    journal_id,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::OwnershipAcquisition,
                        error.code.wire_name(),
                    ),
                    None,
                );
            }
        };
        let prefix = match self
            .storage
            .read_prefix(ReadJournalPrefixV1 {
                journal_id: journal_id.clone(),
            })
            .await
        {
            Ok(prefix) => prefix,
            Err(error) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        ResumeRejection::new(
                            ResumeStartFailureCategory::JournalReadOrFormat,
                            error.code.wire_name(),
                        ),
                    )
                    .await;
            }
        };
        let (_, recovered) = match recover_authoritative_prefix_with_retained_program(&prefix) {
            Ok(recovered) => recovered,
            Err(DurableEvidenceError::Checkpoint(_)) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        ResumeRejection::new(
                            ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                            "invalid-retained-artifact",
                        ),
                    )
                    .await;
            }
            Err(_) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        ResumeRejection::new(
                            ResumeStartFailureCategory::JournalReadOrFormat,
                            "invalid-authoritative-prefix",
                        ),
                    )
                    .await;
            }
        };
        let metadata = match recovered
            .execution_start()
            .ok_or_else(|| {
                ResumeRejection::new(
                    ResumeStartFailureCategory::JournalReadOrFormat,
                    "missing-execution-start",
                )
            })
            .and_then(decode_resume_metadata)
        {
            Ok(metadata) => metadata,
            Err(failure) => {
                return self
                    .reject_resume_and_release(journal_id, ownership.token, failure)
                    .await;
            }
        };
        if request
            .expected_execution_id
            .is_some_and(|expected| expected != metadata.execution_id)
        {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        "execution-identity-mismatch",
                    ),
                )
                .await;
        }
        let event_delivery = request.event_delivery.cloned().unwrap_or_default();
        if required_sinks_json(&event_delivery) != metadata.required_event_sinks {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::UnavailableRequiredEventSink,
                        "required-event-sink-mismatch",
                    ),
                )
                .await;
        }
        if protocol_selection_json(request.protocol_selection) != metadata.protocol_selection {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        "protocol-selection-mismatch",
                    ),
                )
                .await;
        }
        if configuration_json(
            self.configuration,
            request.protocol_selection,
            metadata.root_session_id,
            &metadata.root_session_provenance,
            &event_delivery,
        ) != metadata.configuration
        {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                        "immutable-configuration-mismatch",
                    ),
                )
                .await;
        }
        let mut admission = match self.start.lifecycle.admit(AdmissionKind::NewWork) {
            Ok(admission) => admission,
            Err(error) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        ResumeRejection::new(
                            ResumeStartFailureCategory::Lifecycle,
                            error.code.wire_name(),
                        ),
                    )
                    .await;
            }
        };

        let (mut candidate_package_activity, source_comparison) =
            if let Some(package_root) = request.candidate_package_root {
                let activity = match self
                    .start
                    .package
                    .analyze(AnalyzePackageRequest {
                        package_root,
                        protocol_selection: request.protocol_selection,
                        frontend_limits: self.configuration.required().frontend_limits,
                        event_delivery: None,
                    })
                    .await
                {
                    Ok(activity) => activity,
                    Err(error) => {
                        return self
                            .reject_resume_and_release(
                                journal_id,
                                ownership.token,
                                resume_analysis_failure(error),
                            )
                            .await;
                    }
                };
                if activity.status != AnalyzePackageStatus::SourceValid {
                    return self
                        .reject_resume_and_release(
                            journal_id,
                            ownership.token,
                            ResumeRejection::with_activity(
                                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                                "candidate-source-invalid",
                                activity,
                            ),
                        )
                        .await;
                }
                let comparison = match compare_candidate_source(&metadata, &activity) {
                    Ok(comparison) => comparison,
                    Err(failure) => {
                        return self
                            .reject_resume_and_release(
                                journal_id,
                                ownership.token,
                                failure.with_candidate_activity(activity),
                            )
                            .await;
                    }
                };
                (Some(activity), comparison)
            } else {
                (None, DurableResumeSourceComparison::SourceFree)
            };

        let mapping_revisions = match self.resolve_resume_mappings(&metadata).await {
            Ok(revisions) => revisions,
            Err(failure) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        failure.with_optional_activity(candidate_package_activity),
                    )
                    .await;
            }
        };
        let sessions = match recovered.sessions() {
            Some(sessions) => sessions,
            None => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        ResumeRejection::new(
                            ResumeStartFailureCategory::JournalReadOrFormat,
                            "missing-logical-sessions",
                        )
                        .with_optional_activity(candidate_package_activity),
                    )
                    .await;
            }
        };
        if let Err(failure) = validate_resume_root(&metadata, sessions) {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    failure.with_optional_activity(candidate_package_activity),
                )
                .await;
        }
        if let Err(failure) = self.resolve_resume_sessions(sessions).await {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    failure.with_optional_activity(candidate_package_activity),
                )
                .await;
        }
        if let Some(activity) = candidate_package_activity.as_mut() {
            match self
                .start
                .package
                .deliver_completed_events(&activity.events, request.event_delivery)
                .await
            {
                Ok(deliveries) => activity.deliveries = deliveries,
                Err(_) => {
                    return self
                        .reject_resume_and_release(
                            journal_id,
                            ownership.token,
                            ResumeRejection::new(
                                ResumeStartFailureCategory::UnavailableRequiredEventSink,
                                "required-event-delivery-failure",
                            )
                            .with_optional_activity(candidate_package_activity),
                        )
                        .await;
                }
            }
        }
        if let Err(error) = admission.reserve_execution(metadata.execution_id) {
            return self
                .reject_resume_and_release(
                    journal_id,
                    ownership.token,
                    ResumeRejection::new(
                        ResumeStartFailureCategory::Lifecycle,
                        match error {
                            gantry_runtime::AcceptExecutionError::DuplicateIdentity => {
                                "execution-already-active"
                            }
                            _ => "execution-reservation-invariant",
                        },
                    )
                    .with_optional_activity(candidate_package_activity),
                )
                .await;
        }
        let desired_mutable_policy = mutable_policy_json(self.configuration, &event_delivery);
        let active_mutable_policy = recovered
            .execution_state()
            .map(|state| state.mutable_policy())
            .unwrap_or(metadata.mutable_policy.as_bytes());
        let active_agent_mapping = recovered
            .execution_state()
            .and_then(|state| state.agent_mapping_revision())
            .or(metadata.agent_mapping_revision.as_deref());
        let active_action_mapping = recovered
            .execution_state()
            .and_then(|state| state.action_mapping_revision())
            .or(metadata.action_mapping_revision.as_deref());
        let desired_agent_mapping = mapping_revisions.agent.as_ref().map(|value| value.as_str());
        let desired_action_mapping = mapping_revisions
            .action
            .as_ref()
            .map(|value| value.as_str());
        let pending_revision = if desired_mutable_policy.as_bytes() != active_mutable_policy
            || desired_agent_mapping != active_agent_mapping
            || desired_action_mapping != active_action_mapping
        {
            let revision = match DurableExecutionStateV1::new(
                metadata.execution_id,
                Arc::<[u8]>::from(desired_mutable_policy.into_bytes()),
                desired_agent_mapping.map(Arc::from),
                desired_action_mapping.map(Arc::from),
            ) {
                Ok(revision) => revision,
                Err(_) => {
                    return self
                        .reject_resume_and_release(
                            journal_id,
                            ownership.token,
                            ResumeRejection::new(
                                ResumeStartFailureCategory::Internal,
                                "execution-state-invariant",
                            )
                            .with_optional_activity(candidate_package_activity),
                        )
                        .await;
                }
            };
            Some(revision)
        } else {
            None
        };
        let activity_id = match self.start.fresh_activity_id() {
            Ok(activity_id) => activity_id,
            Err(failure) => {
                return self
                    .reject_resume_and_release(
                        journal_id,
                        ownership.token,
                        resume_preflight_failure(failure)
                            .with_optional_activity(candidate_package_activity),
                    )
                    .await;
            }
        };
        handoff(PreparedDurableResume {
            admission,
            execution_id: metadata.execution_id,
            activity_id,
            recovered,
            journal_id,
            ownership_token: ownership.token,
            candidate_package_activity,
            source_comparison,
            retained_artifacts: metadata.retained_artifacts,
            mapping_revisions,
            event_delivery,
            pending_revision,
        })
        .await
    }

    pub(crate) async fn accept_prepared_resume(
        &self,
        mut prepared: PreparedDurableResume,
    ) -> DurableResumeExecutionResult {
        if let Err(failure) = self.commit_prepared_resume_revision(&mut prepared).await {
            return self.reject_prepared_resume_with(prepared, failure).await;
        }
        match self.publish_prepared_resume(prepared) {
            Ok(accepted) => DurableResumeExecutionResult::Accepted(Box::new(accepted)),
            Err(prepared) => {
                self.reject_prepared_resume(
                    *prepared,
                    ResumeStartFailureCategory::Lifecycle,
                    "execution-already-active",
                )
                .await
            }
        }
    }

    pub(crate) async fn commit_prepared_resume_revision(
        &self,
        prepared: &mut PreparedDurableResume,
    ) -> Result<(), ResumeRejection> {
        let Some(revision) = prepared.pending_revision.take() else {
            return Ok(());
        };
        self.commit_resume_state(
            &prepared.journal_id,
            &prepared.ownership_token,
            &mut prepared.recovered,
            revision,
        )
        .await
    }

    pub(crate) fn publish_prepared_resume(
        &self,
        mut prepared: PreparedDurableResume,
    ) -> Result<DurableResumeExecutionAccepted, Box<PreparedDurableResume>> {
        let handle = match prepared
            .admission
            .accept_reserved_execution(prepared.execution_id)
        {
            Ok(handle) => handle,
            Err(_) => return Err(Box::new(prepared)),
        };
        let lifecycle = DurableLifecycleCoordinator::new(Arc::clone(&self.storage));
        let owned = lifecycle
            .own_committed_start(
                prepared.journal_id.clone(),
                prepared.ownership_token.clone(),
                handle.clone(),
                prepared.recovered.clone(),
                prepared.event_delivery,
            )
            .unwrap_or_else(|_| unreachable!("validated recovery restores its lifecycle state"));
        Ok(DurableResumeExecutionAccepted {
            execution_id: prepared.execution_id,
            handle,
            owned,
            recovered: prepared.recovered,
            journal_id: prepared.journal_id,
            ownership_token: prepared.ownership_token,
            candidate_package_activity: prepared.candidate_package_activity.map(Box::new),
            source_comparison: prepared.source_comparison,
            retained_artifacts: prepared.retained_artifacts,
        })
    }

    pub(crate) async fn reject_prepared_resume(
        &self,
        prepared: PreparedDurableResume,
        category: ResumeStartFailureCategory,
        code: &'static str,
    ) -> DurableResumeExecutionResult {
        self.reject_prepared_resume_with(prepared, ResumeRejection::new(category, code))
            .await
    }

    pub(crate) async fn reject_prepared_resume_with(
        &self,
        prepared: PreparedDurableResume,
        failure: ResumeRejection,
    ) -> DurableResumeExecutionResult {
        self.reject_resume_and_release(
            prepared.journal_id,
            prepared.ownership_token,
            failure.with_optional_activity(prepared.candidate_package_activity),
        )
        .await
    }

    async fn resolve_resume_mappings(
        &self,
        metadata: &ResumeMetadata,
    ) -> Result<MappingRevisions, ResumeRejection> {
        if metadata.agent_names.is_empty() && metadata.action_signatures.is_empty() {
            return Ok(MappingRevisions::default());
        }
        let payload = format!(
            "{{\"action_signatures\":{},\"agent_names\":{}}}",
            json_string_array(&metadata.action_signatures),
            json_string_array(&metadata.agent_names),
        );
        let response = self
            .start
            .call_preflight(EmbeddingOperation::ResolveMappings, payload)
            .await
            .map_err(resume_preflight_failure)?;
        if response.canonical_bytes() == b"{\"result\":\"unresolved\"}" {
            return Err(unresolved_mapping(
                &metadata.action_signatures,
                &metadata.agent_names,
            ));
        }
        let revisions = decode_mapping_revisions(
            &response,
            !metadata.agent_names.is_empty(),
            !metadata.action_signatures.is_empty(),
        )
        .map_err(resume_preflight_failure)?;
        Ok(revisions)
    }

    async fn commit_resume_state(
        &self,
        journal_id: &JournalId,
        ownership_token: &JournalOwnershipToken,
        recovered: &mut RecoveredDurableStateV1,
        revision: DurableExecutionStateV1,
    ) -> Result<(), ResumeRejection> {
        let local_id = BatchLocalEvidenceId::new("execution-state").map_err(|_| {
            ResumeRejection::new(
                ResumeStartFailureCategory::Internal,
                "execution-state-invariant",
            )
        })?;
        let body = revision
            .unfinalized(
                local_id.clone(),
                [JournalEvidenceReferenceV1::Existing(
                    recovered.latest_evidence_id(),
                )],
            )
            .map_err(|_| {
                ResumeRejection::new(
                    ResumeStartFailureCategory::Internal,
                    "execution-state-invariant",
                )
            })?;
        let batch = JournalBatchV1::new(vec![body], Vec::new()).map_err(|_| {
            ResumeRejection::new(
                ResumeStartFailureCategory::Internal,
                "execution-state-invariant",
            )
        })?;
        let expected_sequence = recovered.latest_sequence().checked_add(1).ok_or_else(|| {
            ResumeRejection::new(
                ResumeStartFailureCategory::JournalReadOrFormat,
                "sequence-exhausted",
            )
        })?;
        let receipt = self
            .storage
            .commit(JournalCommitRequestV1 {
                journal_id: journal_id.clone(),
                ownership_token: ownership_token.clone(),
                batch,
            })
            .await
            .map_err(|error| {
                ResumeRejection::new(
                    ResumeStartFailureCategory::JournalReadOrFormat,
                    error.code.wire_name(),
                )
            })?;
        let entry = receipt.entries.first().ok_or_else(|| {
            ResumeRejection::new(
                ResumeStartFailureCategory::Internal,
                "execution-state-receipt",
            )
        })?;
        if receipt.first_sequence != expected_sequence
            || receipt.last_sequence != expected_sequence
            || receipt.entries.len() != 1
            || entry.sequence != expected_sequence
            || entry.batch_local_id != local_id
            || entry.evidence_id.kind() != IdentityKind::Evidence
        {
            return Err(ResumeRejection::new(
                ResumeStartFailureCategory::Internal,
                "execution-state-receipt",
            ));
        }
        recovered
            .record_execution_state_commit(revision, entry.evidence_id, entry.sequence)
            .map_err(|_| {
                ResumeRejection::new(
                    ResumeStartFailureCategory::Internal,
                    "execution-state-receipt",
                )
            })
    }

    async fn resolve_resume_sessions(
        &self,
        sessions: &LogicalSessionRegistryV1,
    ) -> Result<(), ResumeRejection> {
        let response = self
            .start
            .call_preflight(
                EmbeddingOperation::ResolveSessions,
                resume_sessions_json(sessions),
            )
            .await
            .map_err(resume_preflight_failure)?;
        if response.canonical_bytes() == b"{\"result\":\"unresolved\"}" {
            return Err(ResumeRejection::new(
                ResumeStartFailureCategory::UnresolvedLogicalSession,
                "unresolved-logical-session",
            ));
        }
        require_resolved(&response).map_err(resume_preflight_failure)
    }

    async fn reject_and_release(
        &self,
        journal_id: JournalId,
        ownership_token: JournalOwnershipToken,
        failure: StartExecutionFailure,
    ) -> DurableStartExecutionResult {
        let release_error = self
            .storage
            .release_owner(ReleaseJournalOwnerV1 {
                journal_id: journal_id.clone(),
                ownership_token,
            })
            .await
            .err();
        rejected(journal_id, failure, release_error)
    }

    async fn reject_resume_and_release(
        &self,
        journal_id: JournalId,
        ownership_token: JournalOwnershipToken,
        failure: ResumeRejection,
    ) -> DurableResumeExecutionResult {
        let release_error = self
            .storage
            .release_owner(ReleaseJournalOwnerV1 {
                journal_id: journal_id.clone(),
                ownership_token,
            })
            .await
            .err();
        resume_rejected(journal_id, failure, release_error)
    }
}

#[derive(Debug)]
struct ResumeMetadata {
    execution_id: ProtocolIdentity,
    protocol_selection: String,
    configuration: String,
    required_event_sinks: String,
    retained_artifacts: DurableRetainedArtifacts,
    agent_names: Vec<String>,
    action_signatures: Vec<String>,
    agent_mapping_revision: Option<String>,
    action_mapping_revision: Option<String>,
    mutable_policy: String,
    root_session_id: ProtocolIdentity,
    root_session_provenance: String,
    root_session_transcript: String,
}

#[derive(Debug)]
pub(crate) struct ResumeRejection {
    category: ResumeStartFailureCategory,
    code: Arc<str>,
    candidate_package_activity: Option<Box<AnalyzePackageResult>>,
}

impl ResumeRejection {
    fn new(category: ResumeStartFailureCategory, code: impl Into<Arc<str>>) -> Self {
        Self {
            category,
            code: code.into(),
            candidate_package_activity: None,
        }
    }

    fn with_activity(
        category: ResumeStartFailureCategory,
        code: impl Into<Arc<str>>,
        activity: AnalyzePackageResult,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            candidate_package_activity: Some(Box::new(activity)),
        }
    }

    fn with_candidate_activity(mut self, activity: AnalyzePackageResult) -> Self {
        self.candidate_package_activity = Some(Box::new(activity));
        self
    }

    fn with_optional_activity(mut self, activity: Option<AnalyzePackageResult>) -> Self {
        self.candidate_package_activity = activity.map(Box::new);
        self
    }
}

fn decode_resume_metadata(
    execution_start: &DurableExecutionStartV3,
) -> Result<ResumeMetadata, ResumeRejection> {
    let bytes = execution_start.metadata();
    let maximum_bytes = u64::try_from(bytes.len()).map_err(|_| invalid_resume_metadata())?;
    let document = StrictJsonDocument::decode(
        bytes,
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .map_err(|_| invalid_resume_metadata())?;
    let canonical =
        CanonicalJson::from_document(&document).map_err(|_| invalid_resume_metadata())?;
    if canonical.bytes() != bytes {
        return Err(invalid_resume_metadata());
    }
    let root = metadata_object(&document, document.root())?;
    require_metadata_fields(
        root,
        &[
            "action_mapping_revision",
            "action_signatures",
            "agent_mapping_revision",
            "agent_names",
            "canonical_ir",
            "canonical_ir_identity",
            "configuration",
            "configuration_identity",
            "entry",
            "execution_id",
            "format",
            "generated_schemas",
            "generated_schemas_identity",
            "journal_schema",
            "manifest",
            "manifest_identity",
            "maximum_directive_integer",
            "mutable_policy",
            "protocol_selection",
            "protocol_selection_identity",
            "required_event_sinks",
            "required_event_sinks_identity",
            "root_session",
            "source_map",
            "source_map_identity",
        ],
    )?;
    if metadata_string(&document, metadata_field(root, "format")?)?
        != "gantry.execution-start-metadata/v1"
        || metadata_string(
            &document,
            metadata_field(root, "maximum_directive_integer")?,
        )? != gantry_core::portable::MAXIMUM_DIRECTIVE_INTEGER.to_string()
    {
        return Err(invalid_resume_metadata());
    }
    let journal_schema = metadata_object(&document, metadata_field(root, "journal_schema")?)?;
    require_metadata_fields(journal_schema, &["major", "minor"])?;
    if metadata_unsigned(&document, metadata_field(journal_schema, "major")?)? != 1
        || metadata_unsigned(&document, metadata_field(journal_schema, "minor")?)? != 0
    {
        return Err(invalid_resume_metadata());
    }
    let execution_id = ProtocolIdentity::parse_kind(
        metadata_string(&document, metadata_field(root, "execution_id")?)?,
        IdentityKind::Execution,
    )
    .map_err(|_| invalid_resume_metadata())?;
    if execution_id != execution_start.execution_id() {
        return Err(invalid_resume_metadata());
    }
    let protocol_selection =
        canonical_metadata_node(&document, metadata_field(root, "protocol_selection")?)?;
    let configuration = canonical_metadata_node(&document, metadata_field(root, "configuration")?)?;
    let required_event_sinks =
        canonical_metadata_node(&document, metadata_field(root, "required_event_sinks")?)?;
    let mutable_policy =
        canonical_metadata_node(&document, metadata_field(root, "mutable_policy")?)?;
    let canonical_ir_identity =
        metadata_string(&document, metadata_field(root, "canonical_ir_identity")?)?;
    let manifest_identity = metadata_string(&document, metadata_field(root, "manifest_identity")?)?;
    let source_map_identity =
        metadata_string(&document, metadata_field(root, "source_map_identity")?)?;
    let generated_schemas_identity = metadata_string(
        &document,
        metadata_field(root, "generated_schemas_identity")?,
    )?;
    let canonical_ir = retained_artifact(
        metadata_string(&document, metadata_field(root, "canonical_ir")?)?,
        canonical_ir_identity,
    )?;
    let generated_schemas = retained_artifact(
        metadata_string(&document, metadata_field(root, "generated_schemas")?)?,
        generated_schemas_identity,
    )?;
    let manifest = retained_artifact(
        metadata_string(&document, metadata_field(root, "manifest")?)?,
        manifest_identity,
    )?;
    let source_map = retained_artifact(
        metadata_string(&document, metadata_field(root, "source_map")?)?,
        source_map_identity,
    )?;
    if !canonical_identity_matches(
        &protocol_selection,
        metadata_string(
            &document,
            metadata_field(root, "protocol_selection_identity")?,
        )?,
    ) || !canonical_identity_matches(
        &configuration,
        metadata_string(&document, metadata_field(root, "configuration_identity")?)?,
    ) || !canonical_identity_matches(
        &required_event_sinks,
        metadata_string(
            &document,
            metadata_field(root, "required_event_sinks_identity")?,
        )?,
    ) {
        return Err(invalid_resume_metadata());
    }
    let root_session = metadata_object(&document, metadata_field(root, "root_session")?)?;
    require_metadata_fields(root_session, &["id", "provenance", "transcript"])?;
    let root_session_id = ProtocolIdentity::parse_kind(
        metadata_string(&document, metadata_field(root_session, "id")?)?,
        IdentityKind::Session,
    )
    .map_err(|_| invalid_resume_metadata())?;
    let root_session_provenance =
        metadata_string(&document, metadata_field(root_session, "provenance")?)?.to_owned();
    if !matches!(
        root_session_provenance.as_str(),
        "embedder-supplied" | "gantry-created"
    ) {
        return Err(invalid_resume_metadata());
    }
    let root_session_transcript =
        canonical_metadata_node(&document, metadata_field(root_session, "transcript")?)?;
    Ok(ResumeMetadata {
        execution_id,
        protocol_selection,
        configuration,
        required_event_sinks,
        retained_artifacts: DurableRetainedArtifacts {
            canonical_ir,
            canonical_ir_identity: Arc::from(canonical_ir_identity),
            generated_schemas,
            generated_schemas_identity: Arc::from(generated_schemas_identity),
            manifest,
            manifest_identity: Arc::from(manifest_identity),
            source_map,
            source_map_identity: Arc::from(source_map_identity),
        },
        agent_names: metadata_string_array(&document, metadata_field(root, "agent_names")?)?,
        action_signatures: metadata_string_array(
            &document,
            metadata_field(root, "action_signatures")?,
        )?,
        agent_mapping_revision: metadata_optional_string(
            &document,
            metadata_field(root, "agent_mapping_revision")?,
        )?
        .map(str::to_owned),
        action_mapping_revision: metadata_optional_string(
            &document,
            metadata_field(root, "action_mapping_revision")?,
        )?
        .map(str::to_owned),
        mutable_policy,
        root_session_id,
        root_session_provenance,
        root_session_transcript,
    })
}

fn compare_candidate_source(
    metadata: &ResumeMetadata,
    activity: &AnalyzePackageResult,
) -> Result<DurableResumeSourceComparison, ResumeRejection> {
    let analysis = activity.analysis.as_ref().ok_or_else(|| {
        ResumeRejection::new(
            ResumeStartFailureCategory::Internal,
            "missing-candidate-analysis",
        )
    })?;
    let canonical_ir = analysis.canonical_ir().ok_or_else(|| {
        ResumeRejection::new(ResumeStartFailureCategory::Internal, "missing-candidate-ir")
    })?;
    let manifest = analysis.manifest().ok_or_else(|| {
        ResumeRejection::new(
            ResumeStartFailureCategory::Internal,
            "missing-candidate-manifest",
        )
    })?;
    if canonical_ir.artifact().sha256_hex() != metadata.retained_artifacts.canonical_ir_identity() {
        return Err(ResumeRejection::new(
            ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
            "canonical-ir-identity-mismatch",
        ));
    }
    Ok(
        if manifest.artifact().sha256_hex() == metadata.retained_artifacts.manifest_identity() {
            DurableResumeSourceComparison::ExactManifest
        } else {
            DurableResumeSourceComparison::CosmeticManifestDifference
        },
    )
}

fn validate_resume_root(
    metadata: &ResumeMetadata,
    sessions: &LogicalSessionRegistryV1,
) -> Result<(), ResumeRejection> {
    let root = sessions
        .sessions()
        .find(|session| session.parent.is_none())
        .ok_or_else(|| {
            ResumeRejection::new(
                ResumeStartFailureCategory::JournalReadOrFormat,
                "missing-root-session",
            )
        })?;
    let provenance = match root.mode {
        SessionCreationModeV1::EmbedderRoot => "embedder-supplied",
        SessionCreationModeV1::GantryRoot => "gantry-created",
        SessionCreationModeV1::New | SessionCreationModeV1::Fork => {
            return Err(ResumeRejection::new(
                ResumeStartFailureCategory::JournalReadOrFormat,
                "invalid-root-session-mode",
            ));
        }
    };
    let transcript = std::str::from_utf8(root.transcript.bytes()).map_err(|_| {
        ResumeRejection::new(
            ResumeStartFailureCategory::JournalReadOrFormat,
            "invalid-root-session-transcript",
        )
    })?;
    if root.id != metadata.root_session_id
        || provenance != metadata.root_session_provenance
        || transcript != metadata.root_session_transcript
    {
        return Err(ResumeRejection::new(
            ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
            "root-session-mismatch",
        ));
    }
    Ok(())
}

fn resume_sessions_json(sessions: &LogicalSessionRegistryV1) -> String {
    let mut output = String::from("{\"session_descriptors\":[");
    for (index, session) in sessions.sessions().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"opaque_lookup_material\":null,\"provenance\":");
        push_json_string(
            &mut output,
            match session.mode {
                SessionCreationModeV1::EmbedderRoot => "embedder-supplied",
                SessionCreationModeV1::GantryRoot => "gantry-created",
                SessionCreationModeV1::New => "gantry-new",
                SessionCreationModeV1::Fork => "gantry-fork",
            },
        );
        output.push_str(",\"session_id\":");
        push_json_string(&mut output, &session.id.to_string());
        output.push_str(",\"transcript\":");
        output.push_str(
            std::str::from_utf8(session.transcript.bytes())
                .unwrap_or_else(|_| unreachable!("validated transcripts are UTF-8")),
        );
        output.push('}');
    }
    output.push_str("]}");
    output
}

fn unresolved_mapping(actions: &[String], agents: &[String]) -> ResumeRejection {
    if !actions.is_empty() {
        ResumeRejection::new(
            ResumeStartFailureCategory::UnresolvedActionMapping,
            "unresolved-action-mapping",
        )
    } else if !agents.is_empty() {
        ResumeRejection::new(
            ResumeStartFailureCategory::UnresolvedAgentMapping,
            "unresolved-agent-mapping",
        )
    } else {
        ResumeRejection::new(
            ResumeStartFailureCategory::IntegrationPreflight,
            "unresolved-mapping",
        )
    }
}

fn resume_preflight_failure(failure: StartExecutionFailure) -> ResumeRejection {
    let category = if failure.category == StartFailureCategory::Internal {
        ResumeStartFailureCategory::Internal
    } else {
        ResumeStartFailureCategory::IntegrationPreflight
    };
    ResumeRejection {
        category,
        code: failure.code,
        candidate_package_activity: failure.package_activity,
    }
}

fn resume_analysis_failure(error: AnalyzePackageError) -> ResumeRejection {
    let category = match &error {
        AnalyzePackageError::Package(error) if error.frontend_resource_limit().is_some() => {
            ResumeStartFailureCategory::FrontendResourceLimit
        }
        AnalyzePackageError::Analysis(gantry_analysis::AnalysisError::ResourceLimit { .. }) => {
            ResumeStartFailureCategory::FrontendResourceLimit
        }
        AnalyzePackageError::Package(_) => {
            ResumeStartFailureCategory::SourceOrConfigurationIncompatibility
        }
        AnalyzePackageError::ActivityIdentity(_) => {
            ResumeStartFailureCategory::IntegrationPreflight
        }
        AnalyzePackageError::Analysis(_)
        | AnalyzePackageError::Event(_)
        | AnalyzePackageError::MissingDeliveryRuntime
        | AnalyzePackageError::Delivery(_)
        | AnalyzePackageError::RequiredEventDelivery => ResumeStartFailureCategory::Internal,
    };
    ResumeRejection::new(category, error.code())
}

fn resume_rejected(
    journal_id: JournalId,
    failure: ResumeRejection,
    release_error: Option<JournalError>,
) -> DurableResumeExecutionResult {
    DurableResumeExecutionResult::Rejected(DurableResumeExecutionFailure {
        journal_id,
        category: failure.category,
        code: failure.code,
        candidate_package_activity: failure.candidate_package_activity,
        release_error,
    })
}

fn invalid_resume_metadata() -> ResumeRejection {
    ResumeRejection::new(
        ResumeStartFailureCategory::JournalReadOrFormat,
        "invalid-execution-start-metadata",
    )
}

fn metadata_object(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<&[(Arc<str>, JsonNodeId)], ResumeRejection> {
    match document.node(id) {
        Some(JsonNode::Object(members)) => Ok(members),
        _ => Err(invalid_resume_metadata()),
    }
}

fn metadata_field(
    object: &[(Arc<str>, JsonNodeId)],
    name: &str,
) -> Result<JsonNodeId, ResumeRejection> {
    object
        .iter()
        .find_map(|(candidate, value)| (candidate.as_ref() == name).then_some(*value))
        .ok_or_else(invalid_resume_metadata)
}

fn require_metadata_fields(
    object: &[(Arc<str>, JsonNodeId)],
    expected: &[&str],
) -> Result<(), ResumeRejection> {
    if object.len() == expected.len()
        && expected
            .iter()
            .all(|expected| object.iter().any(|(name, _)| name.as_ref() == *expected))
    {
        Ok(())
    } else {
        Err(invalid_resume_metadata())
    }
}

fn metadata_string(document: &StrictJsonDocument, id: JsonNodeId) -> Result<&str, ResumeRejection> {
    match document.node(id) {
        Some(JsonNode::String(value)) => Ok(value),
        _ => Err(invalid_resume_metadata()),
    }
}

fn metadata_optional_string(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Option<&str>, ResumeRejection> {
    match document.node(id) {
        Some(JsonNode::Null) => Ok(None),
        Some(JsonNode::String(value)) => Ok(Some(value)),
        _ => Err(invalid_resume_metadata()),
    }
}

fn metadata_unsigned(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<u64, ResumeRejection> {
    match document.node(id) {
        Some(JsonNode::Number(value)) => value
            .to_gantry_int()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(invalid_resume_metadata),
        _ => Err(invalid_resume_metadata()),
    }
}

fn metadata_string_array(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<Vec<String>, ResumeRejection> {
    let Some(JsonNode::Array(values)) = document.node(id) else {
        return Err(invalid_resume_metadata());
    };
    values
        .iter()
        .map(|value| metadata_string(document, *value).map(str::to_owned))
        .collect()
}

enum MetadataEncodeTask {
    Node(JsonNodeId),
    Byte(char),
    String(Arc<str>),
}

fn canonical_metadata_node(
    document: &StrictJsonDocument,
    id: JsonNodeId,
) -> Result<String, ResumeRejection> {
    let mut output = String::new();
    let mut work = vec![MetadataEncodeTask::Node(id)];
    while let Some(task) = work.pop() {
        match task {
            MetadataEncodeTask::Byte(value) => output.push(value),
            MetadataEncodeTask::String(value) => push_json_string(&mut output, &value),
            MetadataEncodeTask::Node(id) => match document.node(id) {
                Some(JsonNode::Null) => output.push_str("null"),
                Some(JsonNode::Bool(true)) => output.push_str("true"),
                Some(JsonNode::Bool(false)) => output.push_str("false"),
                Some(JsonNode::Number(value)) => output.push_str(value.lexeme()),
                Some(JsonNode::String(value)) => push_json_string(&mut output, value),
                Some(JsonNode::Array(items)) => {
                    output.push('[');
                    let mut sequence = Vec::with_capacity(items.len().saturating_mul(2));
                    for (index, item) in items.iter().copied().enumerate() {
                        if index > 0 {
                            sequence.push(MetadataEncodeTask::Byte(','));
                        }
                        sequence.push(MetadataEncodeTask::Node(item));
                    }
                    sequence.push(MetadataEncodeTask::Byte(']'));
                    work.extend(sequence.into_iter().rev());
                }
                Some(JsonNode::Object(members)) => {
                    output.push('{');
                    let mut sequence = Vec::with_capacity(members.len().saturating_mul(4));
                    for (index, (name, value)) in members.iter().enumerate() {
                        if index > 0 {
                            sequence.push(MetadataEncodeTask::Byte(','));
                        }
                        sequence.push(MetadataEncodeTask::String(Arc::clone(name)));
                        sequence.push(MetadataEncodeTask::Byte(':'));
                        sequence.push(MetadataEncodeTask::Node(*value));
                    }
                    sequence.push(MetadataEncodeTask::Byte('}'));
                    work.extend(sequence.into_iter().rev());
                }
                None => return Err(invalid_resume_metadata()),
            },
        }
    }
    Ok(output)
}

fn canonical_identity_matches(value: &str, expected: &str) -> bool {
    let Ok(maximum_bytes) = u64::try_from(value.len()) else {
        return false;
    };
    StrictJsonDocument::decode(
        value.as_bytes(),
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .ok()
    .and_then(|document| CanonicalJson::from_document(&document).ok())
    .is_some_and(|canonical| {
        canonical.bytes() == value.as_bytes() && canonical.sha256_hex() == expected
    })
}

fn retained_artifact(encoded: &str, expected: &str) -> Result<Arc<[u8]>, ResumeRejection> {
    decode_lower_hex(encoded)
        .filter(|bytes| {
            std::str::from_utf8(bytes)
                .is_ok_and(|value| canonical_identity_matches(value, expected))
        })
        .map(Arc::from)
        .ok_or_else(|| {
            ResumeRejection::new(
                ResumeStartFailureCategory::SourceOrConfigurationIncompatibility,
                "invalid-retained-artifact",
            )
        })
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn json_string_array(values: &[String]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, value);
    }
    output.push(']');
    output
}

fn build_execution_start(
    prepared: &PreparedExecutionStart,
    configuration: &gantry_runtime::InterpreterConfiguration,
    selection: &gantry_core::protocol::ProtocolSelection,
    required_sinks: &gantry_observe::SinkPlan,
) -> Result<DurableExecutionStartV3, StartExecutionFailure> {
    let analysis = prepared
        .package_activity
        .analysis
        .as_ref()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-analysis"))?;
    let entry = analysis
        .entry()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-entry"))?;
    let program = analysis.executable_program().cloned().ok_or_else(|| {
        start_failure(StartFailureCategory::Internal, "missing-executable-program")
    })?;
    let arguments = prepared
        .entry_input
        .as_ref()
        .map(|input| {
            decode_logical_value(
                input.canonical_json.bytes(),
                &input.ty,
                configuration.required().value_limits,
                analysis.declared_value_shapes(),
            )
            .map(|value| vec![value])
        })
        .transpose()
        .map_err(|_| start_failure(StartFailureCategory::Internal, "entry-reconstruction"))?
        .unwrap_or_default();
    let initial_agent = analysis.structure().default_agent().map(Arc::from);
    let machine = Machine::new_with_context(
        Arc::new(program.clone()),
        &entry.path,
        arguments,
        prepared.execution_id,
        configuration.machine_limits(),
        initial_agent,
        Some(prepared.root_session.id),
    )
    .map_err(|_| start_failure(StartFailureCategory::Internal, "machine-build"))?;
    let root_mode = match prepared.root_session.provenance {
        crate::RootSessionProvenance::EmbedderSupplied => SessionCreationModeV1::EmbedderRoot,
        crate::RootSessionProvenance::GantryCreated => SessionCreationModeV1::GantryRoot,
    };
    let sessions = LogicalSessionRegistryV1::new(
        prepared.execution_id,
        prepared.root_session.id,
        root_mode,
        prepared.root_session.transcript.clone(),
    )
    .map_err(|_| start_failure(StartFailureCategory::Internal, "session-state"))?;
    let task_id = root_task_identity(prepared.execution_id);
    let state = DurableLogicalEvidenceV3::new_with_sessions(
        prepared.execution_id,
        task_id,
        DurableCommitCutV1::Checkpoint,
        None,
        &machine,
        Some(sessions.checkpoint()),
    )
    .map_err(|_: DurableEvidenceError| {
        start_failure(StartFailureCategory::Internal, "execution-start-state")
    })?;
    let metadata = execution_start_metadata(prepared, configuration, selection, required_sinks)?;
    DurableExecutionStartV3::new(prepared.execution_id, task_id, &program, metadata, state)
        .map_err(|_| start_failure(StartFailureCategory::Internal, "execution-start-metadata"))
}

fn fresh_prefix(prefix: &gantry_host::journal::JournalPrefixV1) -> bool {
    matches!(
        prefix,
        gantry_host::journal::JournalPrefixV1::Full(prefix)
            if prefix.evidence.is_empty() && prefix.committed_through == 0
    )
}

fn start_failure(
    category: StartFailureCategory,
    code: impl Into<Arc<str>>,
) -> StartExecutionFailure {
    StartExecutionFailure {
        category,
        code: code.into(),
        package_activity: None,
    }
}

fn rejected(
    journal_id: JournalId,
    failure: StartExecutionFailure,
    release_error: Option<JournalError>,
) -> DurableStartExecutionResult {
    DurableStartExecutionResult::Rejected(DurableStartExecutionFailure {
        journal_id,
        failure,
        release_error,
    })
}

fn execution_start_metadata(
    prepared: &PreparedExecutionStart,
    configuration: &gantry_runtime::InterpreterConfiguration,
    selection: &gantry_core::protocol::ProtocolSelection,
    required_sinks: &gantry_observe::SinkPlan,
) -> Result<Arc<[u8]>, StartExecutionFailure> {
    let analysis = prepared
        .package_activity
        .analysis
        .as_ref()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-analysis"))?;
    let manifest = analysis
        .manifest()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-manifest"))?;
    let ir = analysis
        .canonical_ir()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-canonical-ir"))?;
    let source_map = analysis
        .source_map()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-source-map"))?;
    let schemas = analysis
        .schemas()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-schemas"))?;
    let entry = analysis
        .entry()
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "missing-entry"))?;
    let protocol_selection_json = protocol_selection_json(selection);
    let protocol_selection_identity = canonical_identity(&protocol_selection_json)?;
    let required_sinks_json = required_sinks_json(required_sinks);
    let required_sinks_identity = canonical_identity(&required_sinks_json)?;
    let mutable_policy_json = mutable_policy_json(configuration, required_sinks);
    let root_session_provenance = match prepared.root_session.provenance {
        crate::RootSessionProvenance::EmbedderSupplied => "embedder-supplied",
        crate::RootSessionProvenance::GantryCreated => "gantry-created",
    };
    let configuration_json = configuration_json(
        configuration,
        selection,
        prepared.root_session.id,
        root_session_provenance,
        required_sinks,
    );
    let configuration_identity = canonical_identity(&configuration_json)?;
    let mut output = String::from("{\"action_mapping_revision\":");
    push_optional_string(
        &mut output,
        prepared
            .mapping_revisions
            .action
            .as_ref()
            .map(|value| value.as_str()),
    );
    output.push_str(",\"action_signatures\":[");
    for (index, action) in analysis.actions().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, action.signature.as_str());
    }
    output.push_str("],\"agent_mapping_revision\":");
    push_optional_string(
        &mut output,
        prepared
            .mapping_revisions
            .agent
            .as_ref()
            .map(|value| value.as_str()),
    );
    output.push_str(",\"agent_names\":[");
    for (index, agent) in analysis.structure().agents().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(&mut output, &agent.name);
    }
    output.push(']');
    output.push_str(",\"canonical_ir\":");
    push_json_string(&mut output, &hex(ir.artifact().canonical_bytes()));
    output.push_str(",\"canonical_ir_identity\":");
    push_json_string(&mut output, &ir.artifact().sha256_hex());
    output.push_str(",\"configuration\":");
    output.push_str(&configuration_json);
    output.push_str(",\"configuration_identity\":");
    push_json_string(&mut output, &configuration_identity);
    output.push_str(",\"entry\":{\"input\":");
    match &prepared.entry_input {
        Some(input) => output.push_str(
            std::str::from_utf8(input.canonical_json.bytes())
                .map_err(|_| start_failure(StartFailureCategory::Internal, "entry-utf8"))?,
        ),
        None => output.push_str("null"),
    }
    output.push_str(",\"input_type\":");
    match &prepared.entry_input {
        Some(input) => push_json_string(&mut output, &input.ty.canonical_string()),
        None => output.push_str("null"),
    }
    output.push_str(",\"signature\":");
    let signature = analysis
        .workflows()
        .iter()
        .find(|workflow| workflow.path == entry.path)
        .map(|workflow| workflow.signature.as_str())
        .ok_or_else(|| start_failure(StartFailureCategory::Internal, "entry-signature"))?;
    push_json_string(&mut output, signature);
    output.push('}');
    output.push_str(",\"execution_id\":");
    push_json_string(&mut output, &prepared.execution_id.to_string());
    output.push_str(",\"format\":\"gantry.execution-start-metadata/v1\",\"generated_schemas\":");
    push_json_string(&mut output, &hex(schemas.artifact().canonical_bytes()));
    output.push_str(",\"generated_schemas_identity\":");
    push_json_string(&mut output, &schemas.artifact().sha256_hex());
    output.push_str(",\"journal_schema\":{\"major\":1,\"minor\":0},\"manifest\":");
    push_json_string(&mut output, &hex(manifest.artifact().canonical_bytes()));
    output.push_str(",\"manifest_identity\":");
    push_json_string(&mut output, &manifest.artifact().sha256_hex());
    output.push_str(",\"maximum_directive_integer\":");
    push_json_string(
        &mut output,
        &gantry_core::portable::MAXIMUM_DIRECTIVE_INTEGER.to_string(),
    );
    output.push_str(",\"mutable_policy\":");
    output.push_str(&mutable_policy_json);
    output.push_str(",\"protocol_selection\":");
    output.push_str(&protocol_selection_json);
    output.push_str(",\"protocol_selection_identity\":");
    push_json_string(&mut output, &protocol_selection_identity);
    output.push_str(",\"required_event_sinks\":");
    output.push_str(&required_sinks_json);
    output.push_str(",\"required_event_sinks_identity\":");
    push_json_string(&mut output, &required_sinks_identity);
    output.push_str(",\"root_session\":{\"id\":");
    push_json_string(&mut output, &prepared.root_session.id.to_string());
    output.push_str(",\"provenance\":");
    push_json_string(&mut output, root_session_provenance);
    output.push_str(",\"transcript\":");
    output.push_str(
        std::str::from_utf8(prepared.root_session.transcript.bytes())
            .map_err(|_| start_failure(StartFailureCategory::Internal, "transcript-utf8"))?,
    );
    output.push('}');
    output.push_str(",\"source_map\":");
    push_json_string(&mut output, &hex(source_map.artifact().canonical_bytes()));
    output.push_str(",\"source_map_identity\":");
    push_json_string(&mut output, &source_map.artifact().sha256_hex());
    output.push('}');
    Ok(Arc::from(output.into_bytes()))
}

fn configuration_json(
    configuration: &gantry_runtime::InterpreterConfiguration,
    selection: &ProtocolSelection,
    root_session_id: ProtocolIdentity,
    root_session_provenance: &str,
    event_sinks: &gantry_observe::SinkPlan,
) -> String {
    let required = configuration.required();
    let retry = configuration.retry_defaults();
    let version = |family| selection.version(family);
    let protocol = |family| {
        let version = version(family);
        format!(
            "{{\"major\":{},\"minor\":{}}}",
            version.major, version.minor
        )
    };
    format!(
        "{{\"canonical_ir_protocol\":{},\"configuration_protocol\":{},\"deterministic_values\":{{\"maximum_entry_input_bytes\":{},\"maximum_hook_output_bytes\":{},\"maximum_list_items\":{},\"maximum_string_scalars\":{},\"maximum_value_nesting_depth\":{},\"maximum_value_nodes\":{}}},\"embedding_protocol\":{},\"event_protocol\":{},\"hook_protocol\":{},\"interpreter\":{{\"maximum_deterministic_transitions_per_execution\":{},\"maximum_loop_iterations_per_task\":{},\"maximum_operations_per_execution\":{},\"maximum_tasks_per_execution\":{},\"maximum_workflow_call_depth\":{}}},\"journal_protocol\":{},\"maximum_directive_integer\":{},\"recovery_projection_protocol\":{},\"required_event_sinks\":{},\"root_session\":{{\"id\":{},\"provenance\":{}}},\"source_language\":{},\"source_map_protocol\":{},\"structured_output\":{{\"action_retry_limit\":{},\"backoff\":{{\"cap_us\":{},\"initial_us\":{},\"jitter\":{}}},\"model_retry_limit\":{}}},\"value_protocol\":{}}}",
        protocol(gantry_core::portable::ProtocolFamily::CanonicalIr),
        protocol(gantry_core::portable::ProtocolFamily::Configuration),
        json_string(&required.maximum_entry_input_bytes.to_string()),
        json_string(&required.maximum_hook_output_bytes.to_string()),
        json_string(&required.value_limits.maximum_list_items().to_string()),
        json_string(&required.value_limits.maximum_string_scalars().to_string()),
        json_string(&required.value_limits.maximum_nesting_depth().to_string()),
        json_string(&required.value_limits.maximum_nodes().to_string()),
        protocol(gantry_core::portable::ProtocolFamily::Embedding),
        protocol(gantry_core::portable::ProtocolFamily::Event),
        protocol(gantry_core::portable::ProtocolFamily::Hook),
        json_string(
            &required
                .maximum_deterministic_transitions_per_execution
                .to_string()
        ),
        json_string(&required.maximum_loop_iterations_per_task.to_string()),
        json_string(&required.maximum_operations_per_execution.to_string()),
        json_string(&configuration.maximum_tasks_per_execution().to_string()),
        json_string(&configuration.maximum_workflow_call_depth().to_string()),
        protocol(gantry_core::portable::ProtocolFamily::Journal),
        json_string(&gantry_core::portable::MAXIMUM_DIRECTIVE_INTEGER.to_string()),
        protocol(gantry_core::portable::ProtocolFamily::RecoveryProjection),
        required_sinks_json(event_sinks),
        json_string(&root_session_id.to_string()),
        json_string(root_session_provenance),
        protocol(gantry_core::portable::ProtocolFamily::SourceLanguage),
        protocol(gantry_core::portable::ProtocolFamily::SourceMap),
        json_string(&retry.action_retry_limit.to_string()),
        json_string(&retry.backoff_cap.get().to_string()),
        json_string(&retry.backoff_initial.get().to_string()),
        json_string(retry.jitter.wire_name()),
        json_string(&retry.model_retry_limit.to_string()),
        protocol(gantry_core::portable::ProtocolFamily::Value),
    )
}

fn protocol_selection_json(selection: &gantry_core::protocol::ProtocolSelection) -> String {
    let mut output = String::from("{\"protocols\":[");
    for (index, protocol) in selection.protocols().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"family\":");
        push_json_string(&mut output, protocol.family.wire_name());
        output.push_str(",\"major\":");
        output.push_str(&protocol.version.major.to_string());
        output.push_str(",\"minor\":");
        output.push_str(&protocol.version.minor.to_string());
        output.push('}');
    }
    output.push_str("],\"specification_revision\":");
    push_json_string(&mut output, &selection.specification_revision());
    output.push('}');
    output
}

fn required_sinks_json(required_sinks: &gantry_observe::SinkPlan) -> String {
    let mut output = String::from("[");
    let mut first = true;
    for registration in required_sinks
        .registrations()
        .iter()
        .filter(|registration| registration.policy().class == SinkClass::Required)
    {
        if !first {
            output.push(',');
        }
        first = false;
        push_sink_registration(&mut output, registration, false);
    }
    output.push(']');
    output
}

fn best_effort_sinks_json(event_sinks: &gantry_observe::SinkPlan) -> String {
    let mut output = String::from("[");
    let mut first = true;
    for registration in event_sinks
        .registrations()
        .iter()
        .filter(|registration| registration.policy().class == SinkClass::BestEffort)
    {
        if !first {
            output.push(',');
        }
        first = false;
        push_sink_registration(&mut output, registration, true);
    }
    output.push(']');
    output
}

fn mutable_policy_json(
    configuration: &gantry_runtime::InterpreterConfiguration,
    event_sinks: &gantry_observe::SinkPlan,
) -> String {
    format!(
        "{{\"best_effort_event_sinks\":{},\"graceful_shutdown_timeout_us\":{},\"post_cancellation_drain_us\":{}}}",
        best_effort_sinks_json(event_sinks),
        json_string(&configuration.graceful_shutdown_timeout().get().to_string()),
        json_string(&configuration.post_cancellation_drain().get().to_string()),
    )
}

fn push_sink_registration(
    output: &mut String,
    registration: &gantry_observe::SinkRegistration,
    include_class: bool,
) {
    let policy = registration.policy();
    output.push_str("{\"attempt_timeout_us\":");
    push_json_string(output, &policy.attempt_timeout_us.to_string());
    output.push_str(",\"backoff\":{\"cap_us\":");
    push_json_string(output, &policy.retry.cap_us.to_string());
    output.push_str(",\"initial_us\":");
    push_json_string(output, &policy.retry.initial_delay_us.to_string());
    output.push_str(",\"jitter\":");
    push_json_string(output, policy.retry.jitter.wire_name());
    output.push('}');
    if include_class {
        output.push_str(",\"class\":\"best-effort\"");
    }
    output.push_str(",\"id\":");
    push_json_string(output, registration.id().as_str());
    output.push_str(",\"raw_output_enabled\":");
    output.push_str(if policy.raw_output { "true" } else { "false" });
    output.push_str(",\"redaction_capabilities\":{\"integration_diagnostics\":");
    output.push_str(if policy.capabilities.integration_diagnostics {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"operation_request_content\":");
    output.push_str(if policy.capabilities.operation_request_content {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"operation_result_content\":");
    output.push_str(if policy.capabilities.operation_result_content {
        "true"
    } else {
        "false"
    });
    output.push_str(",\"source_snippets\":");
    output.push_str(if policy.capabilities.source_snippets {
        "true"
    } else {
        "false"
    });
    output.push('}');
    output.push_str(",\"redaction_policy_id\":");
    push_json_string(output, &policy.redaction_policy_id);
    output.push_str(",\"retry_limit\":");
    push_json_string(output, &policy.retry.retry_limit.to_string());
    output.push_str(",\"retry_policy_revision\":");
    push_json_string(output, &policy.retry.revision);
    output.push('}');
}

fn canonical_identity(value: &str) -> Result<String, StartExecutionFailure> {
    let maximum_bytes = u64::try_from(value.len())
        .map_err(|_| start_failure(StartFailureCategory::Internal, "metadata-size"))?;
    let document = StrictJsonDocument::decode(
        value.as_bytes(),
        JsonLimits {
            maximum_bytes,
            maximum_nesting_depth: maximum_bytes.max(1),
            maximum_nodes: maximum_bytes.max(1),
            maximum_string_scalars: maximum_bytes.max(1),
            maximum_list_items: maximum_bytes.max(1),
        },
    )
    .map_err(|_| start_failure(StartFailureCategory::Internal, "metadata-json"))?;
    CanonicalJson::from_document(&document)
        .map(|value| value.sha256_hex())
        .map_err(|_| start_failure(StartFailureCategory::Internal, "metadata-canonical"))
}

fn json_string(value: &str) -> String {
    let mut output = String::new();
    push_json_string(&mut output, value);
    output
}

fn push_optional_string(output: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_json_string(output, value),
        None => output.push_str("null"),
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for scalar in value.chars() {
        match scalar {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            value if value <= '\u{1f}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
