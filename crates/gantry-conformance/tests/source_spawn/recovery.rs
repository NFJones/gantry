//! Public crash-cut recovery regressions using the source-task fixture services.

use super::*;

#[path = "rollback.rs"]
mod rollback;
use rollback::assert_recovered_submission_rollback;

struct RejectExecutionStateStore {
    parent: Arc<FailingGraphJournalStore>,
    rejected: AtomicBool,
}

impl RejectExecutionStateStore {
    fn new(parent: Arc<FailingGraphJournalStore>) -> Self {
        Self {
            parent,
            rejected: AtomicBool::new(false),
        }
    }
}

impl JournalStorage for RejectExecutionStateStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.parent.acquire_owner(request)
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        self.parent.read_prefix(request)
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        let has_execution_state = request
            .batch
            .evidence
            .iter()
            .any(|evidence| evidence.kind.as_ref() == "gantry.execution-state/v1");
        if has_execution_state && !self.rejected.swap(true, Ordering::AcqRel) {
            Box::pin(async { Err(JournalError::new(JournalErrorCode::Internal)) })
        } else {
            self.parent.commit(request)
        }
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.parent.resolve_payload(request)
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.parent.release_owner(request)
    }
}

#[test]
fn missing_dispatch_event_is_repaired_before_redispatch() {
    recover_missing_operation_event(
        "\"kind\":\"operation-dispatch\"",
        DurableCommitCutV1::OperationPrepared,
        EventKind::OperationDispatch,
    );
}

#[test]
fn missing_operation_result_event_is_replaced_before_source_consumption() {
    recover_missing_operation_event(
        "\"kind\":\"operation-result\"",
        DurableCommitCutV1::OperationResult,
        EventKind::OperationResult,
    );
}

#[test]
fn missing_operation_completion_event_is_replaced_before_outcome_processing() {
    recover_missing_operation_event(
        "\"kind\":\"operation-completion\"",
        DurableCommitCutV1::OperationOutcome,
        EventKind::OperationCompletion,
    );
}

#[test]
fn missing_join_event_is_replaced_before_source_continuation() {
    recover_missing_operation_event(
        "\"kind\":\"join\"",
        DurableCommitCutV1::Checkpoint,
        EventKind::Join,
    );
}

#[test]
fn missing_terminal_event_is_replaced_before_resume_returns() {
    recover_missing_operation_event(
        "\"kind\":\"terminal-execution\"",
        DurableCommitCutV1::TerminalCompletion,
        EventKind::TerminalExecution,
    );
}

/// Interrupts event commitment and requires its repair without another hook call.
#[test]
fn missing_foreground_event_is_replaced_before_resume_observation() {
    recover_missing_operation_event(
        "\"kind\":\"foreground-completion\"",
        DurableCommitCutV1::ForegroundCompletion,
        EventKind::ForegroundCompletion,
    );
}

#[test]
fn missing_task_completion_event_is_replaced_before_join_observation() {
    recover_missing_operation_event(
        "\"kind\":\"task-completion\"",
        DurableCommitCutV1::TaskSettlement,
        EventKind::TaskCompletion,
    );
}

#[test]
fn rejected_resume_preserves_prefix_when_lifecycle_repair_precedes_revision() {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"7"[..]),
        ))])],
    ));
    let interpreter = interpreter_with_delivery(
        executor.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let mut parent = FailingGraphJournalStore::new(executor.clone());
    parent.failure_cut = "\"kind\":\"terminal-execution\"";
    let parent = Arc::new(parent);
    parent.allow_release();
    let journal_id = JournalId::new("atomic-preacceptance-repair-revision")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, parent.clone(), journal_id.clone());
    for _ in 0..1_000 {
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
        if parent.release_count() > 0 {
            break;
        }
    }
    assert!(parent.failed.load(Ordering::Acquire));
    assert_eq!(parent.release_count(), 1);
    let prefix_before = block_on(parent.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix before resume: {error:?}"));

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v2","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [],
    ));
    let resumed = interpreter_with_identity_source(
        executor.clone(),
        integration.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
        Arc::new(DeterministicIdentitySource::new(
            (193_u8..=255).map(|byte| Ok([byte; 32])),
        )),
    );
    let storage = Arc::new(RejectExecutionStateStore::new(parent));
    let selection = selection();
    let mut resume = pin!(resumed.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(accepted.execution_id()),
            event_delivery: None,
        },
    ));
    let mut result = None;
    for _ in 0..1_000 {
        if let Poll::Ready(value) = resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            result = Some(value);
            break;
        }
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
    }
    assert!(
        matches!(result, Some(DurableResumeExecutionResult::Rejected(_))),
        "resume: {result:?}"
    );
    assert!(storage.rejected.load(Ordering::Acquire));
    assert_eq!(
        block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone()
        }))
        .unwrap_or_else(|error| panic!("prefix after rejection: {error:?}")),
        prefix_before
    );
    assert!(
        resumed
            .query_execution(accepted.execution_id())
            .unwrap_or_else(|error| panic!("rejected query: {error:?}"))
            .is_none()
    );
    assert!(resumed.test_task_supervisor_snapshot().tasks.is_empty());
    let Some(DurableResumeExecutionResult::Rejected(failure)) = result else {
        unreachable!("checked rejection")
    };
    assert!(failure.release_error.is_none(), "{failure:?}");

    // A new caller can acquire the released owner and atomically commit both bodies.
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v2","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [],
    ));
    let retry = interpreter_with_identity_source(
        executor.clone(),
        integration.clone(),
        integration.clone(),
        8,
        65_536,
        SinkPlan::default(),
        Arc::new(DeterministicIdentitySource::new(
            (193_u8..=255).map(|byte| Ok([byte; 32])),
        )),
    );
    let mut resume = pin!(retry.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(accepted.execution_id()),
            event_delivery: None,
        }
    ));
    let mut result = None;
    for _ in 0..1_000 {
        if let Poll::Ready(value) = resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            result = Some(value);
            break;
        }
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
    }
    let Some(DurableResumeExecutionResult::Accepted(retried)) = result else {
        panic!("corrected retry: {result:?}")
    };
    assert_eq!(retried.execution_id(), accepted.execution_id());
    assert!(integration.calls().iter().all(|call| !matches!(
        call.operation,
        EmbeddingOperation::CreateHook | EmbeddingOperation::DispatchOperation
    )));
    let after = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("retry prefix: {error:?}"));
    let (JournalPrefixV1::Full(before), JournalPrefixV1::Full(after)) = (&prefix_before, &after)
    else {
        panic!("expected full prefixes")
    };
    assert_eq!(
        &after.evidence[..before.evidence.len()],
        before.evidence.as_ref()
    );
    let appended = &after.evidence[before.evidence.len()..];
    assert_eq!(appended.len(), 2);
    let occurrence = DurableEventOccurrenceV1::decode(&appended[0].canonical_body)
        .unwrap_or_else(|error| panic!("repaired occurrence: {error:?}"));
    assert_eq!(occurrence.event().kind(), EventKind::TerminalExecution);
    assert_eq!(
        occurrence.causal_evidence_id(),
        before
            .evidence
            .last()
            .unwrap_or_else(|| panic!("empty fixture prefix"))
            .evidence_id
    );
    assert_eq!(appended[1].kind.as_ref(), "gantry.execution-state/v1");
    assert_eq!(appended[1].references.as_ref(), &[appended[0].evidence_id]);
    let program = Arc::new(
        DurableExecutionStartV3::retained_program(&after.evidence[0].canonical_body)
            .unwrap_or_else(|error| panic!("retained program: {error:?}")),
    );
    let recovered = recover_concurrent_authoritative_prefix(
        program.clone(),
        &JournalPrefixV1::Full(after.clone()),
    )
    .unwrap_or_else(|error| panic!("committed resume revision must recover: {error:?}"));
    assert_eq!(recovered.latest_sequence(), after.committed_through);
    assert_eq!(
        recovered
            .execution_state()
            .and_then(|state| state.action_mapping_revision()),
        Some("actions-v2")
    );
    let compacted = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, after)
        .unwrap_or_else(|error| panic!("revision compaction: {error:?}"));
    let snapshot = JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
        journal_id: after.journal_id.clone(),
        snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
        frontier: compacted.frontier(),
        canonical_snapshot: compacted.canonical_body().into(),
        retained_evidence: compacted.retained_evidence().clone(),
        suffix: Arc::from([]),
        committed_through: compacted.frontier(),
    });
    let compacted_recovery = recover_concurrent_authoritative_prefix(program, &snapshot)
        .unwrap_or_else(|error| panic!("compacted revision recovery: {error:?}"));
    assert_eq!(
        compacted_recovery.execution_state(),
        recovered.execution_state()
    );
    assert_eq!(
        compacted_recovery.latest_sequence(),
        recovered.latest_sequence()
    );
}

/// Interrupts event commitment and requires its repair without another hook call.
fn recover_missing_operation_event(
    failure_cut: &'static str,
    cut: DurableCommitCutV1,
    kind: EventKind,
) {
    recover_missing_operation_event_outcome(failure_cut, cut, kind, false);
}

#[test]
fn missing_failed_child_completion_retains_original_failure() {
    recover_missing_operation_event_outcome(
        "\"kind\":\"task-completion\"",
        DurableCommitCutV1::TaskSettlement,
        EventKind::TaskCompletion,
        true,
    );
}

#[test]
fn missing_failed_join_event_retains_member_failure_details() {
    recover_missing_operation_event_outcome(
        "\"kind\":\"join\"",
        DurableCommitCutV1::Checkpoint,
        EventKind::Join,
        true,
    );
}

/// Covers both successful and failed committed child settlements.
fn recover_missing_operation_event_outcome(
    failure_cut: &'static str,
    cut: DurableCommitCutV1,
    kind: EventKind,
    failed: bool,
) {
    let root = TempDirectory::new(
        "action read_only inspect() -> Int;\nfn main() { spawn child -> Int { action inspect() } discard join(child); }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(if failed {
            HookOutcomeV1::Declined(Arc::from("declined-child"))
        } else {
            HookOutcomeV1::Completed(Arc::from(&b"7"[..]))
        })])],
    ));
    let interpreter = interpreter_with_delivery(
        executor.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let mut store = FailingGraphJournalStore::new(executor.clone());
    store.failure_cut = failure_cut;
    let storage = Arc::new(store);
    storage.allow_release();
    let journal_id =
        JournalId::new("missing-result-event").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    for _ in 0..1_000 {
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
        if storage.release_count() > 0 {
            break;
        }
    }
    assert!(storage.failed.load(Ordering::Acquire));
    assert_eq!(storage.release_count(), 1);
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let (program, entries) = durable_graph_entries(&prefix);
    assert_eq!(entries.last().map(|(_, entry)| entry.cut()), Some(cut));
    let child = entries
        .iter()
        .find(|(_, entry)| entry.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, entry)| entry.task_id())
        .unwrap_or_else(|| panic!("child creation is absent"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("expected full prefix")
    };
    let cause = full
        .evidence
        .last()
        .unwrap_or_else(|| panic!("empty prefix"))
        .evidence_id;

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        if kind == EventKind::OperationDispatch {
            vec![ScriptedHook::created([Ok(HookOutcomeV1::Completed(
                Arc::from(&b"7"[..]),
            ))])]
        } else {
            vec![]
        },
    ));
    let resumed = interpreter_with_identity_source(
        executor.clone(),
        integration.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
        Arc::new(DeterministicIdentitySource::new(
            (193_u8..=255).map(|byte| Ok([byte; 32])),
        )),
    );
    // Pause after lifecycle acceptance, while graph installation is incomplete.
    // Registry consumers must wait rather than receive an inactive owner.
    let publication_observer = if kind == EventKind::OperationResult {
        let gate = Arc::new(gantry::DurableHandoffTestGate::default());
        resumed.install_durable_handoff_test_gate(gate.clone());
        let observer = resumed.clone();
        Some(std::thread::spawn(move || {
            let handle = gate.wait_until_accepted();
            let mut observation = pin!(observer.test_durable_observation(handle.execution_id()));
            let pending = observation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending();
            gate.release();
            pending
        }))
    } else {
        None
    };
    let selection = selection();
    let mut resume = pin!(resumed.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(accepted.execution_id()),
            event_delivery: None,
        }
    ));
    let mut result = None;
    for _ in 0..1_000 {
        if let Poll::Ready(value) = resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            result = Some(value);
            break;
        }
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
    }
    let Some(DurableResumeExecutionResult::Accepted(accepted)) = result else {
        panic!("resume: {result:?}")
    };
    let snapshot = drive_to_terminal(&executor, &resumed, accepted.handle());
    if failed {
        assert!(
            matches!(snapshot.foreground, Some(MachineOutcome::Failed(_))),
            "{snapshot:?}"
        );
    } else {
        assert!(
            matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(_))),
            "{snapshot:?}"
        );
    }
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("resumed prefix: {error:?}"));
    let recovered = recover_concurrent_authoritative_prefix(program, &prefix)
        .unwrap_or_else(|error| panic!("resumed recovery: {error:?}"));
    let event = recovered
        .events()
        .event_for_cause(cause)
        .unwrap_or_else(|| panic!("result was consumed without its event"));
    assert_eq!(event.occurrence().event().kind(), kind);
    assert_eq!(event.occurrence_sequence(), full.committed_through + 1);
    if failed && kind == EventKind::Join {
        let payload: serde_json::Value =
            serde_json::from_slice(event.occurrence().event().payload().canonical_bytes())
                .unwrap_or_else(|error| panic!("repaired join payload was not JSON: {error}"));
        assert_eq!(payload["settlement_status"], "failed");
        assert_eq!(
            payload["joined_task_ids"],
            serde_json::json!([child.to_string()])
        );
        let failures = payload["child_failures"]
            .as_array()
            .unwrap_or_else(|| panic!("repaired join payload has no child failures: {payload}"));
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["task_id"], child.to_string());
        assert_eq!(failures[0]["category"], "required-result-decline");
        assert_eq!(
            failures[0]["failure_reference"],
            format!("task:{child}:failure:required-result-decline")
        );
    }
    if let Some(observer) = publication_observer {
        assert!(
            observer
                .join()
                .unwrap_or_else(|_| panic!("publication observer panicked")),
            "recovered owner became visible before graph installation"
        );
    }
}

#[test]
fn missing_spawn_event_is_replaced_before_recovered_child_progress() {
    recover_missing_control_event(EventKind::Spawn);
}

#[test]
fn missing_detach_event_is_replaced_before_source_continuation() {
    recover_missing_control_event(EventKind::Detach);
}

#[test]
fn missing_cancellation_event_is_replaced_before_recovered_progress() {
    recover_missing_control_event(EventKind::Cancellation);
}

/// Reuses the source-control crash harness for creation and ownership events.
fn recover_missing_control_event(kind: EventKind) {
    let detach = kind == EventKind::Detach;
    let root = TempDirectory::new(if detach {
        "fn main() { spawn child -> Int { 7 } detach(child); }"
    } else {
        "fn main() { spawn child -> Int { 7 } discard join(child); }"
    });
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::EstablishSession,
                &br#"{"result":"established"}"#[..],
            ),
        ],
        [],
    ));
    let interpreter = interpreter_with_delivery(
        executor.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let mut store = FailingGraphJournalStore::new(executor.clone());
    store.failure_cut = match kind {
        EventKind::Detach => "\"kind\":\"detach\"",
        EventKind::Cancellation => "\"kind\":\"cancellation\"",
        _ => "\"kind\":\"spawn\"",
    };
    let storage = Arc::new(store);
    storage.allow_release();
    let journal_id =
        JournalId::new("missing-spawn-event").unwrap_or_else(|error| panic!("journal: {error:?}"));
    let accepted = durable_accepted(&interpreter, &root, storage.clone(), journal_id.clone());
    let reason = caller_cancellation_reason(Some(Arc::from("recovered-cancellation")), 64)
        .unwrap_or_else(|error| panic!("cancellation reason: {error:?}"));
    let mut cancellation =
        Box::pin(interpreter.cancel_execution(accepted.execution_id(), reason.clone()));
    if kind == EventKind::Cancellation {
        assert!(matches!(
            executor.poll_task(0),
            Ok(DeterministicTaskPoll::Pending)
        ));
        assert!(
            cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    for _ in 0..1_000 {
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
        if storage.release_count() > 0 {
            break;
        }
    }
    assert!(storage.failed.load(Ordering::Acquire));
    assert_eq!(storage.release_count(), 1);
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let (program, entries) = durable_graph_entries(&prefix);
    let child = entries
        .iter()
        .find(|(_, entry)| entry.cut() == DurableCommitCutV1::TaskCreation)
        .map(|(_, entry)| entry.task_id())
        .unwrap_or_else(|| panic!("no child creation"));
    let JournalPrefixV1::Full(full) = &prefix else {
        panic!("expected full prefix")
    };
    let cause = full
        .evidence
        .last()
        .unwrap_or_else(|| panic!("empty prefix"))
        .evidence_id;
    let before = recover_concurrent_authoritative_prefix(program.clone(), &prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert!(before.events().event_for_cause(cause).is_none());

    if kind == EventKind::Spawn {
        for submission in [None, Some(1), Some(2), Some(3)] {
            assert_recovered_submission_rollback(
                storage.clone(),
                &journal_id,
                accepted.execution_id(),
                &prefix,
                submission,
            );
        }
    }

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let resumed = interpreter_with_delivery(
        executor.clone(),
        integration,
        8,
        65_536,
        SinkPlan::default(),
    );
    let selection = selection();
    let mut resume = pin!(resumed.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(accepted.execution_id()),
            event_delivery: None,
        }
    ));
    let mut result = None;
    for _ in 0..1_000 {
        if let Poll::Ready(value) = resume
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            result = Some(value);
            break;
        }
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
    }
    let Some(DurableResumeExecutionResult::Accepted(accepted)) = result else {
        panic!("resume: {result:?}")
    };
    let snapshot = drive_to_terminal(&executor, &resumed, accepted.handle());
    if kind == EventKind::Cancellation {
        assert_eq!(snapshot.cancellation, Some(reason));
        assert!(
            matches!(snapshot.foreground, Some(MachineOutcome::Cancelled(_))),
            "{snapshot:?}"
        );
    } else {
        assert!(
            matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(_))),
            "{snapshot:?}"
        );
    }
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("resumed prefix: {error:?}"));
    let recovered = recover_concurrent_authoritative_prefix(program.clone(), &prefix)
        .unwrap_or_else(|error| panic!("resumed recovery: {error:?}"));
    let event = recovered
        .events()
        .event_for_cause(cause)
        .unwrap_or_else(|| panic!("committed child {child} has no replacement spawn event"));
    assert_eq!(event.occurrence().event().kind(), kind);
    assert_eq!(event.occurrence_sequence(), full.committed_through + 1);
    let JournalPrefixV1::Full(after) = &prefix else {
        panic!("expected full resumed prefix")
    };
    if kind == EventKind::Cancellation {
        for task in [recovered.execution().foreground().task_id(), child] {
            let target_events = recovered
                .events()
                .events()
                .values()
                .filter(|record| {
                    let event = record.occurrence().event();
                    event.kind() == EventKind::Cancellation
                        && event.task_id() == Some(task)
                        && std::str::from_utf8(event.payload().canonical_bytes())
                            .is_ok_and(|payload| payload.contains("\"target_kind\":\"task\""))
                })
                .count();
            assert_eq!(
                target_events, 1,
                "missing task-target cancellation for {task}"
            );
        }
    }
    let resolution = after
        .evidence
        .iter()
        .find(|entry| {
            entry.sequence > full.committed_through
                && matches!(
                    entry.kind.as_ref(),
                    CONCURRENT_DURABLE_EVIDENCE_KIND_V4 | CONCURRENT_DURABLE_EVIDENCE_KIND_V5
                )
        })
        .unwrap_or_else(|| panic!("missing submission resolution"));
    assert!(event.occurrence_sequence() < resolution.sequence);
    let snapshot = ConcurrentDurableRecoverySnapshotV1::from_full_prefix(&program, after)
        .unwrap_or_else(|error| panic!("compaction: {error:?}"));
    let compacted = recover_concurrent_authoritative_prefix(
        program,
        &JournalPrefixV1::Snapshot(SnapshotJournalPrefixV1 {
            journal_id: after.journal_id.clone(),
            snapshot_version: CONCURRENT_DURABLE_SNAPSHOT_VERSION_V1,
            frontier: snapshot.frontier(),
            canonical_snapshot: Arc::from(snapshot.canonical_body()),
            retained_evidence: snapshot.retained_evidence().clone(),
            suffix: Arc::from([]),
            committed_through: snapshot.frontier(),
        }),
    )
    .unwrap_or_else(|error| panic!("compacted recovery: {error:?}"));
    assert_eq!(
        compacted.task_creation_cause(child),
        before.task_creation_cause(child)
    );
    assert_eq!(compacted.events().event_for_cause(cause), Some(event));
}
