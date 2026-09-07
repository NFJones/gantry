//! Public crash-cut recovery regressions using the source-task fixture services.

use super::*;

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
fn recover_missing_operation_event(
    failure_cut: &'static str,
    cut: DurableCommitCutV1,
    kind: EventKind,
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
    assert!(
        matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(_))),
        "{snapshot:?}"
    );
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
}

#[test]
fn missing_spawn_event_is_replaced_before_recovered_child_progress() {
    recover_missing_control_event(false);
}

#[test]
fn missing_detach_event_is_replaced_before_source_continuation() {
    recover_missing_control_event(true);
}

/// Reuses the source-control crash harness for creation and ownership events.
fn recover_missing_control_event(detach: bool) {
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
    store.failure_cut = if detach {
        "\"kind\":\"detach\""
    } else {
        "\"kind\":\"spawn\""
    };
    let storage = Arc::new(store);
    storage.allow_release();
    let journal_id =
        JournalId::new("missing-spawn-event").unwrap_or_else(|error| panic!("journal: {error:?}"));
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
    assert!(
        matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(_))),
        "{snapshot:?}"
    );
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("resumed prefix: {error:?}"));
    let recovered = recover_concurrent_authoritative_prefix(program.clone(), &prefix)
        .unwrap_or_else(|error| panic!("resumed recovery: {error:?}"));
    let event = recovered
        .events()
        .event_for_cause(cause)
        .unwrap_or_else(|| panic!("committed child {child} has no replacement spawn event"));
    assert_eq!(
        event.occurrence().event().kind(),
        if detach {
            EventKind::Detach
        } else {
            EventKind::Spawn
        }
    );
    assert_eq!(event.occurrence_sequence(), full.committed_through + 1);
    let JournalPrefixV1::Full(after) = &prefix else {
        panic!("expected full resumed prefix")
    };
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
