//! Public crash-cut recovery regressions using the source-task fixture services.

use super::*;

#[test]
fn missing_spawn_event_is_replaced_before_recovered_child_progress() {
    let root = TempDirectory::new("fn main() { spawn child -> Int { 7 } discard join(child); }");
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
    store.failure_cut = "\"kind\":\"spawn\"";
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
    assert_eq!(event.occurrence().event().kind(), EventKind::Spawn);
    assert_eq!(event.occurrence_sequence(), full.committed_through + 1);
    let JournalPrefixV1::Full(after) = &prefix else {
        panic!("expected full resumed prefix")
    };
    let resolution = after
        .evidence
        .iter()
        .find(|entry| {
            entry.sequence > full.committed_through
                && entry.kind.as_ref() == CONCURRENT_DURABLE_EVIDENCE_KIND_V5
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
    assert_eq!(compacted.task_creation_cause(child), Some(cause));
    assert_eq!(compacted.events().event_for_cause(cause), Some(event));
}
