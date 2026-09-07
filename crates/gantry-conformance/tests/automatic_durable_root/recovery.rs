//! Serial crash-cut recovery through the public facade.

use super::*;

#[test]
fn committed_serial_outcome_resumes_without_hook_and_repairs_completion() {
    recover_serial_outcome(false);
}

#[test]
fn serial_completion_retains_outcome_cause_across_resume_revision() {
    recover_serial_outcome(true);
}

/// A policy record may advance the journal tip without replacing the outcome cause.
fn recover_serial_outcome(revise_mapping: bool) {
    let root = TempDirectory::new(
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(7) }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let initial = interpreter_with_integration(executor.clone(), integration);
    let mut store = ObservedJournalStore::with_post_commit_settlement_gate(1);
    store.outcome_gate = true;
    let storage = Arc::new(store);
    let journal_id = JournalId::new("serial-outcome-recovery")
        .unwrap_or_else(|error| panic!("journal: {error:?}"));
    let selection = selection();
    let DurableStartExecutionResult::Accepted(started) = block_on(initial.start_durable_execution(
        storage.clone(),
        DurableStartExecutionRequest {
            journal_id: journal_id.clone(),
            start: StartExecutionRequest {
                package_root: &root.0,
                protocol_selection: &selection,
                required_peers: &[],
                entry_input: None,
                root_session: None,
                event_delivery: None,
            },
        },
    )) else {
        panic!("initial start rejected")
    };
    let root_task = *executor
        .task_ids()
        .last()
        .unwrap_or_else(|| panic!("no root"));
    poll_task_until(&executor, root_task, || {
        storage.post_commit_settlement_started()
    });
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert_eq!(recovered.latest_cut(), DurableCommitCutV1::OperationOutcome);
    let cause = recovered.latest_evidence_id();
    let sequence = recovered.latest_sequence();
    assert!(recovered.events().event_for_cause(cause).is_none());
    executor
        .fail_task(root_task)
        .unwrap_or_else(|error| panic!("crash: {error:?}"));
    storage.release_post_commit_settlement();
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: started.test_ownership_token().clone(),
    }))
    .unwrap_or_else(|error| panic!("release: {error:?}"));

    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveMappings,
                if revise_mapping {
                    &br#"{"action_mapping_revision":"actions-v2","result":"resolved"}"#[..]
                } else {
                    &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..]
                },
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [],
    ));
    let resumed =
        interpreter_with_integration_and_identity_start(executor.clone(), integration.clone(), 97);
    let mut resume = pin!(resumed.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(started.execution_id()),
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
    for _ in 0..1_000 {
        for task in executor.task_ids() {
            if executor.is_runnable(task) {
                let _ = executor.poll_task(task);
            }
        }
    }
    let snapshot = resumed
        .query_execution(accepted.execution_id())
        .unwrap_or_else(|error| panic!("query: {error:?}"))
        .unwrap_or_else(|| panic!("missing execution"));
    assert!(
        matches!(snapshot.foreground, Some(MachineOutcome::Succeeded(ref value))
        if matches!(value.view(), LogicalValueView::String("done"))),
        "{snapshot:?}"
    );
    assert!(integration.calls().iter().all(|call| !matches!(
        call.operation,
        EmbeddingOperation::CreateHook | EmbeddingOperation::DispatchOperation
    )));
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("final prefix: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("final recovery: {error:?}"));
    let event = recovered
        .events()
        .event_for_cause(cause)
        .unwrap_or_else(|| panic!("missing completion"));
    assert_eq!(
        event.occurrence().event().kind(),
        EventKind::OperationCompletion
    );
    assert_eq!(
        event.occurrence_sequence(),
        sequence + 1 + u64::from(revise_mapping)
    );
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
}
