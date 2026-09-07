//! Recovered graph admission rollback through the public facade.

use super::*;

/// Rejects capacity or a selected submission after preflight owns the resume.
pub(super) fn assert_recovered_submission_rollback(
    storage: Arc<dyn JournalStorage>,
    journal_id: &JournalId,
    execution_id: ProtocolIdentity,
    prefix: &JournalPrefixV1,
    submission: Option<u64>,
) {
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    if let Some(submission) = submission {
        executor.fail_spawn_number(submission);
    }
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveSessions,
            &br#"{"result":"resolved"}"#[..],
        )],
        [],
    ));
    let capacities = AsyncCapacityLimits::new(
        8,
        8,
        if submission.is_some() { 8 } else { 1 },
        8,
        8,
        8,
        8,
        8,
        8,
    )
    .unwrap_or_else(|error| panic!("capacity: {error:?}"));
    let interpreter = interpreter_with_capacity_limits(
        executor.clone(),
        integration.clone(),
        integration.clone(),
        capacities,
        65_536,
        SinkPlan::default(),
        Arc::new(DeterministicIdentitySource::new(
            (193_u8..=255).map(|byte| Ok([byte; 32])),
        )),
    );
    let selection = selection();
    let mut resume = pin!(interpreter.resume_durable_execution(
        storage.clone(),
        DurableResumeExecutionRequest {
            journal_id: journal_id.clone(),
            protocol_selection: &selection,
            candidate_package_root: None,
            expected_execution_id: Some(execution_id),
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
    let Some(DurableResumeExecutionResult::Rejected(failure)) = result else {
        panic!("admission {submission:?} was not rejected: {result:?}");
    };
    if submission.is_none() {
        assert_eq!(failure.code.as_ref(), "resume-runnable-task-capacity");
        assert_eq!(
            executor.task_ids(),
            [0],
            "capacity rejection submitted a replacement driver"
        );
    }
    assert!(failure.release_error.is_none(), "{failure:?}");
    assert!(
        interpreter
            .query_execution(execution_id)
            .unwrap_or_else(|error| panic!("query: {error:?}"))
            .is_none()
    );
    assert!(interpreter.test_task_supervisor_snapshot().tasks.is_empty());
    assert!(integration.calls().iter().all(|call| !matches!(
        call.operation,
        EmbeddingOperation::CreateHook
            | EmbeddingOperation::DispatchOperation
            | EmbeddingOperation::EstablishSession
    )));
    assert_eq!(
        &block_on(storage.read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone()
        }))
        .unwrap_or_else(|error| panic!("prefix: {error:?}")),
        prefix
    );
    let owner = block_on(storage.acquire_owner(AcquireJournalOwnerV1 {
        journal_id: journal_id.clone(),
        operation: gantry::host::journal::JournalOwnerOperationV1::Resume,
    }))
    .unwrap_or_else(|error| panic!("rollback retained owner: {error:?}"));
    block_on(storage.release_owner(ReleaseJournalOwnerV1 {
        journal_id: journal_id.clone(),
        ownership_token: owner.token,
    }))
    .unwrap_or_else(|error| panic!("release: {error:?}"));
}
