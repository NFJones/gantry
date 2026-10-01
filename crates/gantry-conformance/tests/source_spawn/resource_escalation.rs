//! Confirmed hard-cancellation composition over explicit fake-host resource ownership.
//!
//! These fixtures exercise execution cleanup, not source live-handle transport or recovery.

use super::resource_cleanup::{CleanupTimerFailureExecutor, CleanupValue, resource_machine};
use super::*;
use gantry::ir::{
    LivenessRoot, OwnerGeneration, ResourceCarrier, ResourceLedger, ResourceLifetimeState,
    ResourceState,
};

/// A real grace timeout followed by confirmed stop releases accounting and physical ownership.
#[test]
fn confirmed_hard_cancellation_releases_task_resources() {
    for (timer_fails, abort_fails, pending_work) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let root = TempDirectory::new("fn main() {}");
        let executor = Arc::new(DeterministicConcurrentExecutor::default());
        executor.control_sleeps();
        let fail_timer = Arc::new(AtomicBool::new(false));
        let adapter: Arc<dyn ExecutorAdapter> = Arc::new(CleanupTimerFailureExecutor {
            inner: Arc::clone(&executor),
            fail: Arc::clone(&fail_timer),
        });
        let integration = Arc::new(ScriptedIntegration::new(
            [ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            )],
            [],
        ));
        let identities: Arc<dyn IdentitySource> = Arc::new(DeterministicIdentitySource::new(
            (1_u8..=192).map(|byte| Ok([byte; 32])),
        ));
        let interpreter = interpreter_with_accounting_policy(
            adapter,
            integration.clone(),
            integration,
            AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
                .unwrap_or_else(|error| panic!("capacities: {error}")),
            8,
            SinkPlan::default(),
            identities,
            Some((2, 2)),
        );
        let accepted = accepted(&interpreter, &root);
        let execution = accepted.execution_id();
        let coordinator = interpreter
            .test_nondurable_resource_coordinator(execution)
            .unwrap_or_else(|| panic!("resource owner"));
        let mut machine = resource_machine(execution);
        let subject = machine
            .pending_resource_subject()
            .unwrap_or_else(|| panic!("subject"));
        let owner = OwnerGeneration::new(4);
        let record =
            ResourceLedger::new(owner, ResourceState::Usable, &[LivenessRoot::Resource], &[])
                .unwrap_or_else(|error| panic!("record: {error:?}"));
        coordinator
            .admit_resource(
                &machine,
                ResourceCarrier::ReconstructionRecord,
                record.durable_record(),
            )
            .unwrap_or_else(|error| panic!("admission: {error:?}"));
        let drops = Arc::new(AtomicU64::new(0));
        coordinator
            .attach_resource_host_value(
                &subject,
                owner,
                CleanupValue {
                    drops: Arc::clone(&drops),
                    fails: false,
                    pause: None,
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
        if !pending_work {
            assert!(machine.cancel("settle fixture operation").is_some());
            let _ = machine.step();
        }
        let before_records = coordinator
            .snapshot()
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .to_vec();
        let reason = caller_cancellation_reason(None, 64)
            .unwrap_or_else(|error| panic!("reason: {error:?}"));
        let mut cancellation = Box::pin(interpreter.cancel_execution(execution, reason));
        assert!(
            cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let root_driver = executor.task_ids()[0];
        let control = *executor
            .task_ids()
            .last()
            .unwrap_or_else(|| panic!("control task"));
        let _ = executor
            .poll_task(control)
            .unwrap_or_else(|error| panic!("control: {error:?}"));
        // The root is deliberately never polled: only the timer and confirmed abort may settle it.
        assert_eq!(executor.sleep_durations().len(), 1);
        fail_timer.store(timer_fails, Ordering::Release);
        if abort_fails {
            executor
                .fail_abort(root_driver)
                .unwrap_or_else(|error| panic!("abort fixture: {error:?}"));
        }
        executor
            .release_sleep(0)
            .unwrap_or_else(|error| panic!("grace: {error:?}"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let result = loop {
            if let Poll::Ready(result) = cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                break result;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "hard cancellation did not settle"
            );
            for id in executor.task_ids() {
                if id != root_driver && executor.is_runnable(id) {
                    let _ = executor
                        .poll_task(id)
                        .unwrap_or_else(|error| panic!("task {id}: {error:?}"));
                }
            }
            std::thread::yield_now();
        };
        if timer_fails || abort_fails {
            assert!(
                matches!(result, Err(gantry::CancelExecutionError::Executor(_))),
                "cleanup: {result:?}"
            );
            assert_eq!(drops.load(Ordering::Acquire), 0);
            assert_eq!(
                coordinator.snapshot().resource_records(),
                Some(before_records.as_slice())
            );
            coordinator
                .begin_resource_finish(&subject, owner)
                .unwrap_or_else(|error| panic!("explicit finish: {error:?}"));
            coordinator
                .dispose_resource_host_value(&subject, owner)
                .unwrap_or_else(|error| panic!("explicit disposal: {error:?}"));
            coordinator
                .complete_resource_finalization(&subject, owner, 21)
                .unwrap_or_else(|error| panic!("explicit finalization: {error:?}"));
            if abort_fails {
                let _ = executor.poll_task(root_driver);
            }
            continue;
        }
        if pending_work {
            assert!(
                matches!(
                    result,
                    Err(gantry::CancelExecutionError::ResourceObligations(
                        gantry::runtime::ExecutionResourceCleanupFailure::PendingResourceWork
                    ))
                ),
                "cleanup: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Ok(CancellationRecord::Accepted { .. })),
                "cleanup: {result:?}"
            );
        }
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(
            coordinator
                .snapshot()
                .resource_records()
                .unwrap_or_else(|| panic!("records"))[0]
                .record()
                .lifetime(),
            ResourceLifetimeState::EmergencyReleased
        );
        assert_eq!(coordinator.has_pending_resource_operations(), pending_work);
        assert_eq!(
            accepted
                .handle()
                .snapshot()
                .unwrap_or_else(|error| panic!("snapshot: {error:?}"))
                .resource_cleanup_failure,
            pending_work
                .then_some(gantry::runtime::ExecutionResourceCleanupFailure::PendingResourceWork)
        );
        if pending_work {
            assert!(
                machine
                    .cancel("explicit external work settlement")
                    .is_some()
            );
            let _ = machine.step();
            assert!(!coordinator.has_pending_resource_operations());
        }
    }
}
