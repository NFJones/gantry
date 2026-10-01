//! Cancellation completion checks over accounting-only fake-host obligations.
//!
//! These fixtures do not qualify source live-handle transport or journal recovery.

use super::resource_cleanup::resource_machine;
use super::*;
use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CanonicalPath, DisclosureCharge, FailureClass, LivenessRoot, OperationAbi, OperationKind,
    OwnerGeneration, ReceiverOwnership, ResourceCarrier, ResourceLedger, ResourceState,
};

/// Physical absence cannot discharge semantic accounting or accepted pending work.
#[test]
fn cancellation_refuses_unsettled_resource_obligations_without_physical_slots() {
    for (active, already_terminal) in [(true, false), (false, false), (true, true), (false, true)] {
        let root = TempDirectory::new("fn main() {}");
        let executor = Arc::new(DeterministicConcurrentExecutor::default());
        executor.control_sleeps();
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
            executor.clone(),
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
        let abi = OperationAbi::new(
            OperationKind::LiveResource,
            &CanonicalPath::new("crate::cleanup_resource")
                .unwrap_or_else(|error| panic!("path: {error}")),
            subject.site(),
            0,
            RecoveryClass::Idempotent,
            ReceiverOwnership::RetainedByCaller,
        )
        .unwrap_or_else(|error| panic!("abi: {error:?}"));
        let mut live = abi
            .open_live(
                owner,
                OperationAbi::observation_allowance(
                    1,
                    DisclosureCharge::new(1).unwrap_or_else(|| panic!("nonzero charge")),
                ),
            )
            .unwrap_or_else(|error| panic!("live: {error:?}"));
        let failure = live
            .settle_failure(FailureClass::ResourceFailure)
            .unwrap_or_else(|error| panic!("failure: {error:?}"));
        if active {
            assert!(machine.cancel("settle fixture operation").is_some());
            let _ = machine.step();
        } else {
            coordinator
                .settle_resource_from_post_failure(&failure, 21, &subject)
                .unwrap_or_else(|error| panic!("account release: {error:?}"));
        }
        let before = coordinator
            .snapshot()
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .to_vec();
        let terminal_before =
            already_terminal.then(|| drive_to_terminal(&executor, &interpreter, accepted.handle()));
        let reason = caller_cancellation_reason(Some(Arc::from("resource obligations")), 64)
            .unwrap_or_else(|error| panic!("reason: {error:?}"));
        let mut cancellation = Box::pin(interpreter.cancel_execution(execution, reason));
        assert!(
            cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let control = *executor
            .task_ids()
            .last()
            .unwrap_or_else(|| panic!("control task"));
        let _ = executor
            .poll_task(control)
            .unwrap_or_else(|error| panic!("control: {error:?}"));
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
                "cancellation did not settle"
            );
            for id in executor.task_ids() {
                if executor.is_runnable(id) {
                    let _ = executor
                        .poll_task(id)
                        .unwrap_or_else(|error| panic!("task {id}: {error:?}"));
                }
            }
            std::thread::yield_now();
        };
        let classification = if active {
            gantry::runtime::ExecutionResourceCleanupFailure::UnsettledAccounting
        } else {
            gantry::runtime::ExecutionResourceCleanupFailure::PendingResourceWork
        };
        assert!(
            matches!(result, Err(gantry::CancelExecutionError::ResourceObligations(found))
            if found == classification),
            "physical absence cannot authorize complete resource cleanup"
        );
        let snapshot = accepted
            .handle()
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error:?}"));
        assert_eq!(
            snapshot.resource_cleanup_failure,
            Some(if active {
                gantry::runtime::ExecutionResourceCleanupFailure::UnsettledAccounting
            } else {
                gantry::runtime::ExecutionResourceCleanupFailure::PendingResourceWork
            })
        );
        assert_eq!(
            coordinator.snapshot().resource_records(),
            Some(before.as_slice())
        );
        if let Some(prior) = terminal_before {
            assert_eq!(snapshot.foreground, prior.foreground);
            assert_eq!(snapshot.terminal, prior.terminal);
            assert_eq!(snapshot.cancellation, prior.cancellation);
        }
        if active {
            coordinator
                .settle_resource_from_post_failure(&failure, 21, &subject)
                .unwrap_or_else(|error| panic!("explicit late account release: {error:?}"));
        } else {
            assert!(machine.cancel("explicit late work settlement").is_some());
            let _ = machine.step();
        }
        assert!(!coordinator.has_unsettled_resource_accounts());
        assert!(!coordinator.has_pending_resource_operations());
    }
}
