//! Shutdown composition over retained terminal fake-host resource ownership.

use super::resource_cleanup::{CleanupValue, resource_machine};
use super::*;
use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CanonicalPath, DisclosureCharge, FailureClass, LivenessRoot, OperationAbi, OperationKind,
    OwnerGeneration, ReceiverOwnership, ResourceCarrier, ResourceLedger, ResourceState,
};

/// Terminal language settlement must not hide physical cleanup from interpreter shutdown.
#[test]
fn shutdown_drains_terminal_resource_ownership_before_closing_blocking_service() {
    for (fails, remains_active, physical, pending) in [
        (false, false, true, false),
        (true, false, true, false),
        (false, true, true, false),
        (false, true, false, false),
        (false, false, false, true),
    ] {
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
        let drops = Arc::new(AtomicU64::new(0));
        if physical {
            coordinator
                .attach_resource_host_value(
                    &subject,
                    owner,
                    CleanupValue {
                        drops: Arc::clone(&drops),
                        fails,
                        pause: None,
                    },
                )
                .unwrap_or_else(|_| panic!("attachment"));
        }
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
        if !remains_active {
            coordinator
                .settle_resource_from_post_failure(&failure, 21, &subject)
                .unwrap_or_else(|error| panic!("release: {error:?}"));
        }
        if !pending {
            assert!(machine.cancel("fixture operation settlement").is_some());
            assert!(matches!(
                machine.step(),
                gantry::runtime::MachineStep::Transition(_)
            ));
        }
        let before_records = coordinator
            .snapshot()
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .to_vec();
        let before = drive_to_terminal(&executor, &interpreter, accepted.handle());
        assert_eq!(drops.load(Ordering::Acquire), 0);
        let mut shutdown = Box::pin(interpreter.shutdown());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut released_timer = false;
        let report = loop {
            if let Poll::Ready(result) = shutdown
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                break result.unwrap_or_else(|error| panic!("shutdown: {error:?}"));
            }
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown did not settle"
            );
            for id in executor.task_ids() {
                if executor.is_runnable(id) {
                    let _ = executor
                        .poll_task(id)
                        .unwrap_or_else(|error| panic!("task {id}: {error:?}"));
                }
            }
            if remains_active && !released_timer && !executor.sleep_durations().is_empty() {
                executor
                    .release_sleep(executor.sleep_durations().len() - 1)
                    .unwrap_or_else(|error| panic!("quiescence deadline: {error:?}"));
                released_timer = true;
            }
            std::thread::yield_now();
        };
        assert_eq!(
            drops.load(Ordering::Acquire),
            u64::from(physical && !remains_active),
            "shutdown must drain terminal resource ownership"
        );
        assert_eq!(report.orderly, !fails && !remains_active && !pending);
        let after = accepted
            .handle()
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot: {error:?}"));
        assert_eq!(after.foreground, before.foreground);
        assert_eq!(after.terminal, before.terminal);
        assert_eq!(after.cancellation, before.cancellation);
        assert_eq!(
            after.resource_cleanup_failure,
            if remains_active && physical {
                Some(gantry::runtime::ExecutionResourceCleanupFailure::Deadline)
            } else if remains_active {
                Some(gantry::runtime::ExecutionResourceCleanupFailure::UnsettledAccounting)
            } else if pending {
                Some(gantry::runtime::ExecutionResourceCleanupFailure::PendingResourceWork)
            } else {
                fails.then_some(gantry::runtime::ExecutionResourceCleanupFailure::Disposal)
            }
        );
        assert_eq!(
            coordinator.snapshot().resource_records(),
            Some(before_records.as_slice())
        );
        if remains_active {
            coordinator
                .settle_resource_from_post_failure(&failure, 21, &subject)
                .unwrap_or_else(|error| panic!("explicit late release: {error:?}"));
            coordinator
                .dispose_settled_resource_host_values()
                .unwrap_or_else(|error| panic!("explicit late disposal: {error:?}"));
            assert_eq!(drops.load(Ordering::Acquire), u64::from(physical));
        }
        assert_eq!(coordinator.has_pending_resource_operations(), pending);
        if pending {
            assert!(
                machine
                    .cancel("explicit late operation settlement")
                    .is_some()
            );
            assert!(matches!(
                machine.step(),
                gantry::runtime::MachineStep::Transition(_)
            ));
            assert!(!coordinator.has_pending_resource_operations());
            assert_eq!(
                coordinator.snapshot().resource_records(),
                Some(before_records.as_slice())
            );
        }
    }
}
