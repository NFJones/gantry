//! Public cancellation composition over explicitly admitted fake-host accounting.
//!
//! The fake machine authenticates only fixture metadata; these tests do not qualify source
//! live-handle transport. Semantic resource release is explicit before cancellation cleanup.

use super::*;
use gantry::ir::generated::{OperationSiteKind, RecoveryClass};
use gantry::ir::{
    CanonicalPath, CanonicalSignature, DisclosureCharge, EffectSet, ExecutableAction,
    ExecutableOperation, FailureClass, Instruction, InstructionKind, LivenessRoot, MachineProgram,
    OperationAbi, OperationKind, OwnerGeneration, ReceiverOwnership, ResourceCarrier,
    ResourceLedger, ResourceState, StructuralPosition, TypeDescriptor, Workflow,
};
use gantry::runtime::{HostResourceError, Machine, MachineLabel, MachineLimits, MachineStep};

/// Delegates scheduling while injecting a failure into a registered cleanup timer.
struct CleanupTimerFailureExecutor {
    inner: Arc<DeterministicConcurrentExecutor>,
    fail: Arc<AtomicBool>,
}

impl ExecutorAdapter for CleanupTimerFailureExecutor {
    fn spawn(&self, task: OwnedTaskFuture) -> Result<Box<dyn SubmittedTask>, HostError> {
        self.inner.spawn(task)
    }

    fn sleep(&self, duration: DurationMicros) -> HostFuture<'_, Result<(), HostError>> {
        let mut timer = self.inner.sleep(duration);
        Box::pin(std::future::poll_fn(move |context| {
            if self.fail.load(Ordering::Acquire) {
                Poll::Ready(Err(HostError {
                    code: Arc::from("cleanup-timer-failure"),
                    protected_diagnostic: None,
                }))
            } else {
                timer.as_mut().poll(context)
            }
        }))
    }

    fn yield_now(&self) -> HostFuture<'_, Result<(), HostError>> {
        self.inner.yield_now()
    }

    fn sample_inclusive(&self, range: InclusiveJitterRange) -> Result<u64, HostError> {
        self.inner.sample_inclusive(range)
    }
}

/// Delegates ordinary package work but can refuse the later cleanup submission.
struct RefusingCleanupService {
    inner: gantry::runtime::BoundedBlockingWorkService,
    refuse: Arc<AtomicBool>,
}

impl gantry::host::contracts::BlockingWorkService for RefusingCleanupService {
    fn capacities(&self) -> gantry::host::contracts::BlockingWorkCapacities {
        self.inner.capacities()
    }

    fn submit(
        &self,
        job: gantry::host::contracts::OwnedBlockingJob,
    ) -> Result<
        Arc<dyn gantry::host::contracts::SubmittedBlockingJob>,
        gantry::host::contracts::BlockingWorkSubmitError,
    > {
        if self.refuse.load(Ordering::Acquire) {
            return Err(gantry::host::contracts::BlockingWorkSubmitError::CapacityExhausted);
        }
        self.inner.submit(job)
    }

    fn shutdown(&self) -> HostFuture<'_, Result<(), HostError>> {
        self.inner.shutdown()
    }
}

/// Counts physical disposal and optionally fails within the integration containment boundary.
struct CleanupValue {
    drops: Arc<AtomicU64>,
    fails: bool,
    pause: Option<(Arc<AtomicBool>, std::sync::mpsc::Receiver<()>)>,
}

impl Drop for CleanupValue {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        if let Some((entered, release)) = &self.pause {
            entered.store(true, Ordering::Release);
            let _ = release.recv_timeout(std::time::Duration::from_secs(5));
        }
        assert!(!self.fails, "protected fake destructor failure");
    }
}

/// Builds a pending fake-host resource operation belonging to the accepted execution root.
fn resource_machine(execution: ProtocolIdentity) -> Machine {
    let path = CanonicalPath::new("crate::cleanup_resource")
        .unwrap_or_else(|error| panic!("path: {error}"));
    let workflow =
        CanonicalPath::new("crate::main").unwrap_or_else(|error| panic!("workflow: {error}"));
    let operation = ExecutableOperation {
        kind: OperationSiteKind::Action,
        section20_kind: Some(OperationKind::LiveResource),
        result_type: TypeDescriptor::UNIT,
        action: Some(ExecutableAction {
            signature: CanonicalSignature::action(
                RecoveryClass::Idempotent,
                &path,
                &[],
                &TypeDescriptor::UNIT,
            ),
            path,
            recovery: RecoveryClass::Idempotent,
            parameters: Vec::new(),
        }),
        template_segments: Vec::new(),
        interpolation_types: Vec::new(),
        named_input_names: Vec::new(),
        named_input_types: Vec::new(),
        retry_limit: None,
        session_mode: None,
        attempted: false,
    };
    let program = Arc::new(
        MachineProgram::new(vec![Workflow {
            path: workflow.clone(),
            parameters: Vec::new(),
            result: TypeDescriptor::UNIT,
            effects: EffectSet::default(),
            instructions: vec![Instruction {
                site: StructuralPosition::new(vec![45])
                    .unwrap_or_else(|error| panic!("site: {error}")),
                ty: TypeDescriptor::UNIT,
                kind: InstructionKind::OperationCall {
                    operation,
                    operands: 0,
                },
            }],
        }])
        .unwrap_or_else(|error| panic!("program: {error:?}")),
    );
    let mut machine = Machine::new(
        program,
        &workflow,
        Vec::new(),
        execution,
        MachineLimits::new(8, 1, 1, 1, 8, DEFAULT_VALUE_LIMITS)
            .unwrap_or_else(|| panic!("positive limits")),
    )
    .unwrap_or_else(|error| panic!("machine: {error:?}"));
    assert!(matches!(
        machine.step(),
        MachineStep::Transition(MachineLabel::OperationPrepared(_))
    ));
    machine
}

/// Cancellation drains already-released fake-host values and reports disposal failures separately.
#[test]
fn public_cancellation_drains_settled_physical_resources_before_quiescence() {
    for (fails, times_out, remains_active, service_refuses, executor_fails, already_terminal) in [
        (false, false, false, false, false, false),
        (true, false, false, false, false, false),
        (false, true, false, false, false, false),
        (false, true, true, false, false, false),
        (false, false, false, true, false, false),
        (false, true, true, false, true, false),
        (false, false, false, false, false, true),
        (true, false, false, false, false, true),
    ] {
        let root = TempDirectory::new("fn main() {}");
        let executor = Arc::new(DeterministicConcurrentExecutor::default());
        executor.control_sleeps();
        let fail_timer = Arc::new(AtomicBool::new(false));
        let executor_adapter: Arc<dyn ExecutorAdapter> = Arc::new(CleanupTimerFailureExecutor {
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
        let refuse = Arc::new(AtomicBool::new(false));
        let service = service_refuses.then(|| {
            Box::new(RefusingCleanupService {
                inner: gantry::runtime::BoundedBlockingWorkService::new(8, 8)
                    .unwrap_or_else(|error| panic!("cleanup service: {error:?}")),
                refuse: Arc::clone(&refuse),
            }) as Box<dyn gantry::host::contracts::BlockingWorkService>
        });
        let interpreter = interpreter_with_accounting_service(
            executor_adapter,
            integration.clone(),
            integration,
            AsyncCapacityLimits::new(8, 8, 8, 8, 8, 8, 8, 8, 8)
                .unwrap_or_else(|error| panic!("capacities: {error}")),
            8,
            SinkPlan::default(),
            identities,
            Some((2, 2)),
            service,
        );
        let accepted = accepted(&interpreter, &root);
        let execution = accepted.execution_id();
        let coordinator = interpreter
            .test_nondurable_resource_coordinator(execution)
            .unwrap_or_else(|| panic!("execution accounting owner"));
        let machine = resource_machine(execution);
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
        let entered = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        coordinator
            .attach_resource_host_value(
                &subject,
                owner,
                CleanupValue {
                    drops: Arc::clone(&drops),
                    fails,
                    pause: (times_out && !remains_active)
                        .then_some((Arc::clone(&entered), release_rx)),
                },
            )
            .unwrap_or_else(|_| panic!("attachment"));
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
                .unwrap_or_else(|error| panic!("semantic release: {error:?}"));
        }
        let before = coordinator
            .snapshot()
            .resource_records()
            .unwrap_or_else(|| panic!("records"))
            .to_vec();
        refuse.store(service_refuses, Ordering::Release);
        let terminal_before =
            already_terminal.then(|| drive_to_terminal(&executor, &interpreter, accepted.handle()));
        let reason = caller_cancellation_reason(Some(Arc::from("resource cleanup")), 64)
            .unwrap_or_else(|error| panic!("reason: {error:?}"));
        let mut cancellation = Box::pin(interpreter.cancel_execution(execution, reason));
        assert!(
            cancellation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        // Poll the newly submitted control first, before allowing the root to complete normally.
        let control = *executor
            .task_ids()
            .last()
            .unwrap_or_else(|| panic!("control task"));
        let _ = executor
            .poll_task(control)
            .unwrap_or_else(|error| panic!("control: {error:?}"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut timer_released = false;
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
            if times_out
                && !timer_released
                && (entered.load(Ordering::Acquire)
                    || (remains_active && coordinator.snapshot().state().drivers_are_quiescent()))
            {
                let timer = executor
                    .sleep_durations()
                    .len()
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("cleanup deadline was not registered"));
                fail_timer.store(executor_fails, Ordering::Release);
                executor
                    .release_sleep(timer)
                    .unwrap_or_else(|error| panic!("cleanup deadline: {error:?}"));
                timer_released = true;
            }
            std::thread::yield_now();
        };
        let snapshot = accepted
            .handle()
            .snapshot()
            .unwrap_or_else(|error| panic!("lifecycle snapshot: {error:?}"));
        assert!(
            snapshot.terminal.is_some(),
            "driver terminal publication precedes cleanup reporting"
        );
        let expected_failure = if service_refuses {
            Some(gantry::runtime::ExecutionResourceCleanupFailure::Service)
        } else if executor_fails {
            Some(gantry::runtime::ExecutionResourceCleanupFailure::Executor)
        } else if times_out {
            Some(gantry::runtime::ExecutionResourceCleanupFailure::Deadline)
        } else if fails {
            Some(gantry::runtime::ExecutionResourceCleanupFailure::Disposal)
        } else {
            None
        };
        assert_eq!(snapshot.resource_cleanup_failure, expected_failure);
        if service_refuses {
            assert!(matches!(
                result,
                Err(gantry::CancelExecutionError::ResourceCleanup(
                    gantry::runtime::ResourceCleanupError::Submission(
                        gantry::host::contracts::BlockingWorkSubmitError::CapacityExhausted
                    )
                ))
            ));
            assert_eq!(drops.load(Ordering::Acquire), 0);
            assert_eq!(
                coordinator.snapshot().resource_records(),
                Some(before.as_slice())
            );
            coordinator
                .dispose_settled_resource_host_values()
                .unwrap_or_else(|error| panic!("late physical cleanup: {error:?}"));
        } else if times_out {
            if executor_fails {
                assert!(
                    matches!(result, Err(gantry::CancelExecutionError::Executor(ref error))
                    if error.code.as_ref() == "cleanup-timer-failure")
                );
            } else {
                assert!(matches!(
                    result,
                    Err(gantry::CancelExecutionError::CleanupTimedOut)
                ));
            }
            assert!(timer_released);
            let mut pending = Box::pin(coordinator.wait_for_shutdown_quiescence());
            assert!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "timed-out cleanup still owns the paused physical value"
            );
            let _ = release_tx.send(());
            if remains_active {
                assert_eq!(
                    drops.load(Ordering::Acquire),
                    0,
                    "cancellation cannot fabricate semantic release or dispose active ownership"
                );
                assert_eq!(
                    coordinator.snapshot().resource_records(),
                    Some(before.as_slice())
                );
                coordinator
                    .settle_resource_from_post_failure(&failure, 21, &subject)
                    .unwrap_or_else(|error| panic!("explicit late release: {error:?}"));
                coordinator
                    .dispose_settled_resource_host_values()
                    .unwrap_or_else(|error| panic!("explicit late cleanup: {error:?}"));
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while coordinator.has_settled_resource_host_values() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "retained destruction did not finish"
                );
                std::thread::yield_now();
            }
        } else if fails {
            assert!(matches!(
                result,
                Err(gantry::CancelExecutionError::ResourceDisposal(
                    HostResourceError::Boundary(_)
                ))
            ));
        } else if already_terminal {
            assert!(matches!(result, Ok(CancellationRecord::AlreadyTerminal(_))));
        } else {
            assert!(matches!(result, Ok(CancellationRecord::Accepted { .. })));
        }
        let after_cleanup = accepted
            .handle()
            .snapshot()
            .unwrap_or_else(|error| panic!("lifecycle snapshot: {error:?}"));
        assert_eq!(after_cleanup.foreground, snapshot.foreground);
        assert_eq!(after_cleanup.terminal, snapshot.terminal);
        assert_eq!(after_cleanup.cancellation, snapshot.cancellation);
        assert_eq!(after_cleanup.resource_cleanup_failure, expected_failure);
        if let Some(prior) = terminal_before {
            assert_eq!(after_cleanup.foreground, prior.foreground);
            assert_eq!(after_cleanup.terminal, prior.terminal);
            assert_eq!(after_cleanup.cancellation, prior.cancellation);
        }
        if expected_failure.is_some() {
            assert_eq!(
                accepted.handle().record_resource_cleanup_failure(
                    gantry::runtime::ExecutionResourceCleanupFailure::Service
                ),
                Ok(false)
            );
            assert_eq!(
                accepted
                    .handle()
                    .snapshot()
                    .unwrap_or_else(|error| panic!("repeat snapshot: {error:?}")),
                after_cleanup
            );
        }
        assert_eq!(drops.load(Ordering::Acquire), 1);
        if !remains_active {
            assert_eq!(
                coordinator.snapshot().resource_records(),
                Some(before.as_slice())
            );
        }
        let mut quiescence = Box::pin(coordinator.wait_for_shutdown_quiescence());
        assert!(
            quiescence
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(accepted);
    }
}
