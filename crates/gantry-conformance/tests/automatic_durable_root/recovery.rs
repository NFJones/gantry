//! Serial crash-cut recovery through the public facade.

use super::*;

#[test]
fn committed_serial_outcome_resumes_without_hook_and_repairs_completion() {
    recover_serial_outcome(false, false, false, false);
}

#[test]
fn serial_completion_retains_outcome_cause_across_resume_revision() {
    recover_serial_outcome(true, false, false, false);
}

#[test]
fn serial_model_outcome_reuses_forked_session_without_hook() {
    recover_serial_outcome(false, true, false, false);
}

#[test]
fn serial_result_event_is_repaired_before_source_progress() {
    recover_serial_outcome(false, false, true, false);
}

#[test]
fn serial_model_result_repair_preserves_accepted_transcript() {
    recover_serial_outcome(false, true, true, false);
}

#[test]
fn compacted_serial_result_retains_cause_through_event_repair() {
    recover_serial_outcome(false, false, true, true);
}

#[test]
fn serial_non_idempotent_preparation_recovers_as_unknown_outcome_without_dispatch() {
    let root = TempDirectory::new(
        "action non_idempotent publish(value: Int) -> String;\nfn main() -> String { action publish(7) }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""unexpected""#[..]),
        ))])],
    ));
    let initial = interpreter_with_integration(executor.clone(), integration);
    let mut store = ObservedJournalStore::with_post_commit_settlement_gate(1);
    store.operation_gate = Some("\"cut\":\"operation-prepared\"");
    let storage = Arc::new(store);
    let journal_id = JournalId::new("serial-unknown-outcome-recovery")
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
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::OperationPrepared
    );
    assert!(matches!(
        recovered.operation_recovery(),
        gantry::runtime::DurableOperationRecoveryV1::UnknownOutcome { .. }
    ));
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
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
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
        matches!(
            snapshot.foreground,
            Some(MachineOutcome::Failed(ref failure))
                if failure.code
                    == RuntimeCode::Operation(RuntimeErrorCategory::UnknownActionOutcome)
        ),
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
    assert_eq!(
        recovered.latest_cut(),
        DurableCommitCutV1::TerminalCompletion
    );
    assert!(matches!(
        recovered.machine().outcome(),
        Some(MachineOutcome::Failed(failure))
            if failure.code
                == RuntimeCode::Operation(RuntimeErrorCategory::UnknownActionOutcome)
    ));
}

#[test]
fn serial_read_only_preparation_redispatches_with_stable_operation_identity() {
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
            Arc::from(&br#""unexpected""#[..]),
        ))])],
    ));
    let initial = interpreter_with_integration(executor.clone(), integration);
    let mut store = ObservedJournalStore::with_post_commit_settlement_gate(1);
    store.operation_gate = Some("\"cut\":\"operation-prepared\"");
    let storage = Arc::new(store);
    let journal_id = JournalId::new("serial-read-only-redispatch-recovery")
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
    let (operation_id, previous_dispatch_id) = match recovered.operation_recovery() {
        gantry::runtime::DurableOperationRecoveryV1::Redispatch {
            operation_id,
            previous_dispatch_id,
            validation_attempt: 0,
            next_recovery_dispatch: 1,
            ..
        } => (*operation_id, *previous_dispatch_id),
        recovery => panic!("unexpected recovery: {recovery:?}"),
    };
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
                &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
            ),
            ScriptedPreflight::success(
                EmbeddingOperation::ResolveSessions,
                &br#"{"result":"resolved"}"#[..],
            ),
        ],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
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
    let dispatches = integration
        .calls()
        .into_iter()
        .filter(|call| matches!(call.operation, EmbeddingOperation::DispatchOperation))
        .collect::<Vec<_>>();
    assert_eq!(dispatches.len(), 1);
    let request: serde_json::Value = serde_json::from_slice(&dispatches[0].canonical_bytes)
        .unwrap_or_else(|error| panic!("dispatch request: {error:?}"));
    let request = &request["operation_request"];
    assert_eq!(request["operation_id"], operation_id.to_string());
    assert_ne!(request["dispatch_id"], previous_dispatch_id.to_string());
    assert_eq!(request["validation_attempt"], 0);
    assert_eq!(request["recovery_dispatch"], 1);
}

#[test]
fn serial_retry_wait_is_replayed_before_replacement_dispatch() {
    let root = TempDirectory::new(
        "action read_only lookup() -> String;\nfn main() -> String { action(retry_limit = 1) lookup() }",
    );
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let integration = Arc::new(ScriptedIntegration::new(
        [ScriptedPreflight::success(
            EmbeddingOperation::ResolveMappings,
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..],
        )],
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&b"true"[..]),
        ))])],
    ));
    let initial = interpreter_with_integration(executor.clone(), integration);
    let mut store = ObservedJournalStore::with_post_commit_settlement_gate(1);
    store.operation_gate = Some("\"cut\":\"retry-waiting\"");
    let storage = Arc::new(store);
    let journal_id = JournalId::new("serial-retry-wait-recovery")
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
    assert_eq!(recovered.latest_cut(), DurableCommitCutV1::RetryWaiting);
    assert!(matches!(
        recovered.operation_recovery(),
        gantry::runtime::DurableOperationRecoveryV1::RetryDelay { .. }
    ));
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
    executor.control_sleeps();
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
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
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
        if !executor.sleep_durations().is_empty() {
            break;
        }
    }
    assert_eq!(executor.sleep_durations().len(), 1);
    assert!(integration.calls().iter().all(|call| !matches!(
        call.operation,
        EmbeddingOperation::CreateHook | EmbeddingOperation::DispatchOperation
    )));
    executor
        .release_sleep(0)
        .unwrap_or_else(|error| panic!("retry delay release: {error:?}"));
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
    assert_eq!(
        integration
            .calls()
            .iter()
            .filter(|call| matches!(call.operation, EmbeddingOperation::DispatchOperation))
            .count(),
        1
    );
}

struct CompactingSerialStore {
    inner: Arc<ObservedJournalStore>,
    frontier_cut: &'static str,
}

impl JournalStorage for CompactingSerialStore {
    fn acquire_owner<'a>(
        &'a self,
        request: AcquireJournalOwnerV1,
    ) -> HostFuture<'a, Result<JournalOwnershipV1, JournalError>> {
        self.inner.acquire_owner(request)
    }

    fn read_prefix<'a>(
        &'a self,
        request: ReadJournalPrefixV1,
    ) -> HostFuture<'a, Result<JournalPrefixV1, JournalError>> {
        Box::pin(async move {
            let prefix = self.inner.read_prefix(request).await?;
            let JournalPrefixV1::Full(full) = prefix else {
                return Ok(prefix);
            };
            let Some(frontier_index) = full.evidence.iter().rposition(|entry| {
                entry.kind.as_ref() == "gantry.logical-evidence/v3"
                    && std::str::from_utf8(&entry.canonical_body)
                        .is_ok_and(|body| body.contains(self.frontier_cut))
            }) else {
                return Ok(JournalPrefixV1::Full(full));
            };
            let start = full
                .evidence
                .first()
                .and_then(|entry| {
                    let program = gantry::runtime::DurableExecutionStartV3::retained_program(
                        &entry.canonical_body,
                    )
                    .ok()?;
                    gantry::runtime::DurableExecutionStartV3::decode(
                        &program,
                        &entry.canonical_body,
                    )
                    .ok()
                })
                .ok_or_else(|| JournalError::new(JournalErrorCode::Internal))?;
            let program = start
                .program()
                .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
            let frontier = &full.evidence[frontier_index];
            let state = DurableLogicalEvidenceV3::decode(&program, &frontier.canonical_body)
                .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
            let snapshot = gantry::runtime::DurableRecoverySnapshotV3::new(start, state)
                .map_err(|_| JournalError::new(JournalErrorCode::Internal))?;
            Ok(JournalPrefixV1::Snapshot(
                gantry::host::journal::SnapshotJournalPrefixV1 {
                    journal_id: full.journal_id,
                    snapshot_version: 6,
                    frontier: frontier.sequence,
                    canonical_snapshot: Arc::from(snapshot.canonical_body()),
                    retained_evidence: full.evidence[..=frontier_index]
                        .iter()
                        .map(|entry| (entry.evidence_id, entry.sequence))
                        .collect(),
                    suffix: Arc::from(full.evidence[frontier_index + 1..].to_vec()),
                    committed_through: full.committed_through,
                },
            ))
        })
    }

    fn commit<'a>(
        &'a self,
        request: JournalCommitRequestV1,
    ) -> HostFuture<'a, Result<JournalCommitReceiptV1, JournalError>> {
        self.inner.commit(request)
    }

    fn resolve_payload<'a>(
        &'a self,
        request: ResolveJournalPayloadV1,
    ) -> HostFuture<'a, Result<ResolvedJournalPayloadV1, JournalError>> {
        self.inner.resolve_payload(request)
    }

    fn release_owner<'a>(
        &'a self,
        request: ReleaseJournalOwnerV1,
    ) -> HostFuture<'a, Result<(), JournalError>> {
        self.inner.release_owner(request)
    }
}

/// A policy record may advance the journal tip without replacing the outcome cause.
fn recover_serial_outcome(revise_mapping: bool, model: bool, result_cut: bool, compacted: bool) {
    let root = TempDirectory::new(if model {
        "agents { worker }\ndefault agent = worker;\nfn main() -> String { prompt(session = fork) \"hello\" -> String }"
    } else {
        "action read_only lookup(value: Int) -> String;\nfn main() -> String { action lookup(7) }"
    });
    let executor = Arc::new(DeterministicConcurrentExecutor::default());
    let mut preflight = vec![ScriptedPreflight::success(
        EmbeddingOperation::ResolveMappings,
        if model {
            &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..]
        } else {
            &br#"{"action_mapping_revision":"actions-v1","result":"resolved"}"#[..]
        },
    )];
    if model {
        preflight.push(ScriptedPreflight::success(
            EmbeddingOperation::EstablishSession,
            &br#"{"result":"established"}"#[..],
        ));
    }
    let integration = Arc::new(ScriptedIntegration::new(
        preflight,
        [ScriptedHook::created([Ok(HookOutcomeV1::Completed(
            Arc::from(&br#""done""#[..]),
        ))])],
    ));
    let initial = interpreter_with_integration(executor.clone(), integration);
    let mut store = ObservedJournalStore::with_post_commit_settlement_gate(1);
    store.operation_gate = Some(if result_cut {
        "\"cut\":\"operation-result\""
    } else {
        "\"cut\":\"operation-outcome\""
    });
    let observed = Arc::new(store);
    let storage: Arc<dyn JournalStorage> = if compacted {
        Arc::new(CompactingSerialStore {
            inner: Arc::clone(&observed),
            frontier_cut: "\"cut\":\"operation-result\"",
        })
    } else {
        observed.clone()
    };
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
        observed.post_commit_settlement_started()
    });
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 {
        journal_id: journal_id.clone(),
    }))
    .unwrap_or_else(|error| panic!("prefix: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("recovery: {error:?}"));
    assert_eq!(
        recovered.latest_cut(),
        if result_cut {
            DurableCommitCutV1::OperationResult
        } else {
            DurableCommitCutV1::OperationOutcome
        }
    );
    let cause = recovered.latest_evidence_id();
    let sequence = recovered.latest_sequence();
    let retained_sessions = recovered.sessions().cloned();
    assert!(recovered.events().event_for_cause(cause).is_none());
    executor
        .fail_task(root_task)
        .unwrap_or_else(|error| panic!("crash: {error:?}"));
    observed.release_post_commit_settlement();
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
                if model {
                    &br#"{"agent_mapping_revision":"agents-v1","result":"resolved"}"#[..]
                } else if revise_mapping {
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
        EmbeddingOperation::CreateHook
            | EmbeddingOperation::DispatchOperation
            | EmbeddingOperation::EstablishSession
    )));
    let prefix = block_on(storage.read_prefix(ReadJournalPrefixV1 { journal_id }))
        .unwrap_or_else(|error| panic!("final prefix: {error:?}"));
    let (_, recovered) = recover_authoritative_prefix_with_retained_program(&prefix)
        .unwrap_or_else(|error| panic!("final recovery: {error:?}"));
    if model {
        let before = retained_sessions
            .as_ref()
            .unwrap_or_else(|| panic!("missing retained sessions"));
        let after = recovered
            .sessions()
            .unwrap_or_else(|| panic!("missing recovered sessions"));
        assert_eq!(after.sessions().count(), before.sessions().count());
        for original in before.sessions() {
            let current = after
                .get(original.id)
                .unwrap_or_else(|| panic!("lost session"));
            let mut metadata = current.clone();
            metadata.transcript = original.transcript.clone();
            assert_eq!(&metadata, original);
            if original.parent.is_some() {
                let transcript: serde_json::Value =
                    serde_json::from_slice(current.transcript.bytes())
                        .unwrap_or_else(|error| panic!("transcript: {error:?}"));
                let turns = transcript["turns"]
                    .as_array()
                    .unwrap_or_else(|| panic!("missing turns"));
                assert_eq!(turns.len(), 1);
                assert_eq!(turns[0]["accepted_result"]["value"], "done");
            } else {
                assert_eq!(current.transcript, original.transcript);
            }
        }
    }
    let event = recovered
        .events()
        .event_for_cause(cause)
        .unwrap_or_else(|| panic!("missing completion"));
    assert_eq!(
        event.occurrence().event().kind(),
        if result_cut {
            EventKind::OperationResult
        } else {
            EventKind::OperationCompletion
        }
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
