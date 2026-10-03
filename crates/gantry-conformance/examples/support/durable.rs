//! SQLite-backed logical restart demonstrations using only public facade APIs.
//!
//! Each run owns a temporary database, settles and releases the first interpreter,
//! reopens storage, then resumes with a fresh identity stream and no hook script.
//! This is orderly logical restart, not a simulated process crash or crash-cut test.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

use gantry::host::contracts::JournalStorage;
use gantry::host::journal::{JournalId, ReadJournalPrefixV1};
use gantry::{
    DurableResumeExecutionRequest, DurableResumeExecutionResult, DurableResumeSourceComparison,
    DurableStartExecutionRequest, DurableStartExecutionResult,
};
use gantry_storage_sqlite::{SqliteJournalStore, SqliteJournalStoreConfig};

/// Rejects misplaced or misspelled recovery modes rather than ignoring them.
pub fn validate(case: &Case) -> Result<(), String> {
    if let Some(mode) = case.values.get("durable_mode")
        && (case.class != Class::Durable
            || !matches!(
                mode.as_str(),
                Some(
                    "source-free"
                        | "candidate-exact"
                        | "candidate-mismatch"
                        | "configuration-mismatch"
                        | "start-only"
                )
            ))
    {
        return Err("invalid durable_mode for execution class".into());
    }
    Ok(())
}

/// A private per-scenario directory keeps concurrent scenarios independent.
struct Workspace(PathBuf);
impl Workspace {
    /// Creates a unique directory without overwriting any existing file.
    fn new() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gantry-durable-example-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).map_err(|e| format!("temporary workspace: {e}"))?;
        Ok(Self(path))
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Builds an offline interpreter with finite limits and disjoint restart identities.
pub fn interpreter(
    host: Arc<impl IntegrationPreflight + RuntimeSessionService + HookFactory + 'static>,
    seed: u64,
    mismatch: bool,
) -> Result<Interpreter, String> {
    interpreter_with_policy(host, seed, mismatch, |configuration| configuration)
}

/// Applies an explicit embedder policy before constructing the public interpreter.
pub fn interpreter_with_policy(
    host: Arc<impl IntegrationPreflight + RuntimeSessionService + HookFactory + 'static>,
    seed: u64,
    mismatch: bool,
    policy: impl FnOnce(InterpreterConfiguration) -> InterpreterConfiguration,
) -> Result<Interpreter, String> {
    let identities = Arc::new(DeterministicIdentitySource::new((seed..seed + 16_384).map(
        |n| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&n.to_le_bytes());
            Ok(bytes)
        },
    )));
    let clock = Arc::new(DeterministicUtcClock::new((0..100_000).map(|n| {
        UtcTimestamp::from_unix_seconds(0, n).map_err(|_| host_error("durable-clock"))
    })));
    let executor = Arc::new(TokioExecutor::new(
        tokio::runtime::Handle::current(),
        Arc::new(FixedJitter),
    ));
    let required = RequiredConfiguration::new(
        frontend_limits()?,
        1_048_576,
        if mismatch { 524_288 } else { 1_048_576 },
        DEFAULT_VALUE_LIMITS,
        1_000_000,
        100_000,
        100_000,
        1_000,
    )
    .map_err(|e| e.to_string())?;
    let capacity =
        AsyncCapacityLimits::new(64, 64, 64, 64, 64, 64, 64, 64, 64).map_err(|e| e.to_string())?;
    Ok(Interpreter::new(
        policy(InterpreterConfiguration::new(
            executor, identities, required, capacity,
        )),
        clock,
        host.clone(),
        host.clone(),
        host,
    ))
}

/// Adds recovery session resolution without weakening ordinary script validation.
struct RecoveryHost(Arc<OfflineHost>);
impl IntegrationPreflight for RecoveryHost {
    fn call<'a>(&'a self, request: HostRequest) -> HostFuture<'a, Result<HostResponse, HostError>> {
        if request.operation() == EmbeddingOperation::ResolveSessions {
            Box::pin(async move { response(&request, json!({"result":"resolved"})) })
        } else {
            self.0.call(request)
        }
    }
}
impl RuntimeSessionService for RecoveryHost {
    fn establish<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<HostResponse, HostError>> {
        self.0.establish(request)
    }
}
impl HookFactory for RecoveryHost {
    fn create_hook<'a>(
        &'a self,
        request: HostRequest,
    ) -> HostFuture<'a, Result<Box<dyn OperationHook>, HostError>> {
        self.0.create_hook(request)
    }
}

/// Allocates a script that can prove no new dispatch occurred after restart.
fn host(hooks: Vec<Hook>) -> Arc<OfflineHost> {
    Arc::new(OfflineHost {
        state: Arc::new(Mutex::new(ScriptState {
            pending: hooks.into(),
            requests: Vec::new(),
            failures: Vec::new(),
        })),
    })
}

/// Checks real foreground and terminal coordinates against explicit expected JSON.
fn outcome(snapshot: &gantry::runtime::ExecutionSnapshot, case: &Case) -> Result<(), String> {
    check_terminal(snapshot, case)?;
    match &snapshot.foreground {
        Some(MachineOutcome::Succeeded(value)) => {
            let actual: Value = serde_json::from_slice(value.canonical_json().bytes())
                .map_err(|e| e.to_string())?;
            if case.values.get("expected") == Some(&actual) {
                Ok(())
            } else {
                Err(format!(
                    "durable expected {:?}, got {actual}",
                    case.values.get("expected")
                ))
            }
        }
        other => Err(format!("unexpected durable outcome: {other:?}")),
    }
}

/// Executes, releases, reopens and verifies a committed terminal journal.
pub(super) async fn run(root: &Path, case: &Case) -> Result<Report, String> {
    let workspace = Workspace::new()?;
    let path = workspace.0.join("journal.sqlite");
    let store = Arc::new(
        SqliteJournalStore::open(&path, SqliteJournalStoreConfig::default())
            .map_err(|e| format!("SQLite open: {e:?}"))?,
    );
    let journal_id =
        JournalId::new("example-logical-restart").map_err(|e| format!("journal id: {e:?}"))?;
    let selection = selection()?;
    let scripted = host(case.hooks.clone());
    let initial = interpreter(scripted.clone(), 1, false)?;
    let input = case
        .values
        .get("input")
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|e| e.to_string())?;
    let accepted = match initial
        .start_durable_execution(
            store.clone(),
            DurableStartExecutionRequest {
                journal_id: journal_id.clone(),
                start: StartExecutionRequest {
                    package_root: root,
                    protocol_selection: &selection,
                    required_peers: &[],
                    entry_input: input.as_deref(),
                    root_session: None,
                    event_delivery: None,
                },
            },
        )
        .await
    {
        DurableStartExecutionResult::Accepted(value) => value,
        DurableStartExecutionResult::Rejected(error) => {
            return Err(format!("durable start: {}", error.failure.code));
        }
    };
    let execution_id = accepted.execution_id();
    let snapshot = tokio::time::timeout(
        Duration::from_secs(10),
        initial.await_terminal(accepted.handle()),
    )
    .await
    .map_err(|_| {
        format!(
            "initial terminal timeout; query: {:?}",
            initial.query_execution(execution_id)
        )
    })?
    .map_err(|e| format!("initial terminal: {e:?}"))?
    .ok_or("initial execution missing")?;
    outcome(&snapshot, case)?;
    let report = scripted.finish()?;
    let shutdown = initial
        .shutdown()
        .await
        .map_err(|e| format!("initial shutdown: {e:?}"))?;
    if !shutdown.orderly {
        return Err(format!("initial shutdown not orderly: {shutdown:?}"));
    }
    drop(accepted);
    drop(initial);
    store.close().map_err(|e| format!("SQLite close: {e:?}"))?;
    drop(store);

    let mode = case
        .values
        .get("durable_mode")
        .and_then(Value::as_str)
        .unwrap_or("source-free");
    if mode == "start-only" {
        return Ok(report);
    }
    let candidate = workspace.0.join("candidate");
    if mode == "candidate-mismatch" {
        fs::create_dir(&candidate).map_err(|e| e.to_string())?;
        fs::write(
            candidate.join("main.gnt"),
            "fn main() -> String { \"different signature\" }",
        )
        .map_err(|e| e.to_string())?;
    }
    let store = Arc::new(
        SqliteJournalStore::open(&path, SqliteJournalStoreConfig::default())
            .map_err(|e| format!("SQLite reopen: {e:?}"))?,
    );
    let before = store
        .read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        })
        .await
        .map_err(|e| format!("prefix: {e:?}"))?;
    let empty = host(Vec::new());
    let resumed = interpreter(
        Arc::new(RecoveryHost(empty.clone())),
        20_000,
        mode == "configuration-mismatch",
    )?;
    let result = resumed
        .resume_durable_execution(
            store.clone(),
            DurableResumeExecutionRequest {
                journal_id: journal_id.clone(),
                protocol_selection: &selection,
                candidate_package_root: match mode {
                    "candidate-exact" => Some(root),
                    "candidate-mismatch" => Some(&candidate),
                    _ => None,
                },
                expected_execution_id: Some(execution_id),
                event_delivery: None,
            },
        )
        .await;
    match result {
        DurableResumeExecutionResult::Accepted(value) if !mode.ends_with("mismatch") => {
            let comparison = if mode == "candidate-exact" {
                DurableResumeSourceComparison::ExactManifest
            } else {
                DurableResumeSourceComparison::SourceFree
            };
            if value.execution_id() != execution_id || value.source_comparison() != comparison {
                return Err("resume identity/provenance changed".into());
            }
            let snapshot = tokio::time::timeout(
                Duration::from_secs(10),
                resumed.await_terminal(value.handle()),
            )
            .await
            .map_err(|_| "resumed terminal timeout")?
            .map_err(|e| format!("resumed terminal: {e:?}"))?
            .ok_or("resumed execution missing")?;
            outcome(&snapshot, case)?;
        }
        DurableResumeExecutionResult::Rejected(error) if mode.ends_with("mismatch") => {
            let expected = if mode == "candidate-mismatch" {
                "canonical-ir-identity-mismatch"
            } else {
                "immutable-configuration-mismatch"
            };
            if error.code.as_ref() != expected || error.release_error.is_some() {
                return Err(format!("wrong rejection: {error:?}"));
            }
            let after = store
                .read_prefix(ReadJournalPrefixV1 { journal_id })
                .await
                .map_err(|e| format!("prefix after rejection: {e:?}"))?;
            if before != after {
                return Err("rejected resume changed authoritative prefix".into());
            }
        }
        DurableResumeExecutionResult::Accepted(_) => {
            return Err("mismatch unexpectedly accepted".into());
        }
        DurableResumeExecutionResult::Rejected(error) => {
            return Err(format!("resume rejected: {}", error.code));
        }
        DurableResumeExecutionResult::RunnableReplacementUnavailable(_) => {
            return Err("unfinished graph replacement is unavailable".into());
        }
    }
    let shutdown = resumed
        .shutdown()
        .await
        .map_err(|e| format!("resume shutdown: {e:?}"))?;
    if !shutdown.orderly {
        return Err(format!("resume shutdown not orderly: {shutdown:?}"));
    }
    if !empty.finish()?.requests.is_empty() {
        return Err("committed result redispatched".into());
    }
    drop(resumed);
    store
        .close()
        .map_err(|e| format!("SQLite final close: {e:?}"))?;
    Ok(report)
}
