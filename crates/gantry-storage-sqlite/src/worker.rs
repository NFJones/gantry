//! Bounded command admission and response ownership for the SQLite worker.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

use rusqlite::Connection;

type WorkerJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

/// Point-in-time counters for the bounded SQLite command worker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqliteWorkerSnapshot {
    /// Commands admitted to the finite queue.
    pub queued: u64,
    /// Commands that began execution on the connection thread.
    pub executing: u64,
    /// Mutating commands that crossed their SQLite commit boundary.
    pub committed: u64,
    /// Commands that completed with a structured adapter failure.
    pub failed: u64,
    /// Responses whose caller stopped waiting before completion.
    pub caller_dropped: u64,
}

/// Failure to admit work or receive a result from the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerFailure {
    QueueSaturated,
    WorkerUnavailable,
}

/// Failure while creating the worker-owned SQLite connection.
pub(crate) enum WorkerStartError<E> {
    Initialize(E),
    WorkerUnavailable,
}

/// Completion classification used only for worker state accounting.
pub(crate) enum CommandCompletion<T> {
    Completed(T),
    Committed(T),
    Failed(T),
}

#[derive(Debug, Default)]
pub(crate) struct WorkerCounters {
    queued: AtomicU64,
    executing: AtomicU64,
    committed: AtomicU64,
    failed: AtomicU64,
    caller_dropped: AtomicU64,
}

impl WorkerCounters {
    fn record_queued(&self) {
        self.queued.fetch_add(1, Ordering::Relaxed);
    }

    fn record_executing(&self) {
        self.executing.fetch_add(1, Ordering::Relaxed);
    }

    fn record_committed(&self) {
        self.committed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> SqliteWorkerSnapshot {
        SqliteWorkerSnapshot {
            queued: self.queued.load(Ordering::Relaxed),
            executing: self.executing.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            caller_dropped: self.caller_dropped.load(Ordering::Relaxed),
        }
    }
}

/// One finite queue and one connection-affine worker thread.
pub(crate) struct SqliteWorker {
    sender: Mutex<Option<SyncSender<WorkerJob>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    counters: Arc<WorkerCounters>,
}

impl SqliteWorker {
    pub(crate) fn start<R, E, F>(
        queue_capacity: usize,
        initialize: F,
    ) -> Result<(Self, R), WorkerStartError<E>>
    where
        R: Send + 'static,
        E: Send + 'static,
        F: FnOnce() -> Result<(Connection, R), E> + Send + 'static,
    {
        let counters = Arc::new(WorkerCounters::default());
        let (sender, receiver) = sync_channel::<WorkerJob>(queue_capacity);
        let (initial_sender, initial_receiver) = sync_channel(1);
        let thread = thread::Builder::new()
            .name("gantry-sqlite-worker".to_owned())
            .spawn(move || match initialize() {
                Ok((mut connection, initialized)) => {
                    if initial_sender.send(Ok(initialized)).is_err() {
                        return;
                    }
                    while let Ok(job) = receiver.recv() {
                        job(&mut connection);
                    }
                }
                Err(error) => {
                    let _ = initial_sender.send(Err(error));
                }
            })
            .map_err(|_| WorkerStartError::WorkerUnavailable)?;
        let initialized = match initial_receiver.recv() {
            Ok(Ok(initialized)) => initialized,
            Ok(Err(error)) => {
                let _ = thread.join();
                return Err(WorkerStartError::Initialize(error));
            }
            Err(_) => {
                let _ = thread.join();
                return Err(WorkerStartError::WorkerUnavailable);
            }
        };
        Ok((
            Self {
                sender: Mutex::new(Some(sender)),
                thread: Mutex::new(Some(thread)),
                counters,
            },
            initialized,
        ))
    }

    pub(crate) fn submit<T, F>(&self, run: F) -> Result<ResponseFuture<T>, WorkerFailure>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> CommandCompletion<T> + Send + 'static,
    {
        let (response_sender, response) = response(Arc::clone(&self.counters));
        let counters = Arc::clone(&self.counters);
        let job = Box::new(move |connection: &mut Connection| {
            counters.record_executing();
            let completion = run(connection);
            let value = match completion {
                CommandCompletion::Completed(value) => value,
                CommandCompletion::Committed(value) => {
                    counters.record_committed();
                    value
                }
                CommandCompletion::Failed(value) => {
                    counters.record_failed();
                    value
                }
            };
            response_sender.send(value);
        });
        let sender = lock(&self.sender);
        let Some(sender) = sender.as_ref() else {
            return Err(WorkerFailure::WorkerUnavailable);
        };
        match sender.try_send(job) {
            Ok(()) => {
                self.counters.record_queued();
                Ok(response)
            }
            Err(TrySendError::Full(_)) => Err(WorkerFailure::QueueSaturated),
            Err(TrySendError::Disconnected(_)) => Err(WorkerFailure::WorkerUnavailable),
        }
    }

    pub(crate) fn counters(&self) -> &Arc<WorkerCounters> {
        &self.counters
    }

    pub(crate) fn close(&self) -> Result<(), WorkerFailure> {
        let sender = lock(&self.sender).take();
        drop(sender);
        let thread = lock(&self.thread).take();
        match thread {
            Some(thread) => thread.join().map_err(|_| WorkerFailure::WorkerUnavailable),
            None => Ok(()),
        }
    }
}

impl Drop for SqliteWorker {
    fn drop(&mut self) {
        let sender = lock(&self.sender).take();
        drop(sender);
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct ResponseSender<T> {
    shared: Arc<ResponseShared<T>>,
    sent: bool,
}

pub(crate) struct ResponseFuture<T> {
    shared: Arc<ResponseShared<T>>,
}

struct ResponseShared<T> {
    caller_alive: AtomicBool,
    counters: Arc<WorkerCounters>,
    state: Mutex<ResponseState<T>>,
}

struct ResponseState<T> {
    value: Option<T>,
    sender_closed: bool,
    waker: Option<Waker>,
}

fn response<T>(counters: Arc<WorkerCounters>) -> (ResponseSender<T>, ResponseFuture<T>) {
    let shared = Arc::new(ResponseShared {
        caller_alive: AtomicBool::new(true),
        counters,
        state: Mutex::new(ResponseState {
            value: None,
            sender_closed: false,
            waker: None,
        }),
    });
    (
        ResponseSender {
            shared: Arc::clone(&shared),
            sent: false,
        },
        ResponseFuture { shared },
    )
}

impl<T> ResponseSender<T> {
    fn send(mut self, value: T) {
        let waker = {
            let mut state = lock(&self.shared.state);
            state.value = Some(value);
            state.waker.take()
        };
        self.sent = true;
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Drop for ResponseSender<T> {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        let waker = {
            let mut state = lock(&self.shared.state);
            state.sender_closed = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Future for ResponseFuture<T> {
    type Output = Result<T, WorkerFailure>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock(&self.shared.state);
        if let Some(value) = state.value.take() {
            self.shared.caller_alive.store(false, Ordering::Release);
            Poll::Ready(Ok(value))
        } else if state.sender_closed {
            self.shared.caller_alive.store(false, Ordering::Release);
            Poll::Ready(Err(WorkerFailure::WorkerUnavailable))
        } else {
            state.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl<T> Drop for ResponseFuture<T> {
    fn drop(&mut self) {
        if self.shared.caller_alive.swap(false, Ordering::AcqRel) {
            self.shared
                .counters
                .caller_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::task::{Context, Poll, Waker};
    use std::thread;

    use rusqlite::Connection;

    use super::{CommandCompletion, SqliteWorker, WorkerFailure};

    #[test]
    fn connection_is_opened_and_used_only_on_the_adapter_worker() {
        let caller = thread::current().id();
        let (worker, opened_on) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, thread::current().id()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        assert_ne!(opened_on, caller);
        let executed_on = worker
            .submit(|_| CommandCompletion::Completed(thread::current().id()))
            .unwrap_or_else(|error| panic!("command was rejected: {error:?}"));
        assert_eq!(block_on(executed_on), Ok(opened_on));
        assert_eq!(worker.close(), Ok(()));
    }

    #[test]
    fn finite_queue_rejects_saturation_without_blocking() {
        let (worker, ()) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, ()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        let (started_tx, started_rx) = channel();
        let (release_tx, release_rx) = channel();
        let first = worker
            .submit(move |_| {
                signal(&started_tx);
                wait(release_rx);
                CommandCompletion::Completed(1_u8)
            })
            .unwrap_or_else(|error| panic!("first command was rejected: {error:?}"));
        wait(started_rx);
        let second = worker
            .submit(|_| CommandCompletion::Completed(2_u8))
            .unwrap_or_else(|error| panic!("second command was rejected: {error:?}"));
        assert!(matches!(
            worker.submit(|_| CommandCompletion::Completed(3_u8)),
            Err(WorkerFailure::QueueSaturated)
        ));
        signal(&release_tx);
        assert_eq!(block_on(first), Ok(1));
        assert_eq!(block_on(second), Ok(2));
        assert_eq!(worker.counters().snapshot().queued, 2);
        assert_eq!(worker.close(), Ok(()));
    }

    #[test]
    fn dropped_caller_does_not_cancel_committed_work() {
        let (worker, ()) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, ()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        let (started_tx, started_rx) = channel();
        let (release_tx, release_rx) = channel();
        let response = worker
            .submit(move |connection| {
                signal(&started_tx);
                wait(release_rx);
                connection
                    .execute_batch("CREATE TABLE committed_after_drop (id INTEGER) STRICT")
                    .unwrap_or_else(|error| panic!("worker mutation failed: {error}"));
                CommandCompletion::Committed(())
            })
            .unwrap_or_else(|error| panic!("command was rejected: {error:?}"));
        wait(started_rx);
        drop(response);
        signal(&release_tx);
        assert_eq!(worker.close(), Ok(()));
        let snapshot = worker.counters().snapshot();
        assert_eq!(snapshot.committed, 1);
        assert_eq!(snapshot.caller_dropped, 1);
    }

    #[test]
    fn dropped_queued_caller_does_not_remove_admitted_work() {
        let (worker, ()) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, ()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        let (started_tx, started_rx) = channel();
        let (release_tx, release_rx) = channel();
        let first = worker
            .submit(move |_| {
                signal(&started_tx);
                wait(release_rx);
                CommandCompletion::Completed(1_u8)
            })
            .unwrap_or_else(|error| panic!("first command was rejected: {error:?}"));
        wait(started_rx);
        let queued = worker
            .submit(|connection| {
                connection
                    .execute_batch("CREATE TABLE completed_after_queued_drop (id INTEGER) STRICT")
                    .unwrap_or_else(|error| panic!("queued worker mutation failed: {error}"));
                CommandCompletion::Committed(())
            })
            .unwrap_or_else(|error| panic!("queued command was rejected: {error:?}"));
        drop(queued);
        signal(&release_tx);
        assert_eq!(block_on(first), Ok(1));
        assert_eq!(worker.close(), Ok(()));
        let snapshot = worker.counters().snapshot();
        assert_eq!(snapshot.queued, 2);
        assert_eq!(snapshot.executing, 2);
        assert_eq!(snapshot.committed, 1);
        assert_eq!(snapshot.caller_dropped, 1);
    }

    #[test]
    fn dropped_completed_response_preserves_committed_work() {
        let (worker, ()) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, ()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        let response = worker
            .submit(|connection| {
                connection
                    .execute_batch("CREATE TABLE committed_before_drop (id INTEGER) STRICT")
                    .unwrap_or_else(|error| panic!("worker mutation failed: {error}"));
                CommandCompletion::Committed(())
            })
            .unwrap_or_else(|error| panic!("command was rejected: {error:?}"));
        loop {
            if super::lock(&response.shared.state).value.is_some() {
                break;
            }
            thread::yield_now();
        }
        drop(response);
        assert_eq!(worker.close(), Ok(()));
        let snapshot = worker.counters().snapshot();
        assert_eq!(snapshot.committed, 1);
        assert_eq!(snapshot.caller_dropped, 1);
    }

    #[test]
    fn worker_panic_closes_pending_response_and_future_admission() {
        let (worker, ()) = SqliteWorker::start(1, || {
            Connection::open_in_memory()
                .map(|connection| (connection, ()))
                .map_err(|_| ())
        })
        .unwrap_or_else(|_| panic!("worker failed to start"));
        let response = worker
            .submit::<(), _>(|_| panic!("injected worker panic"))
            .unwrap_or_else(|error| panic!("panic command was rejected: {error:?}"));
        assert_eq!(block_on(response), Err(WorkerFailure::WorkerUnavailable));
        assert_eq!(worker.close(), Err(WorkerFailure::WorkerUnavailable));
        assert!(matches!(
            worker.submit(|_| CommandCompletion::Completed(())),
            Err(WorkerFailure::WorkerUnavailable)
        ));
    }

    fn signal(sender: &Sender<()>) {
        sender
            .send(())
            .unwrap_or_else(|_| panic!("test synchronization receiver was dropped"));
    }

    fn wait(receiver: Receiver<()>) {
        receiver
            .recv()
            .unwrap_or_else(|_| panic!("test synchronization sender was dropped"));
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
