//! Redirected console output over the landed bounded I/O settlement and resource carrier.
//!
//! This module is the first console runtime integration of `SPEC.md` Section 46. It delivers the
//! declared `std.console::output::write@1` signature for the one output target
//! `GNT-46.9-console-control-and-output-boundary` declares first, a redirected or otherwise
//! non-controlling sink, over the landed common bounded I/O settlement of
//! `crates/gantry-runtime/src/io_settlement.rs` and the landed machine resource carrier of
//! `crates/gantry-runtime/src/resource_transport.rs`.
//!
//! It adds no declaration text. Every authority, request, progress, and output-boundary refusal it
//! presents is owned by `GNT-46.8-console-authority-admission`,
//! `GNT-46.9-console-control-and-output-boundary`, `GNT-45.1-bounded-one-call-io-contract`, or
//! `GNT-45.3-io-progress-derivation`, and is presented through the model of
//! `crates/gantry-ir/src/console.rs` rather than restated here.
//!
//! # Delivered boundary
//!
//! [`ConsoleOutputAccess`] is minted from a launch injection alone, so access is injected and never
//! reconstructed from an ambient numeric descriptor. [`ConsoleOutputSettlement::new`] admits one
//! presentable access identity under the precedence of `GNT-46.8` before any octet moves: an
//! ambient descriptor is classified first, then a required group carrying no injected grant, then a
//! grant naming another group, then a grant the injection did not issue. [`ConsoleRedirectedSink`]
//! is the declared redirected, non-controlling sink: it forwards exactly one call to the
//! caller-arranged carrier, keeps no octet between calls, and never retries that carrier.
//!
//! [`ConsoleOutputSettlement::write`] admits exactly one bounded request of
//! `GNT-45.1-bounded-one-call-io-contract` whose declared quantity is the presented octet count,
//! presents the initialized octets the caller declared, and settles exactly one call through
//! [`crate::IoSettlementService`]. The published accepted prefix is that settlement's own evidence,
//! so a short write stays `short-write` progress with the remainder left to the caller, while a
//! zero-octet write and a request beyond `IO_REQUEST_OCTET_BOUND` are refused by the request
//! contract before any dispatch.
//!
//! # One settlement per occurrence inside one grant
//!
//! A console write consumes one machine-issued occurrence, and `GNT-20` allows one resource
//! generation exactly one settlement. The grantor-owned access reserves the occurrence atomically
//! **before** dispatch and releases the reservation only when nothing was dispatched, so two
//! attempts admitted under one grant - including two separately admitted accounts and two attempts
//! that overlap - cannot both settle it: the second is refused under the landed
//! `duplicate-settlement` refusal. The record is one occurrence identity and no octet, it holds no
//! output, and it is dropped with the access.
//!
//! One launch injects one grant per requirement group of `GNT-46.8`, so one run admits one
//! `ConsoleOutputAccess`. Exclusivity across two independently constructed grant values is not a
//! console decision and is not claimed here: the landed machine occurrence and the landed registry
//! carrier issuance own that fact, and this slice consumes them without restating or duplicating
//! them. This module therefore makes a narrower promise than a second ownership domain would, and
//! says so rather than implying a fence it does not hold.
//!
//! # Undelivered targets
//!
//! This slice delivers no attached-terminal output. A presentation naming
//! [`ConsoleOutputTarget::AttachedTerminal`] is decided by the declaration boundary first: octets
//! carrying the declared control octet `0x1b` are refused under
//! `console-control-bearing-output-refused` with the presented octets published unchanged, and
//! octets that boundary admits are then refused as
//! [`ConsoleRuntimeRefusal::AttachedTerminalUndelivered`] with the same preserved octets, because
//! this slice establishes no terminal-safety qualification. The `0x1b` predicate is a decision over
//! presented octets alone and is never evidence that any terminal is safe, so an injected `control`
//! grant also never delivers here: a refusal is never a silent control grant. A sink kind Section
//! 46.9 does not declare is refused under `console-safe-output-unsupported` even when its octets
//! carry no control octet.
//!
//! # Flush, shutdown, and end of access
//!
//! Every output instance is borrowed from the access that issued it, so no output instance can
//! outlive its granting access, and no other access can finish, write, or shut down an instance it
//! did not issue. [`ConsoleOutputInstance::finish`] is the one end-of-access route for one bound
//! account: it finalizes through the landed account finalization, so the account leaves the active
//! lifetime once, its carrier value is disposed once, and it admits no later call.
//!
//! The owner that granted the access owns the final flush and the shutdown. Consuming
//! [`ConsoleOutputAccess`] through [`ConsoleOutputAccess::settle_shutdown`] is the only route that
//! publishes a final-flush settlement, and it refuses rather than claims a flush while any bound
//! instance was not finished: omitted, dropped, and failed instances are refused, not ignored. The
//! fixed task outcome is returned by value on every path, success and refusal alike, so a shutdown
//! outcome can never consume, rewrite, represent, or substitute for it.
//!
//! This console retains no octet between calls, so it holds nothing of its own to flush: the flush
//! settlement publishes the completion of empty console-owned state, with no octet count and no
//! caller-supplied verdict. A flush of the carrier belongs to the grantor that owns the carrier:
//! this slice performs no carrier flush and claims neither a carrier flush nor a carrier flush
//! failure.
//!
//! # Non-claims
//!
//! No ambient standard descriptor, terminal handle, terminal capability, or terminal-control
//! authority is created, read, or implied here. No implicit retry, replay, or deduplication exists:
//! one admitted occurrence settles at most once, and a later call needs a new admitted occurrence.
//! `std.console` gains no adapter dependency. This slice introduces no console host-adapter
//! contract, no complete canonical typed signature, and no package-qualified declaration path, all
//! of which Section 46 leaves undeclared. It performs no target-specific work, so it claims no
//! macOS or other target-specific delivery and refuses nothing by target: the same behavior holds
//! on every host this crate builds for, and attached-terminal delivery is undelivered on all of
//! them.
//!
//! Still owed to `GNT-GP-CONSOLE-001`: console input, terminal observation, separately authorized
//! terminal control, physical attached-terminal delivery with a genuine terminal-safety
//! qualification, encoding, resize, and a console host-adapter contract.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use gantry_ir::{
    Charge, ConsoleAccessIdentity, ConsoleAccessInjection, ConsoleCallError, ConsoleFlushOutcome,
    ConsoleGrant, ConsoleOutputTarget, ConsoleRequirementGroup, ConsoleShutdownSettlement,
    ConsoleWriteReceipt, IoError, IoOperation, IoRequest, ObservationAllowance, OwnerGeneration,
    ResourceLifetimeState, admit_console_write,
};

use crate::{
    AdmittedResource, BoundedIoEndpoint, HostResourceError, IoCallBinding, IoCallOutcome,
    IoEvidence, IoHostResponse, IoRefusal, IoSettlementService, Machine, OwnedHostResource,
    ResourceSubjectBinding,
};

/// The grantor-owned console output access of one launch.
///
/// The only constructor presents exactly one launch injection, so the value that owns the injected
/// grant set of `GNT-46.8-console-authority-admission` is its grantor. The value is not cloneable and
/// consuming it through [`Self::settle_shutdown`] is the only route to a final-flush settlement, so
/// a requester route can neither settle shutdown nor outlive the shutdown its grantor settled.
///
/// The access records the one machine occurrence it reserved and counts the output instances it
/// issued. Those records are occurrence identities and counts and no octet, so the access holds no
/// buffered output.
pub struct ConsoleOutputAccess {
    injection: ConsoleAccessInjection,
    reserved: Mutex<Option<ResourceSubjectBinding>>,
    open: AtomicUsize,
}

impl ConsoleOutputAccess {
    /// Mints the grantor-owned access over exactly one launch injection.
    ///
    /// This is the only constructor: access is injected by the launch of
    /// `GNT-30.2-bounded-launch-snapshot-and-capability-closure` and is never reconstructed from an
    /// ambient descriptor, a descriptor number, a process handle, or a device path.
    #[must_use]
    pub fn from_launch(grantor: &'static str, grants: Vec<ConsoleGrant>) -> Self {
        Self {
            injection: ConsoleAccessInjection::from_launch(grantor, grants),
            reserved: Mutex::new(None),
            open: AtomicUsize::new(0),
        }
    }

    /// Returns the injected access set this grantor issued.
    #[must_use]
    pub const fn injection(&self) -> &ConsoleAccessInjection {
        &self.injection
    }

    /// Binds one redirected sink to one admitted account under this grantor.
    ///
    /// The returned instance borrows this access, so it cannot outlive the grantor and no other
    /// access can write, finish, or shut it down. The landed transport linearizes acquisition against
    /// cancellation and refuses an account that is not active and open. A refused bind returns both
    /// owned inputs unchanged and leaves no accounting fact.
    ///
    /// # Errors
    ///
    /// Returns the landed transport refusal with both owned inputs in the returned tuple.
    #[allow(clippy::type_complexity)]
    pub fn bind<T: BoundedIoEndpoint>(
        &self,
        account: AdmittedResource,
        sink: ConsoleRedirectedSink<T>,
    ) -> Result<
        ConsoleOutputInstance<'_, T>,
        Box<(
            HostResourceError,
            AdmittedResource,
            ConsoleRedirectedSink<T>,
        )>,
    > {
        let owner = account.ledger().owner();
        let resource = OwnedHostResource::bind(account, sink)?;
        self.open.fetch_add(1, Ordering::SeqCst);
        Ok(ConsoleOutputInstance {
            resource,
            owner,
            access: self,
            finished: false,
        })
    }

    /// Settles the grantor-owned final flush and returns the fixed task outcome unchanged.
    ///
    /// The fixed task outcome is returned by value on every path, so no flush outcome can consume,
    /// rewrite, represent, or substitute for it. Shutdown settles only when every output instance
    /// this access issued was finished: an omitted, dropped, or failed instance refuses the
    /// settlement instead of being silently abandoned.
    ///
    /// This console retains no octet between calls, so the flush it publishes is the completion of
    /// empty console-owned state, with no octet count and no caller-supplied verdict. The carrier
    /// flush belongs to the grantor that owns the carrier and is neither performed nor claimed here.
    /// Consuming this access ends every requester route of this grantor.
    #[allow(clippy::type_complexity)]
    pub fn settle_shutdown<K>(
        self,
        task_outcome: K,
    ) -> (K, Result<ConsoleShutdownSettlement, ConsoleRuntimeRefusal>) {
        let open = self.open.load(Ordering::SeqCst);
        if open != 0 {
            return (
                task_outcome,
                Err(ConsoleRuntimeRefusal::UnfinishedOutput { count: open }),
            );
        }
        (
            task_outcome,
            Ok(ConsoleShutdownSettlement::settle(
                ConsoleFlushOutcome::Flushed,
            )),
        )
    }

    /// Reserves the presented occurrence atomically for this grantor.
    ///
    /// Returns `false` when this grantor already reserved that exact occurrence, so a second attempt
    /// cannot reach dispatch. An unreadable record refuses conservatively.
    fn reserve(&self, subject: &ResourceSubjectBinding) -> bool {
        match self.reserved.lock() {
            Ok(mut reserved) => {
                if reserved.as_ref() == Some(subject) {
                    return false;
                }
                *reserved = Some(subject.clone());
                true
            }
            Err(_) => false,
        }
    }

    /// Releases a reservation whose attempt dispatched nothing.
    fn release(&self, subject: &ResourceSubjectBinding) {
        if let Ok(mut reserved) = self.reserved.lock()
            && reserved.as_ref() == Some(subject)
        {
            *reserved = None;
        }
    }

    /// Releases a finished instance and refuses an impossible overcount.
    fn close_instance(&self) {
        let _ = self
            .open
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |open| {
                open.checked_sub(1)
            });
    }
}

/// The declared redirected, non-controlling sink of
/// `GNT-46.9-console-control-and-output-boundary`.
///
/// The type is the sink declaration: a carrier becomes console output only by being presented as
/// this sink, so the output target is structural and never a caller-supplied spelling. The sink
/// keeps no octet, performs no second call, and never retries the carrier it wraps. The carrier
/// itself is the requester's own arrangement of
/// `GNT-46.4-console-encoding-and-shutdown-settlement`, not a facility of this slice.
pub struct ConsoleRedirectedSink<T> {
    carrier: T,
}

impl<T> ConsoleRedirectedSink<T> {
    /// Presents one caller-arranged carrier as the redirected, non-controlling sink.
    #[must_use]
    pub const fn new(carrier: T) -> Self {
        Self { carrier }
    }

    /// Returns the declared output target of this sink.
    #[must_use]
    pub const fn target(&self) -> ConsoleOutputTarget {
        ConsoleOutputTarget::RedirectedNonControlling
    }
}

impl<T: BoundedIoEndpoint> BoundedIoEndpoint for ConsoleRedirectedSink<T> {
    /// Performs exactly one call through the caller-arranged carrier and answers that call.
    ///
    /// The carrier's completion is forwarded unchanged and answers the binding it was given, so a
    /// completion of another call, a malformed length, or an over-accepted count stays the landed
    /// settlement service's contained failure rather than this sink's repair.
    fn attempt(&mut self, call: &IoCallBinding, provided: &[u8]) -> IoHostResponse {
        self.carrier.attempt(call, provided)
    }
}

/// One redirected console sink bound to one admitted account and one granting access.
///
/// The instance borrows its granting [`ConsoleOutputAccess`], so the two cannot be separated: no
/// other access can write, finish, or shut down this output, and no instance outlives the grantor.
/// The landed transport authenticates the pending occurrence's operation identity, resource
/// generation, owner generation, and receiver kind when the one call borrows its receiver loan, and
/// the sink type fixes the declared output target.
pub struct ConsoleOutputInstance<'a, T> {
    resource: OwnedHostResource<ConsoleRedirectedSink<T>>,
    owner: OwnerGeneration,
    access: &'a ConsoleOutputAccess,
    finished: bool,
}

impl<T: BoundedIoEndpoint> ConsoleOutputInstance<'_, T> {
    /// Returns immutable accounting facts only, never the bound carrier.
    #[must_use]
    pub const fn account(&self) -> &AdmittedResource {
        self.resource.account()
    }

    /// Returns the declared output target this instance was bound as.
    #[must_use]
    pub const fn target(&self) -> ConsoleOutputTarget {
        ConsoleOutputTarget::RedirectedNonControlling
    }

    /// Finalizes this account once through the landed account finalization.
    ///
    /// The account leaves the active lifetime once, its carrier value is handed to the finalizer and
    /// disposed once, and no later call is admitted. This console performs no carrier flush, so the
    /// finalizer is the empty completion of console-owned state. A refused finalization keeps this
    /// instance, so its cleanup ownership stays with the caller and shutdown refuses until it is
    /// resolved.
    ///
    /// # Errors
    ///
    /// Returns [`ConsoleRuntimeRefusal::AlreadyFinished`] for a second finish and
    /// [`ConsoleRuntimeRefusal::Transport`] when the landed finalization refuses or fails.
    pub fn finish(
        &mut self,
        settled_at_us: u64,
    ) -> Result<ResourceLifetimeState, ConsoleRuntimeRefusal> {
        if self.finished {
            return Err(ConsoleRuntimeRefusal::AlreadyFinished);
        }
        let state = self
            .resource
            .finish(self.owner, settled_at_us, |_sink| Ok(()))
            .map_err(ConsoleRuntimeRefusal::Transport)?;
        self.finished = true;
        self.access.close_instance();
        Ok(state)
    }
}

/// One presented console output sink of a `std.console::output::write@1` call.
pub enum ConsoleOutputSink<'s, 'a, T> {
    /// A redirected, non-controlling sink bound to one admitted account: the delivered target.
    Redirected(&'s mut ConsoleOutputInstance<'a, T>),
    /// The declared attached terminal, which this slice does not deliver.
    AttachedTerminal,
    /// A sink kind `GNT-46.9-console-control-and-output-boundary` does not declare.
    Unsupported(&'static str),
}

impl<T> ConsoleOutputSink<'_, '_, T> {
    /// Returns the declared output target this presentation names.
    #[must_use]
    pub const fn target(&self) -> ConsoleOutputTarget {
        match self {
            Self::Redirected(_) => ConsoleOutputTarget::RedirectedNonControlling,
            Self::AttachedTerminal => ConsoleOutputTarget::AttachedTerminal,
            Self::Unsupported(sink) => ConsoleOutputTarget::Unsupported(sink),
        }
    }
}

/// One admitted console write: its declaration-layer admission and its one settlement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleWriteCall {
    admission: ConsoleWriteReceipt,
    outcome: IoCallOutcome,
}

impl ConsoleWriteCall {
    /// Returns the declaration-layer receipt of the admitted write.
    ///
    /// The receipt counts every presented octet the declaration boundary admitted to this sink. It
    /// is not an accepted-octet count of the delivery: the octet count the sink actually accepted is
    /// the settlement's accepted prefix, which is smaller for a short write.
    #[must_use]
    pub const fn admission(&self) -> ConsoleWriteReceipt {
        self.admission
    }

    /// Returns the one settlement, failure, cancellation, block, or refusal of this call.
    #[must_use]
    pub const fn outcome(&self) -> &IoCallOutcome {
        &self.outcome
    }

    /// Returns the accepted octet count of the one published settlement.
    ///
    /// Only a settled call publishes an accepted prefix. A cancelled or failed attempt keeps any
    /// accepted octets as protected evidence inside its own settlement and never reports them here
    /// as delivered output, and a refused call publishes no octet at all.
    #[must_use]
    pub fn accepted_prefix(&self) -> Option<u64> {
        match &self.outcome {
            IoCallOutcome::Settled(settlement) => match settlement.evidence() {
                IoEvidence::Write { accepted, .. } => Some(*accepted),
                IoEvidence::NoOctets | IoEvidence::Read { .. } => None,
            },
            IoCallOutcome::Blocked(_)
            | IoCallOutcome::Cancelled(_)
            | IoCallOutcome::Failed(_)
            | IoCallOutcome::Refused(_) => None,
        }
    }
}

/// One refusal of this runtime boundary.
///
/// The first three kinds are the declared refusals this boundary presents, and the fourth is the
/// runtime availability fact this slice states honestly rather than a declaration diagnostic, so no
/// console diagnostic spelling is minted for it and no clause is restated. The remaining kinds are
/// landed transport, end-of-access, and duplicate-attempt facts of this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsoleRuntimeRefusal {
    /// A declaration-owned refusal of the `std.console::output::write@1` call itself.
    ///
    /// The declaration model of `GNT-46.8` and `GNT-46.9` decides this refusal, so it names its own
    /// console or Section 45 code and is never relabelled here.
    Authority(ConsoleCallError),
    /// A Section 45 refusal of the one bounded request the call would consume.
    Request(IoError),
    /// A refusal of the landed settlement service before any dispatch.
    Settlement(IoRefusal),
    /// The declared attached terminal is not delivered by this slice.
    ///
    /// No octet is delivered and the presented octets are preserved unchanged.
    AttachedTerminalUndelivered {
        /// The presented octets, unchanged: no octet is stripped, replaced, or sanitized.
        preserved_octets: Vec<u8>,
    },
    /// A landed transport refusal or failure, before dispatch or during finalization.
    Transport(HostResourceError),
    /// A bound output instance was not finished before its grantor settled shutdown.
    UnfinishedOutput {
        /// The count of instances this access issued that were never finished.
        count: usize,
    },
    /// This output instance already finished.
    AlreadyFinished,
}

impl fmt::Display for ConsoleRuntimeRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Request(error) => write!(
                formatter,
                "the presented std.io request was refused under {}",
                error.code().wire_name()
            ),
            Self::Settlement(refusal) => write!(
                formatter,
                "the landed settlement service refused admission: {refusal:?}"
            ),
            Self::AttachedTerminalUndelivered { preserved_octets } => write!(
                formatter,
                "attached-terminal delivery is not delivered by this slice; {} presented octets are preserved undelivered",
                preserved_octets.len()
            ),
            Self::Transport(error) => {
                write!(formatter, "the landed transport refused: {error:?}")
            }
            Self::UnfinishedOutput { count } => write!(
                formatter,
                "{count} bound output instance(s) were not finished before shutdown"
            ),
            Self::AlreadyFinished => {
                write!(formatter, "this output instance already finished")
            }
        }
    }
}

impl std::error::Error for ConsoleRuntimeRefusal {}

/// One requester route presenting a `std.console::output::write@1` call.
///
/// The route admits its access identity once, when it is built, and admits exactly one bounded
/// request per call. It publishes no flush route: the final flush belongs to the grantor-owned
/// access of `GNT-46.8-console-authority-admission` alone.
pub struct ConsoleOutputSettlement<'a> {
    access: &'a ConsoleOutputAccess,
    grant: ConsoleGrant,
    machine: &'a Machine,
    owner: OwnerGeneration,
    allowance: ObservationAllowance,
    charges: Vec<Charge>,
    settled_at_us: u64,
}

impl<'a> ConsoleOutputSettlement<'a> {
    /// Admits one requester route over one presented access identity.
    ///
    /// The identity is admitted for the `output-flush` group that governs both
    /// `std.console::output::write@1` and `std.console::output::flush@1`. The refusal precedence is
    /// the one `GNT-46.8-console-authority-admission` declares: an ambient numeric descriptor is
    /// classified before any grant comparison, a required group carrying no injected grant is
    /// refused as missing, a grant naming another group is refused as inconsistent, and only then is
    /// a grant the injection did not issue refused as forged. Every refusal precedes any request,
    /// dispatch, charge, or settlement.
    ///
    /// # Errors
    ///
    /// Returns [`ConsoleRuntimeRefusal::Authority`] for every declaration-owned refusal.
    pub fn new(
        access: &'a ConsoleOutputAccess,
        identity: ConsoleAccessIdentity,
        machine: &'a Machine,
        owner: OwnerGeneration,
        allowance: ObservationAllowance,
        charges: Vec<Charge>,
        settled_at_us: u64,
    ) -> Result<Self, ConsoleRuntimeRefusal> {
        let grant = identity
            .admit(access.injection(), ConsoleRequirementGroup::OutputFlush)
            .map_err(|error| ConsoleRuntimeRefusal::Authority(ConsoleCallError::from(error)))?;
        Ok(Self {
            access,
            grant,
            machine,
            owner,
            allowance,
            charges,
            settled_at_us,
        })
    }

    /// Returns the admitted grant this route presents.
    #[must_use]
    pub const fn grant(&self) -> ConsoleGrant {
        self.grant
    }

    /// Presents one output sink with the initialized octets the caller declares.
    ///
    /// The request this call consumes is one admitted request of
    /// `GNT-45.1-bounded-one-call-io-contract` whose declared quantity is the presented octet count,
    /// so a zero-octet write and a write beyond `IO_REQUEST_OCTET_BOUND` are refused before any
    /// dispatch. The declaration boundary of
    /// `GNT-46.9-console-control-and-output-boundary` then decides the presented target, and only a
    /// redirected, non-controlling sink reaches the landed settlement service, which performs
    /// exactly one call and publishes exactly one settlement.
    ///
    /// The occurrence is reserved atomically before dispatch, so a second attempt under this one
    /// grant - through another account, or overlapping - is refused under the landed
    /// `duplicate-settlement` refusal. A reservation is released when the attempt dispatched
    /// nothing, so an unattempted occurrence stays available.
    ///
    /// # Errors
    ///
    /// Returns [`ConsoleRuntimeRefusal::Request`] for a refused request,
    /// [`ConsoleRuntimeRefusal::Authority`] for a declared output-boundary refusal, including the
    /// byte-preserving control-bearing refusal and the unsupported-sink refusal,
    /// [`ConsoleRuntimeRefusal::AttachedTerminalUndelivered`] for the declared attached terminal this
    /// slice does not deliver, and [`ConsoleRuntimeRefusal::Settlement`] when the landed service
    /// refuses admission or this occurrence already settled. Every one of those refusals precedes any
    /// dispatch.
    pub fn write<T: BoundedIoEndpoint>(
        &self,
        sink: ConsoleOutputSink<'_, '_, T>,
        octets: &[u8],
    ) -> Result<ConsoleWriteCall, ConsoleRuntimeRefusal> {
        let quantity = u64::try_from(octets.len()).unwrap_or(u64::MAX);
        let request = IoRequest::write(quantity).map_err(ConsoleRuntimeRefusal::Request)?;
        let admission = admit_console_write(
            self.access.injection(),
            &self.grant,
            &request,
            sink.target(),
            octets,
        )
        .map_err(ConsoleRuntimeRefusal::Authority)?;
        let ConsoleOutputSink::Redirected(instance) = sink else {
            // `admit_console_write` already refuses an undeclared sink, so the only admitted
            // presentation that reaches this arm is the declared attached terminal, which this slice
            // establishes no terminal-safety qualification to deliver.
            return Err(ConsoleRuntimeRefusal::AttachedTerminalUndelivered {
                preserved_octets: octets.to_vec(),
            });
        };
        let subject =
            self.machine
                .pending_resource_subject()
                .ok_or(ConsoleRuntimeRefusal::Settlement(
                    IoRefusal::NoPendingOccurrence,
                ))?;
        if !self.access.reserve(&subject) {
            return Err(ConsoleRuntimeRefusal::Settlement(
                IoRefusal::DuplicateSettlement,
            ));
        }
        let mut service = match IoSettlementService::new(
            self.machine,
            self.owner,
            IoOperation::Write,
            self.allowance,
            self.charges.clone(),
            self.settled_at_us,
        ) {
            Ok(service) => service,
            Err(refusal) => {
                self.access.release(&subject);
                return Err(ConsoleRuntimeRefusal::Settlement(refusal));
            }
        };
        let outcome = service.attempt(&mut instance.resource, request, octets);
        if matches!(&outcome, IoCallOutcome::Refused(_)) {
            self.access.release(&subject);
        }
        Ok(ConsoleWriteCall { admission, outcome })
    }
}

#[cfg(test)]
mod tests;
