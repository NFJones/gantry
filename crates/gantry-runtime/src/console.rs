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
//! # One settlement per occurrence
//!
//! A console write consumes one machine-issued occurrence, and `GNT-20` allows one resource
//! generation exactly one settlement. The grantor-owned access records the one occurrence it
//! settled, so a second presentation of that same pending occurrence is refused under the landed
//! `duplicate-settlement` refusal **before any dispatch**, even when it is presented through a
//! separately admitted account or instance. The record is one occurrence identity and no octet: it
//! holds no output, survives no call of its own, and is dropped with the access. A later occurrence
//! is a different identity and is admitted normally, and once the machine advances past a pending
//! occurrence the landed transport refuses a stale account as a foreign subject.
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
//! The owner that granted the access owns the final flush and the shutdown. Consuming
//! [`ConsoleOutputAccess`] through [`ConsoleOutputAccess::settle_shutdown`] is the only route that
//! publishes a final-flush settlement, and it finalizes every bound output account it is handed
//! through the landed account finalization before it publishes anything: the account leaves the
//! active lifetime once, its carrier value is disposed once, and no call is admitted afterwards.
//! A refused finalization refuses the whole shutdown and withholds the flush settlement, so a
//! shutdown failure is never reported as a completed flush.
//!
//! This console retains no octet between calls, so it holds nothing of its own to flush: the flush
//! settlement publishes the completion of console-owned state, which is empty, and carries no octet
//! count. A flush of the carrier belongs to the grantor that owns the carrier: this slice performs
//! no carrier flush, accepts no caller-supplied flush verdict, and claims neither a carrier flush
//! nor a carrier flush failure. The caller's fixed task outcome is returned by value, unchanged,
//! beside the settlement, so a flush can neither rewrite that outcome nor substitute for it.
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
/// The access also records the one machine occurrence it settled. That record is an occurrence
/// identity and no octet, so the access holds no buffered output.
pub struct ConsoleOutputAccess {
    injection: ConsoleAccessInjection,
    settled: Mutex<Option<ResourceSubjectBinding>>,
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
            settled: Mutex::new(None),
        }
    }

    /// Returns the injected access set this grantor issued.
    #[must_use]
    pub const fn injection(&self) -> &ConsoleAccessInjection {
        &self.injection
    }

    /// Settles the grantor-owned final flush after finalizing every bound output account.
    ///
    /// Each presented instance is finalized through the landed account finalization in the order it
    /// is presented: the account leaves the active lifetime once, its carrier value is disposed
    /// once, and it admits no later call. A refused finalization refuses this shutdown and withholds
    /// the flush settlement; instances already finalized stay finalized, and every later instance is
    /// left unchanged.
    ///
    /// This console retains no octet between calls, so the flush it publishes is the completion of
    /// empty console-owned state, with no octet count and no caller-supplied verdict. The carrier
    /// flush belongs to the grantor that owns the carrier and is neither performed nor claimed here.
    /// The fixed task outcome is returned by value and is never rewritten, represented, or
    /// substituted by the settlement. Consuming this access ends every requester route of this
    /// grantor.
    ///
    /// # Errors
    ///
    /// Returns [`ConsoleRuntimeRefusal::Transport`] when a presented account cannot be finalized.
    pub fn settle_shutdown<K, T: BoundedIoEndpoint>(
        self,
        mut instances: Vec<ConsoleOutputInstance<T>>,
        task_outcome: K,
        settled_at_us: u64,
    ) -> Result<(K, ConsoleShutdownSettlement), ConsoleRuntimeRefusal> {
        for instance in &mut instances {
            instance
                .finalize(settled_at_us)
                .map_err(ConsoleRuntimeRefusal::Transport)?;
        }
        Ok((
            task_outcome,
            ConsoleShutdownSettlement::settle(ConsoleFlushOutcome::Flushed),
        ))
    }

    /// Returns whether this grantor already settled the presented occurrence.
    ///
    /// An unreadable record conservatively reports a settlement, so a poisoned record can never
    /// admit a second settlement of one occurrence.
    fn settled(&self, subject: &ResourceSubjectBinding) -> bool {
        match self.settled.lock() {
            Ok(settled) => settled.as_ref() == Some(subject),
            Err(_) => true,
        }
    }

    /// Records the one occurrence this grantor settled.
    fn record_settled(&self, subject: ResourceSubjectBinding) {
        if let Ok(mut settled) = self.settled.lock() {
            *settled = Some(subject);
        }
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

/// One redirected console sink bound to one admitted account.
///
/// The pair is what makes the sink, the account, and the machine-issued occurrence checkable: the
/// landed transport authenticates the pending occurrence's operation identity, resource generation,
/// owner generation, and receiver kind when this instance's one call borrows its receiver loan, and
/// the sink type fixes the declared output target. The fields are private and no route replaces the
/// bound resource, so the association survives every route of this module.
pub struct ConsoleOutputInstance<T> {
    resource: OwnedHostResource<ConsoleRedirectedSink<T>>,
    owner: OwnerGeneration,
}

impl<T: BoundedIoEndpoint> ConsoleOutputInstance<T> {
    /// Binds one redirected sink to one admitted account.
    ///
    /// The landed transport linearizes acquisition against cancellation and refuses an account
    /// that is not active and open. Refusal returns both owned inputs unchanged.
    ///
    /// # Errors
    ///
    /// Returns the landed transport refusal with both owned inputs in the returned tuple.
    pub fn bind(
        account: AdmittedResource,
        sink: ConsoleRedirectedSink<T>,
    ) -> Result<
        Self,
        Box<(
            HostResourceError,
            AdmittedResource,
            ConsoleRedirectedSink<T>,
        )>,
    > {
        let owner = account.ledger().owner();
        Ok(Self {
            resource: OwnedHostResource::bind(account, sink)?,
            owner,
        })
    }

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
    /// The carrier value is handed to the finalizer and disposed; this console performs no carrier
    /// flush, so the finalizer is the empty completion of console-owned state.
    fn finalize(&mut self, settled_at_us: u64) -> Result<ResourceLifetimeState, HostResourceError> {
        self.resource
            .finish(self.owner, settled_at_us, |_sink| Ok(()))
    }
}

/// One presented console output sink of a `std.console::output::write@1` call.
pub enum ConsoleOutputSink<'a, T> {
    /// A redirected, non-controlling sink bound to one admitted account: the delivered target.
    Redirected(&'a mut ConsoleOutputInstance<T>),
    /// The declared attached terminal, which this slice does not deliver.
    AttachedTerminal,
    /// A sink kind `GNT-46.9-console-control-and-output-boundary` does not declare.
    Unsupported(&'static str),
}

impl<T> ConsoleOutputSink<'_, T> {
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
/// The first three kinds are the declared refusals this boundary presents; the fourth is the runtime
/// availability fact this slice states honestly rather than a declaration diagnostic, so no console
/// diagnostic spelling is minted for it and no clause is restated. The fifth is the landed transport
/// refusal or failure of binding and finalization.
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
    /// A second presentation of the one pending occurrence this grantor already settled is refused
    /// under the landed `duplicate-settlement` refusal before any dispatch, whatever account or
    /// instance it is presented through.
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
        sink: ConsoleOutputSink<'_, T>,
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
        if self.access.settled(&subject) {
            return Err(ConsoleRuntimeRefusal::Settlement(
                IoRefusal::DuplicateSettlement,
            ));
        }
        let mut service = IoSettlementService::new(
            self.machine,
            self.owner,
            IoOperation::Write,
            self.allowance,
            self.charges.clone(),
            self.settled_at_us,
        )
        .map_err(ConsoleRuntimeRefusal::Settlement)?;
        let outcome = service.attempt(&mut instance.resource, request, octets);
        if !matches!(&outcome, IoCallOutcome::Refused(_)) {
            self.access.record_settled(subject);
        }
        Ok(ConsoleWriteCall { admission, outcome })
    }
}

#[cfg(test)]
mod tests;
