//! Affine process-local host ownership over one admitted accounting account.
//!
//! This synchronous boundary reuses host unwind containment. It neither grants host authority
//! nor places handles in logical values, hook bytes, snapshots or reconstruction records.

use gantry_host::containment::{
    AdapterPoison, BoundaryFailure, catch_integration, drop_integration,
};
use gantry_host::contracts::HostError;
use gantry_ir::{
    EmergencyCleanupWitness, LiveResource, LivenessRoot, OperationAbiError, OperationSettlement,
    OwnerGeneration, ProgressObservation, ProgressRecord, ResourceError, ResourceLifetimeState,
    ResourceState,
};

use crate::AdmittedResource;

/// Failure at a process-local resource boundary, without panic payload disclosure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostResourceError {
    /// Accounting owner or lifetime refused the transition before host invocation.
    Model(ResourceError),
    /// The host value has already been disposed.
    Disposed,
    /// Integration invocation or destruction panicked, poisoning this boundary.
    Boundary(BoundaryFailure),
    /// The integration returned an operational error, not a portable domain result.
    Host(HostError),
    /// Pending machine work or an unreadable admission lease prevents transfer.
    PendingOperation,
    /// An outstanding declared loan prevents ownership transfer.
    LoanOutstanding,
    /// Historical containment has not reached its single settlement.
    ContainmentPending,
    /// A bound adapter needs a separately governed substitution contract.
    AdapterBound,
    /// A poisoned transport cannot be transferred back into service.
    TransportPoisoned,
    /// The supplied receiver loan does not name this account's exact subject and owner.
    ForeignLoan,
    /// Receiver-loan admission requires an existing declared loan root.
    MissingLoanRoot,
    /// The Section 20 loan's observation or settlement was refused.
    Operation(OperationAbiError),
    /// This receiver loan already accepted its settlement.
    LoanSettled,
    /// The requested Rust transport type differs from the attached physical value.
    TypeMismatch,
    /// No accounting account exists for the requested subject.
    UnknownSubject,
    /// A portable identity matches, but the issuing execution or task does not.
    ForeignSubject,
    /// A physical slot was already attached, including a disposed slot.
    AlreadyAttached,
    /// This account has no attached physical slot.
    NotAttached,
    /// Physical disposal is already owned by another in-flight cleanup.
    DisposalPending,
    /// Machine cancellation prevents acquiring a new physical value for this account.
    CancellationRequested,
}

/// One unclonable host value bound to one consumed accounting account.
///
/// Callbacks must be bounded and synchronous; this type supplies no scheduler, async
/// cancellation, authority admission, source transfer or durable host reconstruction.
pub struct OwnedHostResource<T> {
    account: AdmittedResource,
    value: Option<T>,
    poison: AdapterPoison,
    loan_pending: bool,
}

impl<T> OwnedHostResource<T> {
    /// Binds an active account, returning both owned inputs untouched on refusal.
    ///
    /// The caller is responsible for authenticating the host value's association with this
    /// account and granting its authority. This constructor does not discover a host resource.
    pub fn bind(
        account: AdmittedResource,
        value: T,
    ) -> Result<Self, Box<(HostResourceError, AdmittedResource, T)>> {
        let lifetime = account.ledger().lifetime();
        if lifetime != ResourceLifetimeState::Active {
            return Err(Box::new((
                HostResourceError::Model(ResourceError::LifetimeDoesNotAdmitCharge {
                    state: lifetime,
                }),
                account,
                value,
            )));
        }
        Ok(Self {
            account,
            value: Some(value),
            poison: AdapterPoison::default(),
            loan_pending: false,
        })
    }

    /// Returns immutable accounting facts only, never the host value.
    #[must_use]
    pub const fn account(&self) -> &AdmittedResource {
        &self.account
    }

    /// Reports whether this transport boundary has been poisoned by an integration panic.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_poisoned()
    }

    /// Consumes this affine owner and advances accounting ownership without copying the value.
    ///
    /// Pending work, loans, unsettled containment, bound adapters and poisoned transport refuse
    /// before mutation. Historical containment remains settled under its original owner. Refusal
    /// returns the complete owner; success preserves subject, quota, roots and physical identity.
    pub fn transfer(
        mut self,
        owner: OwnerGeneration,
        successor: OwnerGeneration,
    ) -> Result<Self, Box<(HostResourceError, Self)>> {
        if let Err(error) = self.require_owner(owner) {
            return Err(Box::new((error, self)));
        }
        if self.loan_pending {
            return Err(Box::new((HostResourceError::LoanOutstanding, self)));
        }
        if self.is_poisoned() {
            return Err(Box::new((HostResourceError::TransportPoisoned, self)));
        }
        if self.value.is_none() {
            return Err(Box::new((HostResourceError::Disposed, self)));
        }
        if let Err(error) = self.account.transfer_owner(owner, successor) {
            return Err(Box::new((error, self)));
        }
        Ok(self)
    }

    /// Exclusively borrows the host value for an exact, unsettled Section 20 receiver loan.
    ///
    /// Admission consumes the model handle, returning it on refusal. The retained pending flag
    /// also fences reuse if the guard is forgotten; abandonment does not fabricate settlement.
    pub fn borrow_receiver(
        &mut self,
        live: LiveResource,
    ) -> Result<HostReceiverLoan<'_, T>, Box<(HostResourceError, LiveResource)>> {
        if let Err(error) = self.require_owner(live.owner()) {
            return Err(Box::new((error, live)));
        }
        let error = if self.loan_pending {
            Some(HostResourceError::LoanOutstanding)
        } else if self.is_poisoned() {
            Some(HostResourceError::TransportPoisoned)
        } else if self.value.is_none() {
            Some(HostResourceError::Disposed)
        } else if self.account.ledger().lifetime() != ResourceLifetimeState::Active
            || !self.account.ledger().operation_state().is_open()
        {
            Some(HostResourceError::Model(
                ResourceError::IllegalLifetimeTransition,
            ))
        } else if !self
            .account
            .ledger()
            .liveness_roots()
            .contains(&LivenessRoot::Loan)
        {
            Some(HostResourceError::MissingLoanRoot)
        } else if live.operation() != self.account.subject().operation()
            || live.generation() != self.account.subject().generation()
            || live.site() != self.account.subject().site()
            || !live.ownership().is_borrowed_loan()
            || live.settlement().is_some()
            || live.fenced().is_some()
            || !live.state().is_open()
        {
            Some(HostResourceError::ForeignLoan)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(Box::new((error, live)));
        }
        self.loan_pending = true;
        Ok(HostReceiverLoan {
            resource: self,
            live,
            settled: false,
        })
    }

    /// Invokes bounded synchronous integration code under current-owner and active-lifetime fences.
    ///
    /// An operational error is returned without rollback or implicit retry. A panic poisons
    /// this boundary but does not fabricate accounting poisoning evidence.
    pub fn invoke<R>(
        &mut self,
        owner: OwnerGeneration,
        invoke: impl FnOnce(&mut T) -> Result<R, HostError>,
    ) -> Result<R, HostResourceError> {
        if let Err(error) = self.require_owner(owner) {
            return self.refuse_callback(invoke, error);
        }
        if self.loan_pending {
            return self.refuse_callback(invoke, HostResourceError::LoanOutstanding);
        }
        let lifetime = self.account.ledger().lifetime();
        if lifetime != ResourceLifetimeState::Active
            || !self.account.ledger().operation_state().is_open()
        {
            return self.refuse_callback(
                invoke,
                HostResourceError::Model(ResourceError::LifetimeDoesNotAdmitCharge {
                    state: lifetime,
                }),
            );
        }
        let Some(value) = self.value.as_mut() else {
            return self.refuse_callback(invoke, HostResourceError::Disposed);
        };
        invoke_contained(&self.poison, value, invoke)
    }

    /// Finalizes once, recording Finished only after callback and contained disposal succeed.
    ///
    /// Failure leaves Finishing observable and cannot be retried through this method. Sealed
    /// emergency cleanup remains available; no accepted external effect is rolled back.
    pub fn finish(
        &mut self,
        owner: OwnerGeneration,
        settled_at: u64,
        finalize: impl FnOnce(&mut T) -> Result<(), HostError>,
    ) -> Result<ResourceLifetimeState, HostResourceError> {
        if self.loan_pending {
            return self.refuse_callback(finalize, HostResourceError::LoanOutstanding);
        }
        if let Err(error) = self.account.begin_finish_for(owner) {
            return self.refuse_callback(finalize, HostResourceError::Model(error));
        }
        let Some(value) = self.value.as_mut() else {
            return self.refuse_callback(finalize, HostResourceError::Disposed);
        };
        invoke_contained(&self.poison, value, finalize)?;
        self.dispose()?;
        self.account
            .complete_finalization_for(owner, settled_at)
            .map_err(HostResourceError::Model)
    }

    /// Settles sealed emergency release before attempting contained physical disposal.
    ///
    /// A disposal panic cannot undo the accounting release. A refused settlement leaves the
    /// host value held, while consuming the single-use cleanup witness.
    pub fn emergency_release(
        &mut self,
        cleanup: EmergencyCleanupWitness,
    ) -> Result<ResourceLifetimeState, HostResourceError> {
        let lifetime = self
            .account
            .settle_from_emergency_cleanup(cleanup)
            .map_err(HostResourceError::Model)?;
        self.loan_pending = false;
        self.dispose()?;
        Ok(lifetime)
    }

    /// Checks current ownership without changing accounting or invoking integration code.
    fn require_owner(&self, presented: OwnerGeneration) -> Result<(), HostResourceError> {
        let current = self.account.ledger().owner();
        if presented != current {
            return Err(HostResourceError::Model(ResourceError::StaleOwner {
                presented,
                current,
            }));
        }
        Ok(())
    }

    /// Removes the physical value before contained destruction so it cannot be destroyed twice.
    fn dispose(&mut self) -> Result<(), HostResourceError> {
        drop_integration(&self.poison, &mut self.value).map_err(HostResourceError::Boundary)
    }

    /// Contains disposal of an unused callback; destruction failure takes precedence over refusal.
    fn refuse_callback<C, R>(
        &self,
        callback: C,
        error: HostResourceError,
    ) -> Result<R, HostResourceError> {
        drop_integration(&self.poison, &mut Some(callback)).map_err(HostResourceError::Boundary)?;
        Err(error)
    }
}

/// Exclusive process-local access tied to one exact borrowed receiver's settlement.
///
/// This guard is neither cloneable nor serializable. Its model handle is observable only by
/// immutable borrow. Dropping an unsettled guard poisons transport and retains the reuse fence.
pub struct HostReceiverLoan<'a, T> {
    resource: &'a mut OwnedHostResource<T>,
    live: LiveResource,
    settled: bool,
}

impl<T> HostReceiverLoan<'_, T> {
    /// Returns immutable progress, identity and settlement evidence for this receiver loan.
    #[must_use]
    pub const fn live(&self) -> &LiveResource {
        &self.live
    }

    /// Observes progress under the model's exact finite observation allowance.
    pub fn observe(
        &mut self,
        progress: ProgressObservation,
    ) -> Result<ProgressRecord, HostResourceError> {
        if self.settled {
            return Err(HostResourceError::LoanSettled);
        }
        self.live
            .observe(progress)
            .map_err(HostResourceError::Operation)
    }

    /// Invokes bounded integration code without releasing the receiver loan.
    pub fn invoke<R>(
        &mut self,
        callback: impl FnOnce(&mut T) -> Result<R, HostError>,
    ) -> Result<R, HostResourceError> {
        if self.settled {
            return self
                .resource
                .refuse_callback(callback, HostResourceError::LoanSettled);
        }
        if !self.live.state().is_open() || self.live.fenced().is_some() {
            return self
                .resource
                .refuse_callback(callback, HostResourceError::ForeignLoan);
        }
        let Some(value) = self.resource.value.as_mut() else {
            return self
                .resource
                .refuse_callback(callback, HostResourceError::Disposed);
        };
        invoke_contained(&self.resource.poison, value, callback)
    }

    /// Accepts one model settlement, projects its state, and releases the declared loan root.
    ///
    /// A refused candidate retains the loan and all prior progress for another settlement attempt.
    /// This does not settle whole-resource lifetime, release machine work, or dispose the host value.
    pub fn settle(
        &mut self,
        candidate: &OperationSettlement,
    ) -> Result<ResourceState, HostResourceError> {
        if self.settled {
            return Err(HostResourceError::LoanSettled);
        }
        self.live
            .settle(candidate)
            .map_err(HostResourceError::Operation)?;
        // Exact subject/owner and the loan root were checked on admission. This guard's exclusive
        // borrow prevents account changes before settlement, so projection and closure must succeed.
        let state = self
            .resource
            .account
            .settle_receiver_loan(&self.live)
            .unwrap_or_else(|_| {
                unreachable!("exclusive admitted loan retains its subject, owner and root")
            });
        self.resource.loan_pending = false;
        self.settled = true;
        Ok(state)
    }
}

impl<T> Drop for HostReceiverLoan<'_, T> {
    /// Abandonment fences reuse without claiming a model settlement or releasing its loan root.
    fn drop(&mut self) {
        if !self.settled {
            self.resource.poison.poison();
        }
    }
}

/// Registry-held physical ownership, kept separate from serializable accounting facts.
pub(crate) struct HostValueSlot {
    value: Option<Box<dyn std::any::Any + Send>>,
    poison: AdapterPoison,
    disposal: std::sync::Arc<std::sync::Mutex<DisposalState>>,
}

/// Process-local cleanup status shared with the private unlocked disposal job.
#[derive(Clone, Copy, Debug)]
enum DisposalState {
    Ready,
    Pending,
    Complete(Result<(), BoundaryFailure>),
}

/// Exclusive physical cleanup extracted without moving or duplicating accounting ownership.
pub(crate) struct HostDisposalJob {
    value: Option<Box<dyn std::any::Any + Send>>,
    poison: AdapterPoison,
    disposal: std::sync::Arc<std::sync::Mutex<DisposalState>>,
}

impl HostDisposalJob {
    /// Contains destruction and publishes its status without acquiring the coordinator mutex.
    pub(crate) fn run(mut self) -> Result<(), HostResourceError> {
        self.complete().map_err(HostResourceError::Boundary)
    }

    /// Completes exactly once, including if this private job is abandoned.
    fn complete(&mut self) -> Result<(), BoundaryFailure> {
        let mut state = self
            .disposal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let DisposalState::Complete(result) = *state {
            return result;
        }
        // Do not hold any status or coordinator lock while integration destruction executes.
        drop(state);
        let result = drop_integration(&self.poison, &mut self.value);
        state = self
            .disposal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *state = DisposalState::Complete(result);
        result
    }
}

impl Drop for HostDisposalJob {
    /// Retains exclusive cleanup even if the internal caller abandons its extracted job.
    fn drop(&mut self) {
        let _ = self.complete();
    }
}

impl std::fmt::Debug for HostValueSlot {
    /// Reports only transport state, never host value contents or identity.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostValueSlot")
            .field("poisoned", &self.poison.is_poisoned())
            .field("present", &self.value.is_some())
            .finish()
    }
}

impl HostValueSlot {
    /// Consumes one physical value without deriving authority or a durable representation.
    pub(crate) fn new<T: std::any::Any + Send>(value: T) -> Self {
        Self {
            value: Some(Box::new(value)),
            poison: AdapterPoison::default(),
            disposal: std::sync::Arc::new(std::sync::Mutex::new(DisposalState::Ready)),
        }
    }

    /// Reports physical presence without exposing host identity or contents.
    pub(crate) fn is_present(&self) -> bool {
        self.value.is_some() || matches!(self.disposal_state(), DisposalState::Pending)
    }

    /// Retains failed destruction independently of physical presence or later disposal attempts.
    pub(crate) fn disposal_failed(&self) -> bool {
        matches!(self.disposal_state(), DisposalState::Complete(Err(_)))
    }

    /// Reads a status projection without exposing physical ownership.
    fn disposal_state(&self) -> DisposalState {
        *self
            .disposal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Contains unused callback destruction, including type or accounting refusals.
    pub(crate) fn refuse<C, R>(
        &self,
        callback: C,
        error: HostResourceError,
    ) -> Result<R, HostResourceError> {
        drop_integration(&self.poison, &mut Some(callback)).map_err(HostResourceError::Boundary)?;
        Err(error)
    }

    /// Invokes the exact attached Rust type through the existing synchronous containment owner.
    pub(crate) fn invoke<T: std::any::Any + Send, R>(
        &mut self,
        callback: impl FnOnce(&mut T) -> Result<R, HostError>,
    ) -> Result<R, HostResourceError> {
        if self.value.is_none() {
            return self.refuse(callback, HostResourceError::Disposed);
        }
        let Some(value) = self
            .value
            .as_mut()
            .and_then(|value| value.downcast_mut::<T>())
        else {
            return self.refuse(callback, HostResourceError::TypeMismatch);
        };
        invoke_contained(&self.poison, value, callback)
    }

    /// Removes the value before contained destruction; no second disposal can execute it.
    pub(crate) fn dispose(&mut self) -> Result<(), HostResourceError> {
        self.extract_disposal()?
            .map_or(Ok(()), HostDisposalJob::run)
    }

    /// Marks cleanup pending before removing physical ownership for unlocked destruction.
    pub(crate) fn extract_disposal(
        &mut self,
    ) -> Result<Option<HostDisposalJob>, HostResourceError> {
        let mut state = self
            .disposal
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match *state {
            DisposalState::Pending => return Err(HostResourceError::DisposalPending),
            DisposalState::Complete(result) => {
                return result.map(|()| None).map_err(HostResourceError::Boundary);
            }
            DisposalState::Ready => {}
        }
        *state = DisposalState::Pending;
        Ok(Some(HostDisposalJob {
            value: self.value.take(),
            poison: self.poison.clone(),
            disposal: std::sync::Arc::clone(&self.disposal),
        }))
    }
}

impl Drop for HostValueSlot {
    /// Contains physical cleanup only, without synthesizing accounting settlement.
    fn drop(&mut self) {
        let _ = self.dispose();
    }
}

/// Contains callbacks rejected before an attached transport slot can be selected.
pub(crate) fn refuse_unbound_callback<C, R>(
    callback: C,
    error: HostResourceError,
) -> Result<R, HostResourceError> {
    drop_integration(&AdapterPoison::default(), &mut Some(callback))
        .map_err(HostResourceError::Boundary)?;
    Err(error)
}

/// Keeps unused callback ownership outside the poisoned invocation fast path, then disposes it.
fn invoke_contained<T, R>(
    poison: &AdapterPoison,
    value: &mut T,
    callback: impl FnOnce(&mut T) -> Result<R, HostError>,
) -> Result<R, HostResourceError> {
    let mut callback = Some(callback);
    let result = catch_integration(poison, || {
        let callback = callback
            .take()
            .unwrap_or_else(|| unreachable!("callback invoked once"));
        callback(value)
    });
    drop_integration(poison, &mut callback).map_err(HostResourceError::Boundary)?;
    result
        .map_err(HostResourceError::Boundary)?
        .map_err(HostResourceError::Host)
}

impl<T> Drop for OwnedHostResource<T> {
    /// Contains physical disposal only; dropping this wrapper never fabricates semantic finish.
    fn drop(&mut self) {
        let _ = self.dispose();
    }
}
