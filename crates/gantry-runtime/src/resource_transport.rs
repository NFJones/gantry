//! Affine process-local host ownership over one admitted accounting account.
//!
//! This synchronous boundary reuses host unwind containment. It neither grants host authority
//! nor places handles in logical values, hook bytes, snapshots or reconstruction records.

use gantry_host::containment::{
    AdapterPoison, BoundaryFailure, catch_integration, drop_integration,
};
use gantry_host::contracts::HostError;
use gantry_ir::{EmergencyCleanupWitness, OwnerGeneration, ResourceError, ResourceLifetimeState};

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
}

/// One unclonable host value bound to one consumed accounting account.
///
/// Callbacks must be bounded and synchronous; this type supplies no scheduler, async
/// cancellation, authority admission, source transfer or durable host reconstruction.
pub struct OwnedHostResource<T> {
    account: AdmittedResource,
    value: Option<T>,
    poison: AdapterPoison,
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
        let lifetime = self.account.ledger().lifetime();
        if lifetime != ResourceLifetimeState::Active {
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
