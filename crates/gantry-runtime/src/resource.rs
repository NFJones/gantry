//! Runtime admission of the Section 28 resource-accounting facts.
//!
//! The runtime consumes a resource's owner generation, lifetime, operation state,
//! quotas, liveness roots, and settlement only from the declared durable
//! reconstruction record of `GNT-28.7-durable-resource-reconstruction`. Every
//! admission routes its declared carrier through the model's `admit_resource_carrier`,
//! so an ordinary serialization or ordinary durable-state carrier is refused with
//! `ResourceError::OrdinaryCarrierRefused` before any recorded fact is reconstructed:
//! a resource can never enter the runtime unowned or without a terminal disposition.
//!
//! Semantic release and record retirement stay distinct here. Finishing, poisoning,
//! or emergency release settles the resource's lifetime while every declared quota
//! fact remains observable, and retirement of the retained reconstruction record is
//! refused until every declared liveness root has closed and the retention fence of
//! `GNT-28.8-retention-and-compaction-fences` has expired; host allocation behavior,
//! runtime compaction, and host-resource reconstruction stay outside this model under
//! `GNT-28.10-resource-accounting-non-claims`.
//!
//! This module owns the admission boundary only. It performs no durable or host I/O,
//! decodes no record bytes, and publishes no journal, checkpoint, evaluator, or host
//! behavior; those remain with the durable, recovery, and machine modules.

use gantry_ir::{
    DurableResourceRecord, Quota, QuotaFamily, QuotaOwner, ResourceCarrier, ResourceError,
    ResourceLedger, admit_resource_carrier,
};

/// One resource whose declared accounting facts the runtime has admitted.
///
/// The account is reconstructible only from the declared durable reconstruction
/// record: the ledger is private and [`AdmittedResource::admit`] is the only
/// constructor, so no ordinary carrier can produce a runtime account.
///
/// The account is uniquely owned and deliberately not copyable: it implements no
/// `Clone`, so a second account over one resource's lifetime requires a second admitted
/// reconstruction record of `GNT-28.7-durable-resource-reconstruction`, and
/// `GNT-28.9-retirement-deletion-and-stale-owner-fences` admits a genuinely later
/// owner only through a distinct declared resource record.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmittedResource {
    ledger: ResourceLedger,
}

impl AdmittedResource {
    /// Admits one durable reconstruction record presented under its declared carrier.
    ///
    /// The carrier is admitted first through the model's `admit_resource_carrier`: an
    /// ordinary serialization or ordinary durable-state carrier is refused with
    /// `ResourceError::OrdinaryCarrierRefused`, and the record is dropped unread. Only
    /// the declared reconstruction record reconstructs the account's ledger.
    pub fn admit(
        carrier: ResourceCarrier,
        record: DurableResourceRecord,
    ) -> Result<Self, ResourceError> {
        admit_resource_carrier(carrier)?;
        Ok(Self {
            ledger: ResourceLedger::reconstruct(record),
        })
    }

    /// Returns the reconstructed accounting ledger of this resource.
    #[must_use]
    pub fn ledger(&self) -> &ResourceLedger {
        &self.ledger
    }

    /// Returns the reconstructed accounting ledger for owner-authorized changes.
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut ResourceLedger {
        &mut self.ledger
    }

    /// Returns one declared quota of this resource by its closed owner and family.
    #[must_use]
    pub fn quota(&self, owner: QuotaOwner, family: QuotaFamily) -> Option<Quota> {
        self.ledger.quota(owner, family)
    }

    /// Returns the declared ceiling minus the committed logical use of one quota.
    ///
    /// This is exactly the logical headroom of that quota: a charge against the key
    /// is admitted by the quota while the committed use stays within the ceiling, and
    /// refused with `ResourceError::QuotaExhausted` once it would exceed it. A charge
    /// still requires a lifetime that admits charging. `None` means the closed
    /// owner/family key is undeclared for this resource.
    #[must_use]
    pub fn remaining(&self, owner: QuotaOwner, family: QuotaFamily) -> Option<u64> {
        self.ledger
            .quota(owner, family)
            .map(|quota| quota.limit().saturating_sub(quota.used()))
    }

    /// Captures the current declared facts as a durable reconstruction record.
    ///
    /// The captured record is exactly the model's `durable_record` output, so a
    /// runtime checkpoint can only publish facts the admitted account actually holds.
    #[must_use]
    pub fn durable_record(&self) -> DurableResourceRecord {
        self.ledger.durable_record()
    }
}
