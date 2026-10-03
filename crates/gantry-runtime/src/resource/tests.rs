//! Storage reclamation regressions independent of semantic resource settlement.

use super::*;

/// Reaping may discard settled storage, never accepted pending or unreadable lease ownership.
#[test]
fn reaping_prunes_closed_leases_and_retains_pending_or_unreadable_work() {
    let closed = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    closed
        .lock()
        .unwrap_or_else(|_| panic!("closed lease"))
        .pending = false;
    let closed_weak = Arc::downgrade(&closed);
    let pending = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    let unreadable = Arc::new(Mutex::new(crate::machine::ResourceOperationLease::open()));
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = unreadable.lock().unwrap_or_else(|_| panic!("lease"));
            panic!("poison fixture lease");
        })
        .is_err()
    );
    let mut registry = ResourceRegistry::new();
    registry.pending_admissions = vec![closed, Arc::clone(&pending), Arc::clone(&unreadable)];
    assert_eq!(registry.pending_operations(), 2);
    assert_eq!(registry.reap_deleted(), 0);
    assert_eq!(registry.pending_admissions.len(), 2);
    assert!(
        closed_weak.upgrade().is_none(),
        "settled reference must be reclaimed without another admission"
    );
    assert!(
        registry
            .pending_admissions
            .iter()
            .any(|lease| Arc::ptr_eq(lease, &pending))
    );
    assert!(
        registry
            .pending_admissions
            .iter()
            .any(|lease| Arc::ptr_eq(lease, &unreadable))
    );
    assert_eq!(registry.pending_operations(), 2);
    assert_eq!(registry.reap_deleted(), 0);
    assert_eq!(registry.pending_admissions.len(), 2);
}
