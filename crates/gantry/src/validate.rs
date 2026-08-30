//! Public syntax-only package activity coordinator.
//!
//! The facade owns activity admission and identity allocation. Frontend code
//! owns source judgments, while `gantry-observe` owns event occurrence metadata
//! and optional delivery settlement.

use std::path::Path;

use gantry_core::event::EventEnvelope;
use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::{IdentityKind, ProtocolFamily};
use gantry_core::protocol::ProtocolSelection;
use gantry_core::source::FrontendLimits;
use gantry_frontend::{CompletedSyntaxPhase, PackageSyntaxError, validate_package_syntax};
use gantry_host::contracts::{
    FreshIdentityAllocator, IdentityAllocationError, IdentitySource, UtcClock,
};
use gantry_host::event::EventDeliveryRuntime;
use gantry_observe::{
    ActivityBarrier, ActivityDeliveryResult, DeliveryError, DeliveryKernel, EventCompleter,
    EventCompletionError, SinkPlan,
};

/// One syntax-only package validation request.
pub struct ValidatePackageRequest<'a> {
    /// Package directory containing `main.gnt`.
    pub package_root: &'a Path,
    /// Exact complete protocol tuple selected for the activity.
    pub protocol_selection: &'a ProtocolSelection,
    /// Finite positive source, token, and diagnostic limits.
    pub frontend_limits: FrontendLimits,
    /// Optional immutable nondurable event sink plan.
    pub event_delivery: Option<&'a SinkPlan>,
}

/// Successful validation result, including the observable parse occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatePackageResult {
    /// Fresh identity allocated before package discovery.
    pub activity_id: ProtocolIdentity,
    /// Deterministic syntax judgment and immutable source evidence.
    pub phase: CompletedSyntaxPhase,
    /// Exactly one completed physical-layer parse event.
    pub event: EventEnvelope,
    /// Optional finite sink settlement and required-sink barrier.
    pub delivery: Option<ActivityDeliveryResult>,
}

/// Operational failure for which no package judgment is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatePackageError {
    /// Activity identity allocation failed before discovery.
    ActivityIdentity(IdentityAllocationError),
    /// Source discovery or syntax processing failed operationally.
    Package(PackageSyntaxError),
    /// Event identity, clock, or envelope completion failed after parsing.
    Event(EventCompletionError),
    /// An event plan was supplied without a delivery runtime.
    MissingDeliveryRuntime,
    /// Event delivery could not reach a finite settlement.
    Delivery(DeliveryError),
    /// A required sink exhausted after the parse occurrence was created.
    RequiredEventDelivery,
}

impl ValidatePackageError {
    /// Returns a stable operational code suitable for CLI and embedding maps.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ActivityIdentity(_) => "identity-generation-failure",
            Self::Package(error) => error.code(),
            Self::Event(EventCompletionError::Identity(_)) => "identity-generation-failure",
            Self::Event(EventCompletionError::Clock(_)) => "executor-failure",
            Self::Event(_) => "internal",
            Self::MissingDeliveryRuntime | Self::Delivery(_) | Self::RequiredEventDelivery => {
                "required-event-delivery-failure"
            }
        }
    }
}

impl std::fmt::Display for ValidatePackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ValidatePackageError {}

/// Stateless composition of frontend and observation services.
pub struct ValidatePackageCoordinator<'a> {
    allocator: &'a FreshIdentityAllocator,
    identity_source: &'a dyn IdentitySource,
    clock: &'a dyn UtcClock,
    delivery_runtime: Option<&'a dyn EventDeliveryRuntime>,
}

impl<'a> ValidatePackageCoordinator<'a> {
    /// Constructs a coordinator without configured event delivery.
    #[must_use]
    pub const fn new(
        allocator: &'a FreshIdentityAllocator,
        identity_source: &'a dyn IdentitySource,
        clock: &'a dyn UtcClock,
    ) -> Self {
        Self {
            allocator,
            identity_source,
            clock,
            delivery_runtime: None,
        }
    }

    /// Supplies the executor-neutral runtime used only when a sink plan exists.
    #[must_use]
    pub const fn with_delivery_runtime(mut self, runtime: &'a dyn EventDeliveryRuntime) -> Self {
        self.delivery_runtime = Some(runtime);
        self
    }

    /// Allocates the activity, validates one immutable package snapshot,
    /// completes one parse occurrence, and settles optional delivery.
    pub async fn validate(
        &self,
        request: ValidatePackageRequest<'_>,
    ) -> Result<ValidatePackageResult, ValidatePackageError> {
        let source_language = request
            .protocol_selection
            .version(ProtocolFamily::SourceLanguage);
        debug_assert_eq!((source_language.major, source_language.minor), (1, 0));
        let activity_id = self
            .allocator
            .allocate(self.identity_source, IdentityKind::Activity)
            .map_err(ValidatePackageError::ActivityIdentity)?;
        let phase = validate_package_syntax(
            request.package_root,
            request.frontend_limits.source_limits(),
        )
        .map_err(ValidatePackageError::Package)?;
        let draft = phase.event_draft().clone();
        let event = EventCompleter::new(self.allocator, self.identity_source, self.clock)
            .complete(activity_id, draft)
            .await
            .map_err(ValidatePackageError::Event)?;
        let delivery = if let Some(plan) = request.event_delivery {
            if plan.registrations().is_empty() {
                Some(ActivityDeliveryResult {
                    barrier: ActivityBarrier::Delivered,
                    settlements: Vec::new(),
                })
            } else {
                let runtime = self
                    .delivery_runtime
                    .ok_or(ValidatePackageError::MissingDeliveryRuntime)?;
                let result = DeliveryKernel::new(self.allocator, self.identity_source, runtime)
                    .deliver(event.clone(), &[], plan)
                    .await
                    .map_err(ValidatePackageError::Delivery)?;
                if matches!(result.barrier, ActivityBarrier::RequiredExhausted { .. }) {
                    return Err(ValidatePackageError::RequiredEventDelivery);
                }
                Some(result)
            }
        } else {
            None
        };
        Ok(ValidatePackageResult {
            activity_id,
            phase,
            event,
            delivery,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};

    use gantry_core::portable::{
        EventLayer, IdentityKind, PORTABLE_SPECIFICATION_REVISION, PROTOCOL_FAMILY_DEFINITIONS,
    };
    use gantry_core::protocol::{ProtocolSelection, ProtocolVersion, SelectedProtocol};
    use gantry_core::source::FrontendLimits;
    use gantry_core::timestamp::UtcTimestamp;
    use gantry_frontend::PackageSyntaxStatus;
    use gantry_host::contracts::{HostError, HostFuture, IdentitySource, UtcClock};

    use super::{ValidatePackageCoordinator, ValidatePackageError, ValidatePackageRequest};
    use crate::host::contracts::FreshIdentityAllocator;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(source: &[u8]) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gantry-validate-package-{}-{suffix}",
                std::process::id()
            ));
            assert!(fs::create_dir(&path).is_ok());
            assert!(fs::write(path.join("main.gnt"), source).is_ok());
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ScriptedIdentitySource(Mutex<VecDeque<Result<[u8; 32], HostError>>>);

    impl IdentitySource for ScriptedIdentitySource {
        fn fresh_material(&self, _kind: IdentityKind) -> Result<[u8; 32], HostError> {
            self.0
                .lock()
                .map_err(|_| failure("identity-state"))?
                .pop_front()
                .unwrap_or_else(|| Err(failure("identity-exhausted")))
        }
    }

    struct FixedClock;

    impl UtcClock for FixedClock {
        fn utc_now<'a>(&'a self) -> HostFuture<'a, Result<UtcTimestamp, HostError>> {
            Box::pin(async { UtcTimestamp::from_unix_seconds(0, 7).map_err(|_| failure("clock")) })
        }
    }

    #[test]
    fn activity_identity_precedes_discovery_and_parse_event_metadata() {
        let root = TempDirectory::new(b"fn main() {}");
        let identities =
            ScriptedIdentitySource(Mutex::new(VecDeque::from([Ok([1; 32]), Ok([2; 32])])));
        let allocator = FreshIdentityAllocator::default();
        let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &FixedClock);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&root.0, &selection)));
        assert!(result.is_ok());
        let result = result.unwrap_or_else(|_| unreachable!("checked above"));
        assert_eq!(result.activity_id.kind(), IdentityKind::Activity);
        assert_eq!(result.event.event_id().kind(), IdentityKind::Event);
        assert_eq!(result.event.activity_id(), result.activity_id);
        assert_eq!(result.event.layer(), EventLayer::Physical);
        assert_eq!(result.phase.status(), PackageSyntaxStatus::Valid);
        assert!(result.event.execution_id().is_none());
    }

    #[test]
    fn identity_failure_returns_before_package_discovery() {
        let missing = std::env::temp_dir().join("gantry-validation-missing-root");
        let identities = ScriptedIdentitySource(Mutex::new(VecDeque::from([Err(failure(
            "identity-source-failure",
        ))])));
        let allocator = FreshIdentityAllocator::default();
        let coordinator = ValidatePackageCoordinator::new(&allocator, &identities, &FixedClock);
        let selection = selection();
        let result = block_on(coordinator.validate(request(&missing, &selection)));
        assert!(matches!(
            result,
            Err(ValidatePackageError::ActivityIdentity(_))
        ));
    }

    fn request<'a>(
        root: &'a std::path::Path,
        selection: &'a ProtocolSelection,
    ) -> ValidatePackageRequest<'a> {
        ValidatePackageRequest {
            package_root: root,
            protocol_selection: selection,
            frontend_limits: FrontendLimits::new(
                32, 1_048_576, 4_194_304, 262_144, 256, 4_194_304, 4_194_304, 4_194_304, 4_194_304,
            )
            .unwrap_or_else(|_| unreachable!("positive limits")),
            event_delivery: None,
        }
    }

    fn selection() -> ProtocolSelection {
        ProtocolSelection::new(
            PORTABLE_SPECIFICATION_REVISION,
            PROTOCOL_FAMILY_DEFINITIONS
                .iter()
                .map(|definition| SelectedProtocol {
                    family: definition.family,
                    version: ProtocolVersion {
                        major: definition.major,
                        minor: definition.minor,
                    },
                })
                .collect(),
        )
        .unwrap_or_else(|_| unreachable!("published selection"))
    }

    fn failure(code: &str) -> HostError {
        HostError {
            code: code.into(),
            protected_diagnostic: None,
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
