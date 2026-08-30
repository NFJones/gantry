//! Unwind containment that classifies failures by their originating boundary.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use gantry_host::contracts::HostFuture;

/// Origin retained when an unwind reaches a Gantry boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PanicOrigin {
    /// Integration-owned invocation, poll, cancellation, or destruction code.
    Integration,
    /// Gantry implementation code inside an owned task or public operation.
    GantryInvariant,
}

/// Stable panic result that deliberately excludes payload and backtrace text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryFailure {
    /// Boundary origin, independent of where the unwind was caught.
    pub origin: PanicOrigin,
}

impl BoundaryFailure {
    /// Returns the stable protected-diagnostic-safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self.origin {
            PanicOrigin::Integration => "integration-panic",
            PanicOrigin::GantryInvariant => "internal-invariant-failure",
        }
    }
}

/// Monotonic poison state for one configured adapter instance.
#[derive(Clone, Debug, Default)]
pub struct AdapterPoison {
    poisoned: Arc<AtomicBool>,
}

impl AdapterPoison {
    /// Returns whether this adapter instance may no longer be invoked.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Marks the adapter poisoned, returning whether this was the first transition.
    pub fn poison(&self) -> bool {
        !self.poisoned.swap(true, Ordering::AcqRel)
    }
}

/// Invokes integration code under an origin-preserving unwind boundary.
pub fn catch_integration<T>(
    poison: &AdapterPoison,
    invoke: impl FnOnce() -> T,
) -> Result<T, BoundaryFailure> {
    if poison.is_poisoned() {
        return Err(BoundaryFailure {
            origin: PanicOrigin::Integration,
        });
    }
    catch_unwind(AssertUnwindSafe(invoke)).map_err(|_| {
        poison.poison();
        BoundaryFailure {
            origin: PanicOrigin::Integration,
        }
    })
}

/// Invokes Gantry-owned code under the outer public-operation boundary.
pub fn catch_gantry<T>(invoke: impl FnOnce() -> T) -> Result<T, BoundaryFailure> {
    catch_unwind(AssertUnwindSafe(invoke)).map_err(|_| BoundaryFailure {
        origin: PanicOrigin::GantryInvariant,
    })
}

/// Destroys one integration-owned value without permitting its destructor to unwind.
///
/// The value is removed from the caller's slot before destruction so a panicking
/// destructor cannot be invoked a second time. A destructor panic poisons the
/// adapter instance exactly like an invocation or future-poll panic.
pub fn drop_integration<T>(
    poison: &AdapterPoison,
    value: &mut Option<T>,
) -> Result<(), BoundaryFailure> {
    let value = value.take();
    catch_unwind(AssertUnwindSafe(|| drop(value))).map_err(|_| {
        poison.poison();
        BoundaryFailure {
            origin: PanicOrigin::Integration,
        }
    })
}

/// Contains every poll and destruction of one integration-owned future.
pub fn contain_integration_future<'a, T: Send + 'a>(
    future: HostFuture<'a, T>,
    poison: AdapterPoison,
) -> HostFuture<'a, Result<T, BoundaryFailure>> {
    Box::pin(ContainedFuture::new(
        future,
        PanicOrigin::Integration,
        Some(poison),
    ))
}

/// Contains every poll and destruction of one Gantry-owned future.
pub fn contain_gantry_future<'a, T: Send + 'a>(
    future: HostFuture<'a, T>,
) -> HostFuture<'a, Result<T, BoundaryFailure>> {
    Box::pin(ContainedFuture::new(
        future,
        PanicOrigin::GantryInvariant,
        None,
    ))
}

struct ContainedFuture<'a, T> {
    future: Option<HostFuture<'a, T>>,
    origin: PanicOrigin,
    poison: Option<AdapterPoison>,
    complete: bool,
}

impl<'a, T> ContainedFuture<'a, T> {
    fn new(future: HostFuture<'a, T>, origin: PanicOrigin, poison: Option<AdapterPoison>) -> Self {
        Self {
            future: Some(future),
            origin,
            poison,
            complete: false,
        }
    }

    fn failure(&self) -> BoundaryFailure {
        if let Some(poison) = &self.poison {
            poison.poison();
        }
        BoundaryFailure {
            origin: self.origin,
        }
    }

    fn drop_future(&mut self) -> Result<(), BoundaryFailure> {
        let future = self.future.take();
        catch_unwind(AssertUnwindSafe(|| drop(future))).map_err(|_| self.failure())
    }
}

impl<T> Future for ContainedFuture<'_, T> {
    type Output = Result<T, BoundaryFailure>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        assert!(!this.complete, "contained future polled after completion");
        if this.poison.as_ref().is_some_and(AdapterPoison::is_poisoned) {
            this.complete = true;
            let _ = this.drop_future();
            return Poll::Ready(Err(this.failure()));
        }
        let polled = catch_unwind(AssertUnwindSafe(|| {
            this.future
                .as_mut()
                .unwrap_or_else(|| unreachable!("future exists before completion"))
                .as_mut()
                .poll(context)
        }));
        match polled {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => {
                this.complete = true;
                match this.drop_future() {
                    Ok(()) => Poll::Ready(Ok(output)),
                    Err(failure) => Poll::Ready(Err(failure)),
                }
            }
            Err(_) => {
                this.complete = true;
                let failure = this.failure();
                let _ = this.drop_future();
                Poll::Ready(Err(failure))
            }
        }
    }
}

impl<T> Drop for ContainedFuture<'_, T> {
    fn drop(&mut self) {
        let _ = self.drop_future();
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    use super::{
        AdapterPoison, PanicOrigin, catch_gantry, catch_integration, contain_integration_future,
    };

    #[test]
    fn synchronous_boundaries_preserve_origin_and_poison_only_integrations() {
        let poison = AdapterPoison::default();
        let integration = catch_integration(&poison, || panic!("protected payload"));
        assert!(matches!(
            integration,
            Err(failure) if failure.origin == PanicOrigin::Integration
        ));
        assert!(poison.is_poisoned());
        assert!(catch_integration(&poison, || 1).is_err());

        let gantry = catch_gantry(|| panic!("invariant payload"));
        assert!(matches!(
            gantry,
            Err(failure) if failure.origin == PanicOrigin::GantryInvariant
        ));
    }

    #[test]
    fn integration_future_poll_panics_never_escape() {
        let poison = AdapterPoison::default();
        let future = Box::pin(std::future::poll_fn::<(), _>(|_| {
            panic!("protected future payload")
        }));
        let mut contained = contain_integration_future(future, poison.clone());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut contained).poll(&mut context),
            Poll::Ready(Err(failure)) if failure.origin == PanicOrigin::Integration
        ));
        assert!(poison.is_poisoned());
    }
}
