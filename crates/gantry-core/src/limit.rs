//! Explicit finite-or-unlimited resource policy shared across Gantry layers.

use std::fmt;
use std::num::NonZeroU64;

/// One resource ceiling selected by an embedding.
///
/// Unlimited is represented explicitly rather than by zero or a large integer,
/// so configuration identity and durable state cannot confuse absence of a
/// ceiling with a finite policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    /// No semantic ceiling is imposed.
    Unlimited,
    /// The resource is admitted up to and including this positive maximum.
    Limited(NonZeroU64),
}

impl ResourceLimit {
    /// Constructs a positive finite ceiling.
    #[must_use]
    pub const fn limited(maximum: u64) -> Option<Self> {
        match NonZeroU64::new(maximum) {
            Some(maximum) => Some(Self::Limited(maximum)),
            None => None,
        }
    }

    /// Returns the finite maximum, or `None` when the policy is unlimited.
    #[must_use]
    pub const fn maximum(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Limited(maximum) => Some(maximum.get()),
        }
    }

    /// Reports whether an observed count is admitted by this policy.
    #[must_use]
    pub const fn admits(self, observed: u64) -> bool {
        match self {
            Self::Unlimited => true,
            Self::Limited(maximum) => observed <= maximum.get(),
        }
    }
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlimited => formatter.write_str("unlimited"),
            Self::Limited(maximum) => maximum.fmt(formatter),
        }
    }
}
