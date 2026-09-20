//! The automatic source names one edition prelude declares (`GNT-34.4`).
//!
//! The compiler-owned type words that are not prelude members stay compiler-owned. The
//! spellings an enumerated member owns are automatic only while the edition prelude
//! enumerates that member, so an unavailable declared spelling is refused rather than
//! resolved.

use std::collections::BTreeSet;

use gantry_ir::{PRELUDE_BINDINGS, Prelude};

/// The automatic source names one edition prelude declares (`GNT-34.4`).
///
/// Name resolution consults this set, so a declared automatic spelling resolves only while
/// the prelude enumerates the member that owns it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutomaticNames {
    available: BTreeSet<&'static str>,
}

impl AutomaticNames {
    /// Derives the automatic names one declared edition prelude makes available.
    #[must_use]
    pub fn from_prelude(prelude: &Prelude) -> Self {
        Self {
            available: prelude.automatic_spellings(),
        }
    }

    /// Returns the canonical edition's automatic names (`GNT-34.4`).
    #[must_use]
    pub fn canonical() -> Self {
        Self::from_prelude(&Prelude::canonical())
    }

    /// Returns whether one spelling belongs to the closed correspondence of any edition
    /// prelude; a declared spelling this prelude does not enumerate is refused rather than
    /// resolved.
    #[must_use]
    pub fn is_declared(spelling: &str) -> bool {
        PRELUDE_BINDINGS
            .iter()
            .any(|binding| binding.spellings().contains(&spelling))
    }

    /// Returns whether one spelling is automatic under this prelude.
    #[must_use]
    pub fn is_available(&self, spelling: &str) -> bool {
        self.available.contains(spelling)
    }

    /// Returns every automatic spelling this prelude makes available.
    #[must_use]
    pub fn available(&self) -> &BTreeSet<&'static str> {
        &self.available
    }
}
