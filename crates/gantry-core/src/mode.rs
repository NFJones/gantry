//! Closed semantic execution modes selected before package analysis.
//!
//! Semantic mode is part of the analyzed package and execution identity. It is
//! deliberately distinct from conformance profiles and embedding arrangement.

/// One closed Gantry semantic execution mode.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SemanticMode {
    /// Deterministic source and pure-package execution without host admission.
    Portable,
    /// Capability-backed application execution.
    Application,
    /// Restart-safe execution with durable admission and recovery evidence.
    Durable,
}

impl SemanticMode {
    /// Returns the exact stable wire spelling used in canonical artifacts.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::Application => "application",
            Self::Durable => "durable",
        }
    }

    /// Parses one exact stable semantic-mode spelling.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "portable" => Some(Self::Portable),
            "application" => Some(Self::Application),
            "durable" => Some(Self::Durable),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SemanticMode;

    #[test]
    fn semantic_modes_have_closed_stable_wire_names() {
        for (mode, wire) in [
            (SemanticMode::Portable, "portable"),
            (SemanticMode::Application, "application"),
            (SemanticMode::Durable, "durable"),
        ] {
            assert_eq!(mode.wire_name(), wire);
            assert_eq!(SemanticMode::from_wire_name(wire), Some(mode));
        }
        assert_eq!(SemanticMode::from_wire_name("embedded"), None);
    }
}
