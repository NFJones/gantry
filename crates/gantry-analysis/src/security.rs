//! Unicode 16 identifier-security classification and safe diagnostic fields.

use std::collections::BTreeSet;

use gantry_core::unicode;

/// Security metadata computed from one exact authored identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IdentifierSecurity {
    pub(crate) excluded: bool,
    pub(crate) nfc: bool,
    pub(crate) skeleton: String,
    pub(crate) scripts: Vec<&'static str>,
    pub(crate) recommended_single_script: bool,
    pub(crate) safe_spelling: String,
}

/// Computes all pinned Unicode judgments without normalizing the identifier.
pub(crate) fn classify(value: &str) -> IdentifierSecurity {
    let excluded = value.chars().any(unicode::is_identifier_security_excluded);
    let nfc = unicode::is_nfc(value);
    let skeleton = unicode::confusable_skeleton(value);
    let mut scripts = BTreeSet::new();
    let mut intersection: Option<BTreeSet<&'static str>> = None;
    let mut recommended = true;

    for scalar in value.chars() {
        if scalar == '_' {
            continue;
        }
        recommended &= unicode::is_identifier_recommended(scalar);
        let scalar_scripts = unicode::script_extensions(scalar);
        let significant = scalar_scripts
            .iter()
            .map(|script| script.short_name())
            .filter(|name| !matches!(*name, "Zyyy" | "Zinh" | "Zzzz"))
            .collect::<BTreeSet<_>>();
        scripts.extend(significant.iter().copied());
        if !significant.is_empty() {
            intersection = Some(match intersection {
                None => significant,
                Some(current) => current.intersection(&significant).copied().collect(),
            });
        }
    }

    let recommended_single_script = recommended
        && intersection
            .as_ref()
            .is_none_or(|candidates| !candidates.is_empty());
    IdentifierSecurity {
        excluded,
        nfc,
        skeleton,
        scripts: scripts.into_iter().collect(),
        recommended_single_script,
        safe_spelling: safe_spelling(value),
    }
}

/// Escapes control and formatting scalars so diagnostic fields cannot reorder
/// or hide the authored token when rendered later.
fn safe_spelling(value: &str) -> String {
    let mut output = String::new();
    for scalar in value.chars() {
        if scalar.is_control() || unicode::is_identifier_security_excluded(scalar) {
            if !output.is_empty() {
                output.push(' ');
            }
            output.push_str(&format!("U+{:04X}", scalar as u32));
        } else {
            output.push(scalar);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn classifies_confusable_mixed_script_and_control_identifiers() {
        let mixed = classify("раypal");
        assert_eq!(mixed.skeleton, "paypal");
        assert_eq!(mixed.scripts, ["Cyrl", "Latn"]);
        assert!(!mixed.recommended_single_script);

        let bidi = classify("safe\u{202e}name");
        assert!(bidi.excluded);
        assert!(bidi.safe_spelling.contains("U+202E"));
    }
}
