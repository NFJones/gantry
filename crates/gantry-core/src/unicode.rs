//! Gantry-owned Unicode 16.0.0 properties and deterministic text operations.
//!
//! The tables are generated offline from hash-verified data under
//! `third_party/unicode/16.0.0`. No transitive crate's current Unicode version
//! participates in these results.

include!("generated/unicode.rs");

const HANGUL_S_BASE: u32 = 0xAC00;
const HANGUL_L_BASE: u32 = 0x1100;
const HANGUL_V_BASE: u32 = 0x1161;
const HANGUL_T_BASE: u32 = 0x11A7;
const HANGUL_L_COUNT: u32 = 19;
const HANGUL_V_COUNT: u32 = 21;
const HANGUL_T_COUNT: u32 = 28;
const HANGUL_N_COUNT: u32 = HANGUL_V_COUNT * HANGUL_T_COUNT;
const HANGUL_S_COUNT: u32 = HANGUL_L_COUNT * HANGUL_N_COUNT;

/// One Unicode Script value from the pinned Unicode 16 registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Script(u16);

impl Script {
    /// Returns the four-letter Unicode script alias.
    #[must_use]
    pub fn short_name(self) -> &'static str {
        SCRIPTS[usize::from(self.0)].0
    }

    /// Returns the canonical long Unicode script name.
    #[must_use]
    pub fn long_name(self) -> &'static str {
        SCRIPTS[usize::from(self.0)].1
    }
}

/// Returns whether `value` has Unicode 16 `XID_Start`.
#[must_use]
pub fn is_xid_start(value: char) -> bool {
    in_ranges(value, XID_START)
}

/// Returns whether `value` has Unicode 16 `XID_Continue`.
#[must_use]
pub fn is_xid_continue(value: char) -> bool {
    in_ranges(value, XID_CONTINUE)
}

/// Returns whether `value` has Unicode 16 `Default_Ignorable_Code_Point`.
#[must_use]
pub fn is_default_ignorable(value: char) -> bool {
    in_ranges(value, DEFAULT_IGNORABLE)
}

/// Returns whether `value` has Unicode 16 `White_Space`.
#[must_use]
pub fn is_white_space(value: char) -> bool {
    in_ranges(value, WHITE_SPACE)
}

/// Returns whether `value` is excluded by Gantry's identifier-security rule.
#[must_use]
pub fn is_identifier_security_excluded(value: char) -> bool {
    is_default_ignorable(value)
        || in_ranges(value, JOIN_CONTROL)
        || in_ranges(value, VARIATION_SELECTOR)
        || in_ranges(value, BIDI_CONTROL)
}

/// Returns whether UTS #39 marks `value` as identifier-allowed.
#[must_use]
pub fn is_identifier_allowed(value: char) -> bool {
    in_ranges(value, IDENTIFIER_ALLOWED)
}

/// Returns whether UTS #39 assigns `Recommended` identifier type to `value`.
#[must_use]
pub fn is_identifier_recommended(value: char) -> bool {
    in_ranges(value, IDENTIFIER_RECOMMENDED)
}

/// Returns the primary Unicode Script value for `value`.
#[must_use]
pub fn script(value: char) -> Script {
    let code = value as u32;
    range_value(code, SCRIPT_RANGES)
        .map(Script)
        .unwrap_or_else(|| script_by_short_name("Zzzz"))
}

/// Returns Script_Extensions for `value`, or its primary Script as a singleton.
#[must_use]
pub fn script_extensions(value: char) -> Vec<Script> {
    let code = value as u32;
    if let Some(indices) = range_slice(code, SCRIPT_EXTENSIONS) {
        indices.iter().copied().map(Script).collect()
    } else {
        vec![script(value)]
    }
}

/// Returns whether `value` is already in Unicode Normalization Form C.
#[must_use]
pub fn is_nfc(value: &str) -> bool {
    normalize_nfc(value) == value
}

/// Returns Unicode 16 Normalization Form D.
#[must_use]
pub fn normalize_nfd(value: &str) -> String {
    let mut codes = Vec::new();
    for character in value.chars() {
        decompose(character as u32, &mut codes);
    }
    canonical_order(&mut codes);
    codes_to_string(&codes)
}

/// Returns Unicode 16 Normalization Form C.
#[must_use]
pub fn normalize_nfc(value: &str) -> String {
    let nfd = normalize_nfd(value);
    let mut codes = nfd.chars().map(|value| value as u32).collect::<Vec<_>>();
    canonical_compose(&mut codes);
    codes_to_string(&codes)
}

/// Appends the full locale-independent lowercase mapping for one scalar.
pub fn push_full_lowercase(value: char, output: &mut String) {
    push_mapping(value, FULL_LOWERCASE, output);
}

/// Appends the full locale-independent uppercase mapping for one scalar.
pub fn push_full_uppercase(value: char, output: &mut String) {
    push_mapping(value, FULL_UPPERCASE, output);
}

/// Returns the full locale-independent lowercase mapping for a String.
///
/// This applies Unicode's context-sensitive `Final_Sigma` rule while ignoring
/// intervening `Case_Ignorable` scalars. Locale-specific mappings are not part
/// of Gantry's deterministic String semantics.
#[must_use]
pub fn to_full_lowercase(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let mut output = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        if character == '\u{03A3}'
            && has_cased_before(&characters, index)
            && !has_cased_after(&characters, index)
        {
            output.push('\u{03C2}');
        } else {
            push_full_lowercase(character, &mut output);
        }
    }
    output
}

/// Returns the full locale-independent uppercase mapping for a String.
#[must_use]
pub fn to_full_uppercase(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        push_full_uppercase(character, &mut output);
    }
    output
}

/// Computes the Unicode 16 UTS #39 confusable skeleton.
#[must_use]
pub fn confusable_skeleton(value: &str) -> String {
    let nfd = normalize_nfd(value);
    let mut mapped = String::new();
    for character in nfd.chars() {
        if let Some(mapping) = mapping(character as u32, CONFUSABLES) {
            for code in mapping {
                mapped.push(code_to_char(*code));
            }
        } else {
            mapped.push(character);
        }
    }
    normalize_nfd(&mapped)
}

fn has_cased_before(characters: &[char], index: usize) -> bool {
    characters[..index]
        .iter()
        .rev()
        .copied()
        .find(|character| !in_ranges(*character, CASE_IGNORABLE))
        .is_some_and(|character| in_ranges(character, CASED))
}

fn has_cased_after(characters: &[char], index: usize) -> bool {
    characters[index + 1..]
        .iter()
        .copied()
        .find(|character| !in_ranges(*character, CASE_IGNORABLE))
        .is_some_and(|character| in_ranges(character, CASED))
}

fn in_ranges(value: char, ranges: &[(u32, u32)]) -> bool {
    let code = value as u32;
    ranges
        .binary_search_by(|(start, end)| {
            if code < *start {
                std::cmp::Ordering::Greater
            } else if code > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn range_value(code: u32, ranges: &[(u32, u32, u16)]) -> Option<u16> {
    ranges
        .binary_search_by(|(start, end, _)| {
            if code < *start {
                std::cmp::Ordering::Greater
            } else if code > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|index| ranges[index].2)
}

fn range_slice(code: u32, ranges: &[(u32, u32, &'static [u16])]) -> Option<&'static [u16]> {
    ranges
        .binary_search_by(|(start, end, _)| {
            if code < *start {
                std::cmp::Ordering::Greater
            } else if code > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|index| ranges[index].2)
}

fn script_by_short_name(name: &str) -> Script {
    let index = SCRIPTS
        .binary_search_by_key(&name, |(short, _)| *short)
        .unwrap_or_else(|_| unreachable!("generated script registry includes Unknown"));
    Script(index as u16)
}

fn combining_class(code: u32) -> u8 {
    COMBINING_CLASSES
        .binary_search_by(|(start, end, _)| {
            if code < *start {
                std::cmp::Ordering::Greater
            } else if code > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map_or(0, |index| COMBINING_CLASSES[index].2)
}

fn mapping(code: u32, mappings: &[(u32, &'static [u32])]) -> Option<&'static [u32]> {
    mappings
        .binary_search_by_key(&code, |(source, _)| *source)
        .ok()
        .map(|index| mappings[index].1)
}

fn decompose(code: u32, output: &mut Vec<u32>) {
    let mut stack = vec![code];
    while let Some(current) = stack.pop() {
        if let Some(parts) = hangul_decomposition(current) {
            stack.extend(parts.into_iter().rev());
        } else if let Some(parts) = mapping(current, CANONICAL_DECOMPOSITIONS) {
            stack.extend(parts.iter().rev().copied());
        } else {
            output.push(current);
        }
    }
}

fn hangul_decomposition(code: u32) -> Option<Vec<u32>> {
    let index = code.checked_sub(HANGUL_S_BASE)?;
    if index >= HANGUL_S_COUNT {
        return None;
    }
    let l = HANGUL_L_BASE + index / HANGUL_N_COUNT;
    let v = HANGUL_V_BASE + (index % HANGUL_N_COUNT) / HANGUL_T_COUNT;
    let t = index % HANGUL_T_COUNT;
    if t == 0 {
        Some(vec![l, v])
    } else {
        Some(vec![l, v, HANGUL_T_BASE + t])
    }
}

fn canonical_order(codes: &mut [u32]) {
    for index in 1..codes.len() {
        let class = combining_class(codes[index]);
        if class == 0 {
            continue;
        }
        let mut position = index;
        while position > 0 {
            let previous = combining_class(codes[position - 1]);
            if previous == 0 || previous <= class {
                break;
            }
            codes.swap(position - 1, position);
            position -= 1;
        }
    }
}

fn canonical_compose(codes: &mut Vec<u32>) {
    if codes.is_empty() {
        return;
    }
    let mut starter_index = 0;
    let mut starter = codes[0];
    let mut prior_class = 0;
    let mut index = 1;
    while index < codes.len() {
        let current = codes[index];
        let class = combining_class(current);
        if let Some(composed) = compose(starter, current)
            && (prior_class == 0 || prior_class < class)
        {
            codes[starter_index] = composed;
            starter = composed;
            codes.remove(index);
            continue;
        }
        if class == 0 {
            starter_index = index;
            starter = current;
        }
        prior_class = class;
        index += 1;
    }
}

fn compose(first: u32, second: u32) -> Option<u32> {
    if (HANGUL_L_BASE..HANGUL_L_BASE + HANGUL_L_COUNT).contains(&first)
        && (HANGUL_V_BASE..HANGUL_V_BASE + HANGUL_V_COUNT).contains(&second)
    {
        return Some(
            HANGUL_S_BASE
                + (first - HANGUL_L_BASE) * HANGUL_N_COUNT
                + (second - HANGUL_V_BASE) * HANGUL_T_COUNT,
        );
    }
    if let Some(syllable_index) = first.checked_sub(HANGUL_S_BASE)
        && syllable_index < HANGUL_S_COUNT
        && syllable_index % HANGUL_T_COUNT == 0
        && (HANGUL_T_BASE + 1..HANGUL_T_BASE + HANGUL_T_COUNT).contains(&second)
    {
        return Some(first + second - HANGUL_T_BASE);
    }
    CANONICAL_COMPOSITIONS
        .binary_search_by_key(&(first, second), |(left, right, _)| (*left, *right))
        .ok()
        .map(|index| CANONICAL_COMPOSITIONS[index].2)
}

fn push_mapping(value: char, mappings: &[(u32, &'static [u32])], output: &mut String) {
    if let Some(codes) = mapping(value as u32, mappings) {
        for code in codes {
            output.push(code_to_char(*code));
        }
    } else {
        output.push(value);
    }
}

fn codes_to_string(codes: &[u32]) -> String {
    codes.iter().copied().map(code_to_char).collect()
}

fn code_to_char(code: u32) -> char {
    char::from_u32(code).unwrap_or_else(|| unreachable!("generated Unicode tables contain scalars"))
}

#[cfg(test)]
mod tests {
    use super::{
        UNICODE_VERSION, confusable_skeleton, is_identifier_security_excluded, is_nfc,
        is_white_space, is_xid_continue, is_xid_start, normalize_nfc, push_full_lowercase,
        push_full_uppercase, script, script_extensions,
    };

    #[test]
    fn pinned_properties_cover_unicode_16_boundaries() {
        assert_eq!(UNICODE_VERSION, (16, 0, 0));
        assert!(is_xid_start('A'));
        assert!(is_xid_continue('0'));
        assert!(is_xid_start('\u{105C0}'));
        assert!(!is_xid_start('\u{088F}'));
        assert!(is_white_space('\u{2003}'));
        assert!(is_identifier_security_excluded('\u{200D}'));
    }

    #[test]
    fn normalization_case_scripts_and_skeletons_use_generated_tables() {
        assert_eq!(normalize_nfc("A\u{0300}"), "À");
        assert!(is_nfc("À"));
        assert!(!is_nfc("A\u{0300}"));

        let mut lower = String::new();
        push_full_lowercase('İ', &mut lower);
        assert_eq!(lower, "i\u{0307}");
        let mut upper = String::new();
        push_full_uppercase('ß', &mut upper);
        assert_eq!(upper, "SS");

        assert_eq!(script('A').short_name(), "Latn");
        assert!(
            script_extensions('\u{00B7}')
                .iter()
                .any(|value| value.short_name() == "Latn")
        );
        assert_eq!(confusable_skeleton("раypal"), "paypal");
    }
}
