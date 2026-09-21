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

/// One Unicode 16 `Grapheme_Cluster_Break` value from the pinned data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphemeBreak {
    /// The implicit default every unlisted code point has.
    Other,
    /// Carriage return.
    Cr,
    /// Line feed.
    Lf,
    /// A control code point other than carriage return and line feed.
    Control,
    /// A grapheme-extending code point, including combining marks and variation selectors.
    Extend,
    /// Zero width joiner.
    Zwj,
    /// A regional indicator symbol.
    RegionalIndicator,
    /// A code point that attaches to a following code point.
    Prepend,
    /// A spacing combining mark.
    SpacingMark,
    /// A Hangul leading consonant.
    L,
    /// A Hangul vowel.
    V,
    /// A Hangul trailing consonant.
    T,
    /// A precomposed Hangul syllable without a trailing consonant.
    Lv,
    /// A precomposed Hangul syllable with a trailing consonant.
    Lvt,
}

impl GraphemeBreak {
    /// Returns the pinned Unicode 16 property-value spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        GRAPHEME_BREAK_VALUES[usize::from(Self::index(self))]
    }

    fn index(value: Self) -> u8 {
        match value {
            Self::Other => 0,
            Self::Cr => 1,
            Self::Lf => 2,
            Self::Control => 3,
            Self::Extend => 4,
            Self::Zwj => 5,
            Self::RegionalIndicator => 6,
            Self::Prepend => 7,
            Self::SpacingMark => 8,
            Self::L => 9,
            Self::V => 10,
            Self::T => 11,
            Self::Lv => 12,
            Self::Lvt => 13,
        }
    }

    fn from_index(index: u8) -> Self {
        match index {
            1 => Self::Cr,
            2 => Self::Lf,
            3 => Self::Control,
            4 => Self::Extend,
            5 => Self::Zwj,
            6 => Self::RegionalIndicator,
            7 => Self::Prepend,
            8 => Self::SpacingMark,
            9 => Self::L,
            10 => Self::V,
            11 => Self::T,
            12 => Self::Lv,
            13 => Self::Lvt,
            _ => Self::Other,
        }
    }
}

/// Returns the pinned Unicode 16 `Grapheme_Cluster_Break` value of `value`.
#[must_use]
pub fn grapheme_break(value: char) -> GraphemeBreak {
    GraphemeBreak::from_index(value_range_u8(value as u32, GRAPHEME_BREAK).unwrap_or(0))
}

/// Returns whether Unicode 16 assigns `value` `Extended_Pictographic`.
#[must_use]
pub fn is_extended_pictographic(value: char) -> bool {
    in_ranges(value, EXTENDED_PICTOGRAPHIC)
}

/// One Unicode 16 `Indic_Conjunct_Break` value from the pinned data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IndicConjunctBreak {
    /// The implicit default every unlisted code point has.
    None,
    /// A consonant that can begin an Indic conjunct cluster.
    Consonant,
    /// A code point that extends an Indic conjunct cluster.
    Extend,
    /// A linker that joins the components of an Indic conjunct cluster.
    Linker,
}

impl IndicConjunctBreak {
    /// Returns the pinned Unicode 16 property-value spelling.
    #[must_use]
    pub fn spelling(self) -> &'static str {
        INDIC_CONJUNCT_BREAK_VALUES[usize::from(Self::index(self))]
    }

    fn index(value: Self) -> u8 {
        match value {
            Self::None => 0,
            Self::Consonant => 1,
            Self::Extend => 2,
            Self::Linker => 3,
        }
    }

    fn from_index(index: u8) -> Self {
        match index {
            1 => Self::Consonant,
            2 => Self::Extend,
            3 => Self::Linker,
            _ => Self::None,
        }
    }
}

/// Returns the pinned Unicode 16 `Indic_Conjunct_Break` value of `value`.
#[must_use]
pub fn indic_conjunct_break(value: char) -> IndicConjunctBreak {
    IndicConjunctBreak::from_index(value_range_u8(value as u32, INDIC_CONJUNCT_BREAK).unwrap_or(0))
}

/// Returns the octet offset of every extended grapheme cluster boundary of `value`, in order.
///
/// The boundaries are those of the extended grapheme clusters the pinned Unicode 16.0.0 data and
/// the UAX #29 rules decide: the result always begins at zero and ends at the value's octet length,
/// holds one entry per cluster boundary, and is decided only by the value's own scalar sequence, so
/// segmentation never normalizes, case-maps, or modifies the value. A value holding no scalar has
/// exactly one boundary at zero.
#[must_use]
pub fn grapheme_cluster_boundaries(value: &str) -> Vec<usize> {
    let scalars: Vec<char> = value.chars().collect();
    let mut boundaries = vec![0_usize];
    if scalars.is_empty() {
        return boundaries;
    }
    let mut offsets = Vec::with_capacity(scalars.len());
    let mut offset = 0_usize;
    for scalar in &scalars {
        offsets.push(offset);
        offset += scalar.len_utf8();
    }
    let classes: Vec<GraphemeBreak> = scalars
        .iter()
        .map(|scalar| grapheme_break(*scalar))
        .collect();
    for (index, offset) in offsets.iter().enumerate().skip(1) {
        if is_grapheme_break(&scalars, &classes, index) {
            boundaries.push(*offset);
        }
    }
    boundaries.push(offset);
    boundaries
}

fn is_grapheme_break(scalars: &[char], classes: &[GraphemeBreak], index: usize) -> bool {
    let prior = classes[index - 1];
    let current = classes[index];
    // GB3
    if prior == GraphemeBreak::Cr && current == GraphemeBreak::Lf {
        return false;
    }
    // GB4
    if matches!(
        prior,
        GraphemeBreak::Cr | GraphemeBreak::Lf | GraphemeBreak::Control
    ) {
        return true;
    }
    // GB5
    if matches!(
        current,
        GraphemeBreak::Cr | GraphemeBreak::Lf | GraphemeBreak::Control
    ) {
        return true;
    }
    // GB6
    if prior == GraphemeBreak::L
        && matches!(
            current,
            GraphemeBreak::L | GraphemeBreak::V | GraphemeBreak::Lv | GraphemeBreak::Lvt
        )
    {
        return false;
    }
    // GB7
    if matches!(prior, GraphemeBreak::Lv | GraphemeBreak::V)
        && matches!(current, GraphemeBreak::V | GraphemeBreak::T)
    {
        return false;
    }
    // GB8
    if matches!(prior, GraphemeBreak::Lvt | GraphemeBreak::T) && current == GraphemeBreak::T {
        return false;
    }
    // GB9
    if matches!(current, GraphemeBreak::Extend | GraphemeBreak::Zwj) {
        return false;
    }
    // GB9a
    if current == GraphemeBreak::SpacingMark {
        return false;
    }
    // GB9b
    if prior == GraphemeBreak::Prepend {
        return false;
    }
    // GB9c
    if indic_conjunct_break(scalars[index]) == IndicConjunctBreak::Consonant
        && indic_conjunct_before(scalars, index)
    {
        return false;
    }
    // GB11
    if prior == GraphemeBreak::Zwj
        && is_extended_pictographic(scalars[index])
        && extended_pictographic_before_zwj(scalars, index)
    {
        return false;
    }
    // GB12 and GB13
    if prior == GraphemeBreak::RegionalIndicator && current == GraphemeBreak::RegionalIndicator {
        let mut count = 1_usize;
        let mut cursor = index - 1;
        while cursor > 0 && classes[cursor - 1] == GraphemeBreak::RegionalIndicator {
            count += 1;
            cursor -= 1;
        }
        if count % 2 == 1 {
            return false;
        }
    }
    // GB999
    true
}

/// Returns whether GB9c holds before the conjunct consonant at `index`.
fn indic_conjunct_before(scalars: &[char], index: usize) -> bool {
    let mut cursor = index;
    let mut linker = false;
    while cursor > 0 {
        match indic_conjunct_break(scalars[cursor - 1]) {
            IndicConjunctBreak::Extend => cursor -= 1,
            IndicConjunctBreak::Linker => {
                linker = true;
                cursor -= 1;
            }
            IndicConjunctBreak::Consonant => return linker,
            IndicConjunctBreak::None => return false,
        }
    }
    false
}

/// Returns whether GB11 holds before the code point at `index`, whose predecessor is a ZWJ.
fn extended_pictographic_before_zwj(scalars: &[char], index: usize) -> bool {
    let mut cursor = index - 1;
    while cursor > 0 {
        let prior = scalars[cursor - 1];
        if is_extended_pictographic(prior) {
            return true;
        }
        if grapheme_break(prior) != GraphemeBreak::Extend {
            return false;
        }
        cursor -= 1;
    }
    false
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
    // One backward pass records, for every position, whether the next non-Case_Ignorable scalar
    // after it is Cased; the forward pass carries the same fact for the previous one. The
    // Final_Sigma rule therefore costs a constant number of steps per scalar instead of a scan
    // from every capital sigma.
    let mut after_is_cased = vec![false; characters.len()];
    let mut next_significant_is_cased = false;
    for index in (0..characters.len()).rev() {
        after_is_cased[index] = next_significant_is_cased;
        let character = characters[index];
        if !in_ranges(character, CASE_IGNORABLE) {
            next_significant_is_cased = in_ranges(character, CASED);
        }
    }
    let mut output = String::new();
    let mut before_is_cased = false;
    for (index, character) in characters.iter().copied().enumerate() {
        if character == '\u{03A3}' && before_is_cased && !after_is_cased[index] {
            output.push('\u{03C2}');
        } else {
            push_full_lowercase(character, &mut output);
        }
        if !in_ranges(character, CASE_IGNORABLE) {
            before_is_cased = in_ranges(character, CASED);
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

fn value_range_u8(code: u32, ranges: &[(u32, u32, u8)]) -> Option<u8> {
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
    if codes.len() < 2 {
        return;
    }
    // Canonical ordering is a stable sort of every non-starter segment by
    // `Canonical_Combining_Class`, so a segment is ordered in one pass over its classes rather
    // than by comparing every non-starter with all of its predecessors.
    let mut ordered = Vec::with_capacity(codes.len());
    let mut segment = Vec::new();
    for &code in codes.iter() {
        if combining_class(code) == 0 {
            flush_non_starter_segment(&mut segment, &mut ordered);
            ordered.push(code);
        } else {
            segment.push(code);
        }
    }
    flush_non_starter_segment(&mut segment, &mut ordered);
    codes.copy_from_slice(&ordered);
}

/// Appends one non-starter segment in canonical order: a stable counting sort over the segment's
/// `Canonical_Combining_Class` values, whose distinct values are a small closed set.
fn flush_non_starter_segment(segment: &mut Vec<u32>, ordered: &mut Vec<u32>) {
    if segment.len() < 2 {
        ordered.append(segment);
        return;
    }
    let classes = segment
        .iter()
        .map(|code| combining_class(*code))
        .collect::<Vec<_>>();
    let mut counts = [0_usize; 256];
    for class in classes.iter() {
        counts[usize::from(*class)] += 1;
    }
    let mut starts = [0_usize; 256];
    let mut total = 0_usize;
    for (index, count) in counts.iter().enumerate() {
        starts[index] = total;
        total += count;
    }
    let mut placed = vec![0_u32; segment.len()];
    for (index, code) in segment.iter().enumerate() {
        let class = usize::from(classes[index]);
        placed[starts[class]] = *code;
        starts[class] += 1;
    }
    ordered.extend(placed);
    segment.clear();
}

fn canonical_compose(codes: &mut Vec<u32>) {
    if codes.is_empty() {
        return;
    }
    let mut starter_index = 0;
    let mut starter = codes[0];
    let mut prior_class = 0;
    // Composition writes into one output buffer instead of removing each composed scalar from the
    // input, so no composition shifts the scalars that follow it.
    let mut composed = Vec::with_capacity(codes.len());
    composed.push(codes[0]);
    for &current in codes[1..].iter() {
        let class = combining_class(current);
        if let Some(value) = compose(starter, current)
            && (prior_class == 0 || prior_class < class)
        {
            composed[starter_index] = value;
            starter = value;
            continue;
        }
        if class == 0 {
            starter_index = composed.len();
            starter = current;
        }
        prior_class = class;
        composed.push(current);
    }
    *codes = composed;
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
        is_white_space, is_xid_continue, is_xid_start, normalize_nfc, normalize_nfd,
        push_full_lowercase, push_full_uppercase, script, script_extensions, to_full_lowercase,
    };

    /// The adversarial size is chosen so that the quadratic implementations this module replaced
    /// (an insertion sort per non-starter and a backward scan per capital sigma) could not finish:
    /// 200,000 non-starters mean 2 * 10^10 comparisons under the previous canonical ordering.
    #[test]
    fn canonical_ordering_and_final_sigma_are_linear_in_their_input() {
        const RUN: usize = 200_000;
        let starter = 'A';
        let class_230 = char::from_u32(0x0301).unwrap_or_else(|| panic!("U+0301 is a scalar"));
        let class_220 = char::from_u32(0x0323).unwrap_or_else(|| panic!("U+0323 is a scalar"));
        let capital_sigma = char::from_u32(0x03A3).unwrap_or_else(|| panic!("U+03A3 is a scalar"));
        let small_sigma = char::from_u32(0x03C3).unwrap_or_else(|| panic!("U+03C3 is a scalar"));
        let final_sigma = char::from_u32(0x03C2).unwrap_or_else(|| panic!("U+03C2 is a scalar"));

        let mut input = String::from(starter);
        for _ in 0..RUN / 2 {
            input.push(class_230);
            input.push(class_220);
        }
        let ordered = normalize_nfd(&input);
        assert_eq!(ordered.chars().count(), input.chars().count());
        let classes = ordered
            .chars()
            .skip(1)
            .map(|character| {
                if character == class_220 {
                    220_u32
                } else {
                    230_u32
                }
            })
            .collect::<Vec<_>>();
        assert!(
            classes.windows(2).all(|pair| pair[0] <= pair[1]),
            "the segment is ordered by canonical combining class"
        );

        let marks = class_230.to_string().repeat(RUN);
        let mut trailing = String::from(starter);
        trailing.push_str(&marks);
        trailing.push(capital_sigma);
        assert_eq!(
            to_full_lowercase(&trailing).chars().last(),
            Some(final_sigma)
        );

        let mut leading = String::new();
        leading.push(capital_sigma);
        leading.push_str(&marks);
        leading.push(starter);
        assert_eq!(
            to_full_lowercase(&leading).chars().next(),
            Some(small_sigma)
        );

        // A capital sigma followed by a long Case_Ignorable run is what makes a per-sigma
        // backward scan quadratic; this input repeats that shape 1,000 times.
        let long_run = class_230.to_string().repeat(1_000);
        let mut repeated = String::new();
        for _ in 0..1_000 {
            repeated.push('a');
            repeated.push_str(&long_run);
            repeated.push(capital_sigma);
            repeated.push('1');
        }
        assert_eq!(
            to_full_lowercase(&repeated).matches(final_sigma).count(),
            1_000,
            "every sigma of the repeated shape takes the final form"
        );

        // Composition-heavy input: the previous implementation removed each composed scalar from
        // the middle of its buffer, so 400,000 compositions shifted about 1.6 * 10^11 scalars.
        let composed_character =
            char::from_u32(0x00E1).unwrap_or_else(|| panic!("U+00E1 is a scalar"));
        let mut repeated = String::new();
        for _ in 0..400_000 {
            repeated.push('a');
            repeated.push(class_230);
        }
        let normalized = normalize_nfc(&repeated);
        assert_eq!(normalized.chars().count(), 400_000);
        assert!(
            normalized
                .chars()
                .all(|character| character == composed_character),
            "every base composes with its following mark"
        );
    }

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
