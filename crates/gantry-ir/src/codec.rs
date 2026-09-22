//! The codec foundation of `GNT-42.0-codec-foundation-scope`,
//! `GNT-42.1-versioned-codec-contract`, `GNT-42.2-hex-codec`, `GNT-42.3-base64-codec`,
//! `GNT-42.4-binary-endian-readers-and-writers`, `GNT-42.5-bounded-dynamic-json`, and
//! `GNT-42.6-compression-codec`: the declared `std.codec` family with its five modules, the
//! versioned codec identity and its exact admission rule, the frozen refusal vocabulary with its
//! codec categories of `GNT-29.9-codec-contract`, the canonical hex, base64, and binary codecs,
//! the bounded dynamic JSON codec, the declared stored compression codec, and the separation
//! between application codecs and the sealed canonical boundary and durable recovery projections.
//!
//! The model is pure: it consumes no host codec library, host encoding facility, ambient
//! registry, platform behavior, timing, or global mutable state, and the only concrete codec
//! behavior it declares is that of the hex, base64, binary, dynamic JSON, and compression codecs,
//! which `GNT-42.2-hex-codec`, `GNT-42.3-base64-codec`,
//! `GNT-42.4-binary-endian-readers-and-writers`, `GNT-42.5-bounded-dynamic-json`, and
//! `GNT-42.6-compression-codec` publish.

use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdlibDiagnosticCode, StdlibError,
};

/// The declared clauses of Section 42, in specification order.
pub const CODEC_CLAUSES: [&str; 7] = [
    "GNT-42.0-codec-foundation-scope",
    "GNT-42.1-versioned-codec-contract",
    "GNT-42.2-hex-codec",
    "GNT-42.3-base64-codec",
    "GNT-42.4-binary-endian-readers-and-writers",
    "GNT-42.5-bounded-dynamic-json",
    "GNT-42.6-compression-codec",
];

/// The one declared version of every codec in this revision
/// (`GNT-42.1-versioned-codec-contract`).
pub const DECLARED_CODEC_VERSION: u16 = 1;

/// One declared codec of the `std.codec` family (`GNT-42.1-versioned-codec-contract`).
///
/// The declared set is closed and its canonical order ([`CodecKind::ALL`]) is its canonical
/// module name order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CodecKind {
    /// The `std.codec::base64` codec.
    Base64,
    /// The `std.codec::binary` codec.
    Binary,
    /// The `std.codec::compression` codec.
    Compression,
    /// The `std.codec::hex` codec.
    Hex,
    /// The `std.codec::json` codec.
    Json,
}

impl CodecKind {
    /// The closed declared set, in canonical name order.
    pub const ALL: [CodecKind; 5] = [
        Self::Base64,
        Self::Binary,
        Self::Compression,
        Self::Hex,
        Self::Json,
    ];

    /// Returns the wire spelling of this codec (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Binary => "binary",
            Self::Compression => "compression",
            Self::Hex => "hex",
            Self::Json => "json",
        }
    }

    /// Returns the canonical logical module name of this codec
    /// (`GNT-34.1-canonical-hierarchy-and-package-names`).
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Base64 => "std.codec::base64",
            Self::Binary => "std.codec::binary",
            Self::Compression => "std.codec::compression",
            Self::Hex => "std.codec::hex",
            Self::Json => "std.codec::json",
        }
    }

    /// Returns the one declared version identity of this codec
    /// (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub const fn declared_version(self) -> CodecVersion {
        CodecVersion {
            kind: self,
            version: DECLARED_CODEC_VERSION,
        }
    }

    /// Decodes one canonical module name; every other spelling is `None`.
    #[must_use]
    pub fn from_module_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.module_name() == name)
    }
}

/// One selected codec version identity of `GNT-42.1-versioned-codec-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecVersion {
    kind: CodecKind,
    version: u16,
}

impl CodecVersion {
    /// Publishes the one declared version identity of one codec
    /// (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub const fn declared(kind: CodecKind) -> Self {
        kind.declared_version()
    }

    /// Admits exactly one declared codec identity of `GNT-42.1-versioned-codec-contract`.
    ///
    /// The canonical identity spelling is `std.codec::<module>@<version>`. An identity naming an
    /// undeclared codec or an undeclared version is refused under `codec-unsupported-version`,
    /// naming the observed spelling and the declared identity, or the declared set when no
    /// declared codec is named, rather than substituted, upgraded, downgraded, inferred, or
    /// approximated. The presented version text is admitted only when it is exactly the
    /// canonical spelling of the declared version: a parseable variant such as a leading zero
    /// or a sign is refused, never normalized to the declared version.
    pub fn admit(presented: &str) -> Result<Self, CodecError> {
        let Some((module, version)) = presented.rsplit_once('@') else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some(kind) = CodecKind::from_module_name(module) else {
            return Err(Self::undeclared_identity(presented));
        };
        let declared = kind.declared_version();
        if version == DECLARED_CODEC_VERSION.to_string() {
            Ok(declared)
        } else {
            Err(CodecError::new(
                CodecDiagnosticCode::UnsupportedVersion,
                format!(
                    "`{presented}` is not the declared codec identity `{}`",
                    declared.canonical_identity()
                ),
            ))
        }
    }

    /// Publishes the refusal of one identity that names no declared codec
    /// (`GNT-42.1-versioned-codec-contract`).
    fn undeclared_identity(presented: &str) -> CodecError {
        let declared = CodecKind::ALL
            .iter()
            .map(|kind| format!("`{}`", kind.declared_version().canonical_identity()))
            .collect::<Vec<_>>()
            .join(", ");
        CodecError::new(
            CodecDiagnosticCode::UnsupportedVersion,
            format!(
                "`{presented}` names no declared codec identity; the declared identities are {declared}"
            ),
        )
    }

    /// Returns the canonical identity spelling `std.codec::<module>@<version>`
    /// (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub fn canonical_identity(self) -> String {
        format!("{}@{}", self.kind.module_name(), self.version)
    }

    /// Returns the declared codec.
    #[must_use]
    pub const fn kind(self) -> CodecKind {
        self.kind
    }

    /// Returns the declared version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// One codec category of `GNT-29.9-codec-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecCategory {
    /// A decode-side selection refusal (`GNT-29.9-codec-contract`).
    Decode,
    /// An encode-side refusal (`GNT-29.9-codec-contract`).
    Encode,
    /// Input outside a codec's declared admitted language (`GNT-29.9-codec-contract`).
    MalformedInput,
    /// A declared resource or expansion bound (`GNT-29.9-codec-contract`).
    ResourceLimit,
    /// A refusal with no narrower category (`GNT-29.9-codec-contract`).
    Unclassified,
}

impl CodecCategory {
    /// The closed declared set, in canonical wire order.
    pub const ALL: [CodecCategory; 5] = [
        Self::Decode,
        Self::Encode,
        Self::MalformedInput,
        Self::ResourceLimit,
        Self::Unclassified,
    ];

    /// Returns the canonical wire spelling (`GNT-29.9-codec-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Encode => "encode",
            Self::MalformedInput => "malformed-input",
            Self::ResourceLimit => "resource-limit",
            Self::Unclassified => "unclassified",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.wire_name() == name)
    }
}

/// One frozen codec refusal of `GNT-42.1-versioned-codec-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecDiagnosticCode {
    /// An identity naming an undeclared codec or version.
    UnsupportedVersion,
    /// Input outside a codec's declared admitted language.
    MalformedInput,
    /// An operation beyond a codec's declared expansion bound.
    ExpansionLimit,
}

impl CodecDiagnosticCode {
    /// The closed declared set, in canonical spelling order.
    pub const ALL: [CodecDiagnosticCode; 3] = [
        Self::ExpansionLimit,
        Self::MalformedInput,
        Self::UnsupportedVersion,
    ];

    /// Returns the frozen refusal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "codec-unsupported-version",
            Self::MalformedInput => "codec-malformed-input",
            Self::ExpansionLimit => "codec-expansion-limit",
        }
    }

    /// Returns the published meaning of this refusal.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => {
                "An identity naming an undeclared codec or version is refused."
            }
            Self::MalformedInput => {
                "Input outside a codec's declared admitted language is refused."
            }
            Self::ExpansionLimit => {
                "An operation beyond a codec's declared expansion bound is refused."
            }
        }
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-42.1-versioned-codec-contract"
    }

    /// Returns the one codec category this refusal classifies under
    /// (`GNT-29.9-codec-contract`).
    #[must_use]
    pub const fn category(self) -> CodecCategory {
        match self {
            Self::UnsupportedVersion => CodecCategory::Decode,
            Self::MalformedInput => CodecCategory::MalformedInput,
            Self::ExpansionLimit => CodecCategory::ResourceLimit,
        }
    }
}

/// One refusal of the codec foundation (`GNT-42.1-versioned-codec-contract`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodecError {
    code: CodecDiagnosticCode,
    detail: String,
}

impl CodecError {
    /// Publishes one refusal of the named code.
    #[must_use]
    pub fn new(code: CodecDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen refusal code.
    #[must_use]
    pub const fn code(&self) -> CodecDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-42.1-versioned-codec-contract`).
    #[must_use]
    pub fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the one codec category this refusal classifies under
    /// (`GNT-29.9-codec-contract`).
    #[must_use]
    pub fn category(&self) -> CodecCategory {
        self.code.category()
    }
}

/// One declared public item of `std.codec` (`GNT-34.6-stability-tiers`,
/// `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The family declares one module item per declared codec: the canonical lowercase logical path of
/// that codec, classified as a module because a module belongs to exactly one package
/// (`GNT-34.2-name-classification`), at the stable tier the family publishes. `clauses` records
/// the section clauses the item publishes, in specification order, so an item's declared surface
/// cannot drift from the clauses that justify it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecItemRow {
    /// The declared codec this item declares the module of.
    pub kind: CodecKind,
    /// The canonical logical item name (`GNT-34.1-canonical-hierarchy-and-package-names`).
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public items of `std.codec`, one module per declared codec.
///
/// Each name is the canonical logical spelling of the model's own codec spelling
/// ([`CodecKind::module_name`]), so the declared rows are derived from the kind vocabulary rather
/// than restated beside it, and each row lists every section clause that publishes a fact about
/// that codec's surface in specification order.
pub const CODEC_ITEMS: [CodecItemRow; 5] = [
    CodecItemRow {
        kind: CodecKind::Base64,
        name: "std.codec::base64",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-42.0-codec-foundation-scope",
            "GNT-42.1-versioned-codec-contract",
            "GNT-42.3-base64-codec",
        ],
    },
    CodecItemRow {
        kind: CodecKind::Binary,
        name: "std.codec::binary",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-42.0-codec-foundation-scope",
            "GNT-42.1-versioned-codec-contract",
            "GNT-42.4-binary-endian-readers-and-writers",
        ],
    },
    CodecItemRow {
        kind: CodecKind::Compression,
        name: "std.codec::compression",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-42.0-codec-foundation-scope",
            "GNT-42.1-versioned-codec-contract",
            "GNT-42.6-compression-codec",
        ],
    },
    CodecItemRow {
        kind: CodecKind::Hex,
        name: "std.codec::hex",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-42.0-codec-foundation-scope",
            "GNT-42.1-versioned-codec-contract",
            "GNT-42.2-hex-codec",
        ],
    },
    CodecItemRow {
        kind: CodecKind::Json,
        name: "std.codec::json",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-42.0-codec-foundation-scope",
            "GNT-42.1-versioned-codec-contract",
            "GNT-42.5-bounded-dynamic-json",
        ],
    },
];

/// Declares the published item surface of `std.codec` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_codec_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Codec.package_name();
    let (modes, targets) = {
        let package = graph.package(&owner).ok_or_else(|| {
            StdlibError::new(
                StdlibDiagnosticCode::UnknownEdge,
                format!("`{owner}` is not declared, so its item surface cannot be declared"),
            )
        })?;
        (
            package.modes().iter().copied().collect::<Vec<_>>(),
            package.targets().iter().copied().collect::<Vec<_>>(),
        )
    };
    for row in CODEC_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the published item surface of `std.codec` declared
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The family owns this declaration (`GNT-GP-STDLIB-CODEC-001`), so the aggregate constructor
/// `canonical_pure_hierarchy` carries packages, applicability, and edges only while this
/// constructor adds the family's reviewed item rows — and with them the package interface digest
/// of `GNT-34.8` over those items. Composing both in one call keeps a consumer of the family
/// surface from reading the package without its published name level.
pub fn canonical_codec_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_codec_surface(&mut graph)?;
    Ok(graph)
}

/// The declared value bound of `GNT-42.2-hex-codec`: the largest octet count a hex value holds
/// and a hex encode admits.
pub const HEX_VALUE_OCTET_BOUND: usize = 65_536;

/// The declared text bound of `GNT-42.2-hex-codec`: the largest octet count an admitted hex text
/// holds, exactly twice the declared value bound.
pub const HEX_TEXT_OCTET_BOUND: usize = 2 * HEX_VALUE_OCTET_BOUND;

/// Decodes one hex text under the declared admitted language of `GNT-42.2-hex-codec`.
///
/// The admitted language is exactly the sequences of zero or more pairs of lowercase hexadecimal
/// digits, and an admitted text decodes to the octet sequence its digit pairs denote. A text
/// holding more than `HEX_TEXT_OCTET_BOUND` octets is refused under `codec-expansion-limit`
/// before any part of it is examined, and a text outside the declared language is refused under
/// `codec-malformed-input`, naming the zero-based octet index of the first position at which it
/// departs from that language.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, CodecError> {
    if text.len() > HEX_TEXT_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented hex text holds {} octets, beyond the declared bound {HEX_TEXT_OCTET_BOUND}",
                text.len()
            ),
        ));
    }
    let mut octets = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    for (index, octet) in text.as_bytes().iter().enumerate() {
        let Some(digit) = hex_digit_value(*octet) else {
            return Err(hex_malformed_refusal(
                index,
                "the octet is not a lowercase hexadecimal digit",
            ));
        };
        match high.take() {
            None => high = Some(digit),
            Some(first) => octets.push(first * 16 + digit),
        }
    }
    if high.is_some() {
        return Err(hex_malformed_refusal(
            text.len() - 1,
            "the final digit has no paired digit",
        ));
    }
    Ok(octets)
}

/// Encodes one octet sequence under the declared canonical form of `GNT-42.2-hex-codec`.
///
/// Every octet is spelled as exactly two lowercase hexadecimal digits, high digit first. A
/// sequence holding more than `HEX_VALUE_OCTET_BOUND` octets is refused under
/// `codec-expansion-limit`, naming the observed octet count and the declared bound, before any
/// part of a result is constructed.
pub fn hex_encode(octets: &[u8]) -> Result<String, CodecError> {
    if octets.len() > HEX_VALUE_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented octet sequence holds {} octets, beyond the declared bound {HEX_VALUE_OCTET_BOUND}",
                octets.len()
            ),
        ));
    }
    let mut text = String::with_capacity(octets.len() * 2);
    for octet in octets {
        text.push(hex_digit(octet >> 4));
        text.push(hex_digit(octet & 0x0f));
    }
    Ok(text)
}

/// Publishes the refusal of one presented hex text outside the declared language of
/// `GNT-42.2-hex-codec`, naming the zero-based octet index of the departure.
fn hex_malformed_refusal(index: usize, reason: &str) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::MalformedInput,
        format!(
            "the presented hex text departs from the declared hex language at index {index}: {reason}"
        ),
    )
}

/// Returns the value of one lowercase hexadecimal digit octet; every other octet is `None`.
fn hex_digit_value(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet - b'0'),
        b'a'..=b'f' => Some(octet - b'a' + 10),
        _ => None,
    }
}

/// Returns the lowercase hexadecimal digit spelling one value below sixteen.
fn hex_digit(value: u8) -> char {
    if value < 10 {
        char::from(b'0' + value)
    } else {
        char::from(b'a' + value - 10)
    }
}

/// The declared value bound of `GNT-42.3-base64-codec`: the largest octet count a base64 value
/// holds and a base64 encode admits.
pub const BASE64_VALUE_OCTET_BOUND: usize = 65_536;

/// The declared text bound of `GNT-42.3-base64-codec`: four symbols for each complete three-octet
/// quantum plus the canonical final group, which is four times one third of the declared value
/// bound rounded up.
pub const BASE64_TEXT_OCTET_BOUND: usize = 4 * (BASE64_VALUE_OCTET_BOUND + 2) / 3;

/// Decodes one base64 text under the declared admitted language of `GNT-42.3-base64-codec`.
///
/// The admitted language is exactly the canonical padded form over the declared alphabet: zero or
/// more complete four-symbol groups, padding only in the final group and only in the declared
/// counts, and the unused low bits of the final symbol before padding zero. A text holding more
/// than `BASE64_TEXT_OCTET_BOUND` octets is refused under `codec-expansion-limit` before any part
/// of it is examined, and a text outside the declared language is refused under
/// `codec-malformed-input`, naming the zero-based octet index of the first position at which it
/// departs from that language.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, CodecError> {
    if text.len() > BASE64_TEXT_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented base64 text holds {} octets, beyond the declared bound {BASE64_TEXT_OCTET_BOUND}",
                text.len()
            ),
        ));
    }
    let bytes = text.as_bytes();
    let len = bytes.len();

    let mut candidates: Vec<(usize, &'static str)> = Vec::new();
    if let Some(index) = bytes
        .iter()
        .position(|octet| base64_value(*octet).is_none() && *octet != b'=')
    {
        candidates.push((
            index,
            "the octet is outside the declared base64 alphabet and padding spelling",
        ));
    }
    let final_group_start = if len >= 4 && len.is_multiple_of(4) {
        Some(len - 4)
    } else {
        None
    };
    let canonical_final = match final_group_start {
        Some(start) => {
            let group = &bytes[start..];
            let symbols = group.iter().take_while(|octet| **octet != b'=').count();
            let pads = group.len() - symbols;
            group[symbols..].iter().all(|octet| *octet == b'=')
                && matches!((symbols, pads), (4, 0) | (3, 1) | (2, 2))
        }
        None => false,
    };
    if let Some(pad_index) = bytes.iter().position(|octet| *octet == b'=')
        && (!canonical_final || final_group_start.is_some_and(|start| pad_index < start))
    {
        candidates.push((
            pad_index,
            "the padding is not part of a canonical final base64 group",
        ));
    }
    if !len.is_multiple_of(4) {
        candidates.push((
            len,
            "the text ends before its final base64 group is completed",
        ));
    }
    if canonical_final && let Some(start) = final_group_start {
        let symbols = bytes[start..]
            .iter()
            .take_while(|octet| **octet != b'=')
            .count();
        let last_symbol_index = start + symbols - 1;
        let last_value = base64_value(bytes[last_symbol_index]).unwrap_or(0);
        let unused_mask = match symbols {
            3 => 0x03,
            2 => 0x0f,
            _ => 0,
        };
        if last_value & unused_mask != 0 {
            candidates.push((
                last_symbol_index,
                "the final symbol's unused low bits are nonzero",
            ));
        }
    }
    if let Some((index, reason)) = candidates.into_iter().min_by_key(|(index, _)| *index) {
        return Err(base64_malformed_refusal(index, reason));
    }

    let mut octets = Vec::with_capacity(len / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks(4).enumerate() {
        let start = chunk_index * 4;
        let symbols = chunk.iter().take_while(|octet| **octet != b'=').count();
        let mut values = [0_u8; 4];
        for (offset, octet) in chunk.iter().enumerate().take(symbols) {
            let Some(value) = base64_value(*octet) else {
                return Err(base64_malformed_refusal(
                    start + offset,
                    "the octet is outside the declared base64 alphabet",
                ));
            };
            values[offset] = value;
        }
        let [first, second, third, fourth] = values;
        match symbols {
            4 => {
                octets.push((first << 2) | (second >> 4));
                octets.push(((second & 0x0f) << 4) | (third >> 2));
                octets.push(((third & 0x03) << 6) | fourth);
            }
            3 => {
                octets.push((first << 2) | (second >> 4));
                octets.push(((second & 0x0f) << 4) | (third >> 2));
            }
            2 => {
                octets.push((first << 2) | (second >> 4));
            }
            _ => {
                return Err(base64_malformed_refusal(
                    start,
                    "the group is not a declared base64 group",
                ));
            }
        }
    }
    Ok(octets)
}

/// Encodes one octet sequence under the declared canonical form of `GNT-42.3-base64-codec`.
///
/// Each complete three-octet quantum is spelled as four symbols of the declared alphabet, and a
/// final one- or two-octet quantum is spelled as the declared group with its single `=` or `==`.
/// A sequence holding more than `BASE64_VALUE_OCTET_BOUND` octets is refused under
/// `codec-expansion-limit`, naming the observed octet count and the declared bound, before any
/// part of a result is constructed.
pub fn base64_encode(octets: &[u8]) -> Result<String, CodecError> {
    if octets.len() > BASE64_VALUE_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented octet sequence holds {} octets, beyond the declared bound {BASE64_VALUE_OCTET_BOUND}",
                octets.len()
            ),
        ));
    }
    let mut text = String::with_capacity(4 * octets.len().div_ceil(3));
    for chunk in octets.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        text.push(base64_symbol(first >> 2));
        text.push(base64_symbol(((first & 0x03) << 4) | (second >> 4)));
        if chunk.len() > 1 {
            text.push(base64_symbol(((second & 0x0f) << 2) | (third >> 6)));
        } else {
            text.push('=');
        }
        if chunk.len() > 2 {
            text.push(base64_symbol(third & 0x3f));
        } else {
            text.push('=');
        }
    }
    Ok(text)
}

/// Publishes the refusal of one presented base64 text outside the declared language of
/// `GNT-42.3-base64-codec`, naming the zero-based octet index of the departure.
fn base64_malformed_refusal(index: usize, reason: &str) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::MalformedInput,
        format!(
            "the presented base64 text departs from the declared base64 language at index {index}: {reason}"
        ),
    )
}

/// Returns the six-bit value of one declared base64 alphabet octet; every other octet is `None`.
fn base64_value(octet: u8) -> Option<u8> {
    match octet {
        b'A'..=b'Z' => Some(octet - b'A'),
        b'a'..=b'z' => Some(octet - b'a' + 26),
        b'0'..=b'9' => Some(octet - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Returns the declared base64 alphabet spelling of one six-bit value (below sixty-four).
fn base64_symbol(value: u8) -> char {
    if value < 26 {
        char::from(b'A' + value)
    } else if value < 52 {
        char::from(b'a' + value - 26)
    } else if value < 62 {
        char::from(b'0' + value - 52)
    } else if value == 62 {
        '+'
    } else {
        '/'
    }
}

/// The declared value bound of `GNT-42.4-binary-endian-readers-and-writers`: the largest octet
/// count a binary read admits.
pub const BINARY_VALUE_OCTET_BOUND: usize = 65_536;

/// One declared byte order of `GNT-42.4-binary-endian-readers-and-writers`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    /// The most significant octet of the width stands first.
    Big,
    /// The least significant octet of the width stands first.
    Little,
}

impl Endian {
    /// The closed declared set, in canonical wire order.
    pub const ALL: [Endian; 2] = [Self::Big, Self::Little];

    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Big => "big",
            Self::Little => "little",
        }
    }

    /// Decodes one canonical wire spelling; every other spelling is `None`.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|endian| endian.wire_name() == name)
    }
}

/// Publishes the width-octet window of one binary read of
/// `GNT-42.4-binary-endian-readers-and-writers`.
///
/// A sequence holding more than `BINARY_VALUE_OCTET_BOUND` octets is refused under
/// `codec-expansion-limit` before any part of it is examined, and a window the sequence does not
/// wholly hold is refused under `codec-malformed-input`, naming the first zero-based octet index
/// the sequence does not hold — the offset itself when the offset lies beyond the recorded
/// length, and otherwise the recorded length.
fn binary_window(octets: &[u8], offset: usize, width: usize) -> Result<&[u8], CodecError> {
    if octets.len() > BINARY_VALUE_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented octet sequence holds {} octets, beyond the declared bound {BINARY_VALUE_OCTET_BOUND}",
                octets.len()
            ),
        ));
    }
    let end = offset.saturating_add(width);
    if end > octets.len() {
        return Err(binary_malformed_refusal(
            offset,
            width,
            offset.max(octets.len()),
        ));
    }
    Ok(&octets[offset..end])
}

/// Publishes the refusal of one binary read whose window the sequence does not wholly hold.
fn binary_malformed_refusal(offset: usize, width: usize, departure: usize) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::MalformedInput,
        format!(
            "the presented octet sequence does not hold the {width}-octet window at offset {offset}: the first octet index it does not hold is {departure}"
        ),
    )
}

/// Reads one unsigned 16-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
pub fn read_u16(endian: Endian, octets: &[u8], offset: usize) -> Result<u16, CodecError> {
    let window = binary_window(octets, offset, 2)?;
    let bytes = [window[0], window[1]];
    Ok(match endian {
        Endian::Big => u16::from_be_bytes(bytes),
        Endian::Little => u16::from_le_bytes(bytes),
    })
}

/// Reads one unsigned 32-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
pub fn read_u32(endian: Endian, octets: &[u8], offset: usize) -> Result<u32, CodecError> {
    let window = binary_window(octets, offset, 4)?;
    let bytes = [window[0], window[1], window[2], window[3]];
    Ok(match endian {
        Endian::Big => u32::from_be_bytes(bytes),
        Endian::Little => u32::from_le_bytes(bytes),
    })
}

/// Reads one unsigned 64-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
pub fn read_u64(endian: Endian, octets: &[u8], offset: usize) -> Result<u64, CodecError> {
    let window = binary_window(octets, offset, 8)?;
    let bytes = [
        window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
    ];
    Ok(match endian {
        Endian::Big => u64::from_be_bytes(bytes),
        Endian::Little => u64::from_le_bytes(bytes),
    })
}

/// Writes one unsigned 16-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
#[must_use]
pub fn write_u16(endian: Endian, value: u16) -> [u8; 2] {
    match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    }
}

/// Writes one unsigned 32-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
#[must_use]
pub fn write_u32(endian: Endian, value: u32) -> [u8; 4] {
    match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    }
}

/// Writes one unsigned 64-bit value in the declared byte order
/// (`GNT-42.4-binary-endian-readers-and-writers`).
#[must_use]
pub fn write_u64(endian: Endian, value: u64) -> [u8; 8] {
    match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    }
}

/// The declared text bound of `GNT-42.5-bounded-dynamic-json`: the largest octet count an
/// admitted JSON text or an encode result may hold.
pub const JSON_TEXT_OCTET_BOUND: usize = 65_536;

/// The declared node bound of `GNT-42.5-bounded-dynamic-json`: the largest number of values and
/// member keys one dynamic value may hold in total.
pub const JSON_NODE_BOUND: usize = 8_192;

/// The declared depth bound of `GNT-42.5-bounded-dynamic-json`: the largest number of containers
/// a value may nest in.
pub const JSON_DEPTH_BOUND: u32 = 64;

/// One dynamic JSON value of `GNT-42.5-bounded-dynamic-json`.
///
/// An object is the sequence of its members in the order its text presents them, and that order
/// is part of the value; an integer is exactly one value of the signed 64-bit range; and a text
/// is a sequence of Unicode scalar values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    /// The `null` value.
    Null,
    /// A boolean value.
    Bool(bool),
    /// An integer of the signed 64-bit range.
    Integer(i64),
    /// A string value.
    Text(String),
    /// An array of values in sequence order.
    Array(Vec<JsonValue>),
    /// An object: its members in the order its text presents them.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Returns the number of values and member keys this value holds in total.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Array(items) => 1 + items.iter().map(Self::node_count).sum::<usize>(),
            Self::Object(members) => {
                1 + members
                    .iter()
                    .map(|(_, value)| 1 + value.node_count())
                    .sum::<usize>()
            }
            _ => 1,
        }
    }

    /// Returns the number of containers this value nests in.
    #[must_use]
    pub fn container_depth(&self) -> u32 {
        match self {
            Self::Array(items) => 1 + items.iter().map(Self::container_depth).max().unwrap_or(0),
            Self::Object(members) => {
                1 + members
                    .iter()
                    .map(|(_, value)| value.container_depth())
                    .max()
                    .unwrap_or(0)
            }
            _ => 0,
        }
    }
}

/// Decodes one text under the declared compact JSON language of `GNT-42.5-bounded-dynamic-json`.
///
/// The admitted language is exactly the compact canonical form: one value of the declared dynamic
/// model for the whole text, with no insignificant whitespace, no trailing octet, and no second
/// spelling of any admitted value. A text holding more than `JSON_TEXT_OCTET_BOUND` octets, a
/// value holding more than `JSON_NODE_BOUND` values and member keys, and a value nesting more
/// than `JSON_DEPTH_BOUND` containers deep are refused under `codec-expansion-limit`; every other
/// departure from the language is refused under `codec-malformed-input`, naming the zero-based
/// octet index of the first departing position.
pub fn json_decode(text: &str) -> Result<JsonValue, CodecError> {
    if text.len() > JSON_TEXT_OCTET_BOUND {
        return Err(json_octet_refusal("presented JSON text", text.len()));
    }
    let mut parser = JsonParser {
        text,
        bytes: text.as_bytes(),
        index: 0,
        nodes: 0,
    };
    let value = parser.parse_value(0)?;
    if parser.index != parser.bytes.len() {
        return Err(parser.malformed("the value is followed by a further octet"));
    }
    Ok(value)
}

/// Encodes one dynamic value of `GNT-42.5-bounded-dynamic-json` as its canonical compact text.
///
/// A value holding more than `JSON_NODE_BOUND` values and member keys, nesting more than
/// `JSON_DEPTH_BOUND` containers deep, or whose canonical text would hold more than
/// `JSON_TEXT_OCTET_BOUND` octets is refused under `codec-expansion-limit`.
pub fn json_encode(value: &JsonValue) -> Result<String, CodecError> {
    if let Some((position, key)) = json_repeated_key(value) {
        return Err(CodecError::new(
            CodecDiagnosticCode::MalformedInput,
            format!(
                "the presented dynamic value repeats the member key `{key}` at member position {position}"
            ),
        ));
    }
    if value.node_count() > JSON_NODE_BOUND {
        return Err(json_node_refusal(
            "presented dynamic value",
            value.node_count(),
        ));
    }
    if value.container_depth() > JSON_DEPTH_BOUND {
        return Err(json_depth_refusal(
            "presented dynamic value",
            value.container_depth(),
        ));
    }
    let mut text = String::new();
    write_json_value(value, &mut text);
    if text.len() > JSON_TEXT_OCTET_BOUND {
        return Err(json_octet_refusal(
            "canonical text of the presented dynamic value",
            text.len(),
        ));
    }
    Ok(text)
}

/// The scan state of one `json_decode` of `GNT-42.5-bounded-dynamic-json`.
struct JsonParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
    nodes: usize,
}

impl JsonParser<'_> {
    /// Publishes the refusal of one departure at the current octet index.
    fn malformed(&self, reason: &str) -> CodecError {
        json_malformed_refusal(self.index, reason)
    }

    /// Parses one value at the given container depth.
    fn parse_value(&mut self, depth: u32) -> Result<JsonValue, CodecError> {
        self.nodes += 1;
        if self.nodes > JSON_NODE_BOUND {
            return Err(json_node_refusal("presented JSON text", self.nodes));
        }
        let Some(octet) = self.bytes.get(self.index).copied() else {
            return Err(self.malformed("the text ends before its value is complete"));
        };
        match octet {
            b'n' => {
                self.expect_literal("null")?;
                Ok(JsonValue::Null)
            }
            b't' => {
                self.expect_literal("true")?;
                Ok(JsonValue::Bool(true))
            }
            b'f' => {
                self.expect_literal("false")?;
                Ok(JsonValue::Bool(false))
            }
            b'"' => Ok(JsonValue::Text(self.parse_string()?)),
            b'[' => self.parse_array(depth),
            b'{' => self.parse_object(depth),
            b'-' | b'0'..=b'9' => Ok(JsonValue::Integer(self.parse_integer()?)),
            _ => Err(self.malformed("the octet cannot begin a JSON value")),
        }
    }

    /// Consumes one declared literal octet by octet, refusing at the first departure.
    fn expect_literal(&mut self, literal: &str) -> Result<(), CodecError> {
        for (offset, expected) in literal.bytes().enumerate() {
            match self.bytes.get(self.index + offset) {
                Some(octet) if *octet == expected => {}
                Some(_) => {
                    self.index += offset;
                    return Err(self.malformed("the octet does not continue the declared literal"));
                }
                None => {
                    self.index = self.bytes.len();
                    return Err(self.malformed("the text ends before its value is complete"));
                }
            }
        }
        self.index += literal.len();
        Ok(())
    }

    /// Parses one array whose opening `[` stands at the current index.
    fn parse_array(&mut self, depth: u32) -> Result<JsonValue, CodecError> {
        self.index += 1;
        if depth >= JSON_DEPTH_BOUND {
            return Err(json_depth_refusal("presented JSON text", depth + 1));
        }
        let mut items = Vec::new();
        if self.bytes.get(self.index) == Some(&b']') {
            self.index += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            match self.bytes.get(self.index).copied() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    return Ok(JsonValue::Array(items));
                }
                Some(_) => return Err(self.malformed("the octet cannot continue a JSON array")),
                None => return Err(self.malformed("the text ends before its array is complete")),
            }
        }
    }

    /// Parses one object whose opening `{` stands at the current index.
    fn parse_object(&mut self, depth: u32) -> Result<JsonValue, CodecError> {
        self.index += 1;
        if depth >= JSON_DEPTH_BOUND {
            return Err(json_depth_refusal("presented JSON text", depth + 1));
        }
        let mut members: Vec<(String, JsonValue)> = Vec::new();
        if self.bytes.get(self.index) == Some(&b'}') {
            self.index += 1;
            return Ok(JsonValue::Object(members));
        }
        loop {
            let key_index = self.index;
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(self.malformed("a JSON object member requires a string key"));
            }
            let key = self.parse_string()?;
            self.nodes += 1;
            if self.nodes > JSON_NODE_BOUND {
                return Err(json_node_refusal("presented JSON text", self.nodes));
            }
            if members.iter().any(|(present, _)| *present == key) {
                return Err(json_malformed_refusal(
                    key_index,
                    "the key repeats an earlier member of the same JSON object",
                ));
            }
            if self.bytes.get(self.index) != Some(&b':') {
                return Err(self.malformed("a JSON object member requires a colon after its key"));
            }
            self.index += 1;
            let member = self.parse_value(depth + 1)?;
            members.push((key, member));
            match self.bytes.get(self.index).copied() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Ok(JsonValue::Object(members));
                }
                Some(_) => return Err(self.malformed("the octet cannot continue a JSON object")),
                None => return Err(self.malformed("the text ends before its object is complete")),
            }
        }
    }

    /// Parses one canonical string whose opening quote stands at the current index.
    fn parse_string(&mut self) -> Result<String, CodecError> {
        self.index += 1;
        let mut value = String::new();
        loop {
            let Some(octet) = self.bytes.get(self.index).copied() else {
                return Err(self.malformed("the text ends before its string is complete"));
            };
            match octet {
                b'"' => {
                    self.index += 1;
                    return Ok(value);
                }
                b'\\' => self.parse_escape(&mut value)?,
                control if control < 0x20 => {
                    return Err(self
                        .malformed("a raw control octet is not part of a canonical JSON string"));
                }
                _ => {
                    let Some(scalar) = self.text[self.index..].chars().next() else {
                        return Err(self.malformed("the text is not a scalar sequence"));
                    };
                    value.push(scalar);
                    self.index += scalar.len_utf8();
                }
            }
        }
    }

    /// Parses one escape whose backslash stands at the current index.
    fn parse_escape(&mut self, value: &mut String) -> Result<(), CodecError> {
        self.index += 1;
        let Some(octet) = self.bytes.get(self.index).copied() else {
            return Err(self.malformed("the text ends before its escape is complete"));
        };
        let scalar = match octet {
            b'"' => '"',
            b'\\' => '\\',
            b'b' => '\u{0008}',
            b'f' => '\u{000c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.parse_unicode_escape(value),
            _ => {
                return Err(
                    self.malformed("the octet is not part of the canonical JSON escape set")
                );
            }
        };
        self.index += 1;
        value.push(scalar);
        Ok(())
    }

    /// Parses one `\u00xx` escape whose `u` stands at the current index.
    fn parse_unicode_escape(&mut self, value: &mut String) -> Result<(), CodecError> {
        let digits_start = self.index + 1;
        let Some(digits) = self.bytes.get(digits_start..digits_start.saturating_add(4)) else {
            self.index = self.bytes.len();
            return Err(self.malformed("the text ends before its unicode escape is complete"));
        };
        let [first, second, third, fourth] = digits else {
            self.index = self.bytes.len();
            return Err(self.malformed("the text ends before its unicode escape is complete"));
        };
        if *first != b'0' || *second != b'0' {
            self.index = if *first != b'0' {
                digits_start
            } else {
                digits_start + 1
            };
            return Err(self.malformed(
                "a canonical unicode escape denotes U+0000 to U+001F as `\\u00` and two digits",
            ));
        }
        let Some(high) = json_lowercase_hex(*third) else {
            self.index = digits_start + 2;
            return Err(
                self.malformed("a canonical unicode escape uses two lowercase hexadecimal digits")
            );
        };
        let Some(low) = json_lowercase_hex(*fourth) else {
            self.index = digits_start + 3;
            return Err(
                self.malformed("a canonical unicode escape uses two lowercase hexadecimal digits")
            );
        };
        let code = (u32::from(high) << 4) | u32::from(low);
        if code > 0x001f {
            self.index = digits_start + 2;
            return Err(self.malformed("a canonical unicode escape denotes U+0000 to U+001F only"));
        }
        if matches!(code, 0x0008 | 0x0009 | 0x000a | 0x000c | 0x000d) {
            self.index = digits_start + 3;
            return Err(self.malformed(
                "a canonical unicode escape is not used for a scalar that has a shorter escape",
            ));
        }
        let Some(scalar) = char::from_u32(code) else {
            self.index = digits_start + 2;
            return Err(self.malformed("the escape denotes no Unicode scalar value"));
        };
        value.push(scalar);
        self.index = digits_start + 4;
        Ok(())
    }

    /// Parses one canonical integer whose first octet stands at the current index.
    fn parse_integer(&mut self) -> Result<i64, CodecError> {
        let start = self.index;
        let negative = self.bytes.get(self.index) == Some(&b'-');
        if negative {
            self.index += 1;
        }
        let digits_start = self.index;
        let mut value: i64 = 0;
        let mut overflow = false;
        while let Some(octet) = self.bytes.get(self.index).copied() {
            let digit = match octet {
                b'0'..=b'9' => i64::from(octet - b'0'),
                _ => break,
            };
            if self.index == digits_start {
                if digit == 0
                    && self
                        .bytes
                        .get(self.index + 1)
                        .is_some_and(u8::is_ascii_digit)
                {
                    self.index += 1;
                    return Err(
                        self.malformed("a leading zero is not part of a canonical JSON integer")
                    );
                }
                if negative && digit == 0 {
                    return Err(
                        self.malformed("the value zero never carries a sign in canonical JSON")
                    );
                }
            }
            value = match value
                .checked_mul(10)
                .and_then(|scaled| scaled.checked_sub(digit))
            {
                Some(scaled) => scaled,
                None => {
                    overflow = true;
                    break;
                }
            };
            self.index += 1;
        }
        if self.index == digits_start {
            return Err(self.malformed("a JSON integer requires at least one digit"));
        }
        if overflow || (!negative && value == i64::MIN) {
            self.index = start;
            return Err(self.malformed("the integer token lies outside the signed 64-bit range"));
        }
        if negative { Ok(value) } else { Ok(-value) }
    }
}

/// Publishes the refusal of one presented JSON text outside the declared compact language of
/// `GNT-42.5-bounded-dynamic-json`, naming the zero-based octet index of the departure.
fn json_malformed_refusal(index: usize, reason: &str) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::MalformedInput,
        format!(
            "the presented JSON text departs from the declared compact JSON language at index {index}: {reason}"
        ),
    )
}

/// Publishes the refusal of one JSON octet count beyond the declared text bound.
fn json_octet_refusal(subject: &str, observed: usize) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::ExpansionLimit,
        format!(
            "the {subject} holds {observed} octets, beyond the declared bound {JSON_TEXT_OCTET_BOUND}"
        ),
    )
}

/// Publishes the refusal of one JSON node count beyond the declared node bound.
fn json_node_refusal(subject: &str, observed: usize) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::ExpansionLimit,
        format!(
            "the {subject} would hold {observed} values and member keys, beyond the declared bound {JSON_NODE_BOUND}"
        ),
    )
}

/// Publishes the refusal of one JSON container depth beyond the declared depth bound.
fn json_depth_refusal(subject: &str, observed: u32) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::ExpansionLimit,
        format!(
            "the {subject} would nest {observed} containers deep, beyond the declared bound {JSON_DEPTH_BOUND}"
        ),
    )
}

/// Returns the value of one lowercase hexadecimal digit octet; every other octet is `None`.
fn json_lowercase_hex(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet - b'0'),
        b'a'..=b'f' => Some(octet - b'a' + 10),
        _ => None,
    }
}

/// Returns the first repeated member key of one dynamic value in member order, with the
/// zero-based position of the repeating member within its own object.
fn json_repeated_key(value: &JsonValue) -> Option<(usize, String)> {
    match value {
        JsonValue::Array(items) => items.iter().find_map(json_repeated_key),
        JsonValue::Object(members) => {
            for (position, (key, member)) in members.iter().enumerate() {
                if members[..position]
                    .iter()
                    .any(|(present, _)| present == key)
                {
                    return Some((position, key.clone()));
                }
                if let Some(found) = json_repeated_key(member) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// Writes the canonical compact text of one dynamic value.
fn write_json_value(value: &JsonValue, out: &mut String) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Integer(integer) => out.push_str(&integer.to_string()),
        JsonValue::Text(text) => write_json_string(text, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_json_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(members) => {
            out.push('{');
            for (position, (key, member)) in members.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_json_value(member, out);
            }
            out.push('}');
        }
    }
}

/// Writes the canonical escaped form of one string.
fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for scalar in text.chars() {
        match scalar {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < '\u{0020}' => {
                let code = u32::from(control);
                out.push_str(&format!("\\u00{code:02x}"));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The declared value bound of `GNT-42.6-compression-codec`: the largest octet count a stored
/// value may hold.
pub const COMPRESSION_VALUE_OCTET_BOUND: usize = 65_536;

/// The declared encoded bound of `GNT-42.6-compression-codec`: the version octet, the four length
/// octets, and the declared value bound.
pub const COMPRESSION_ENCODED_OCTET_BOUND: usize = COMPRESSION_VALUE_OCTET_BOUND + 5;

/// The one declared algorithm version octet of `GNT-42.6-compression-codec`.
pub const COMPRESSION_ALGORITHM_VERSION: u8 = 0x01;

/// Decodes one stream under the declared stored form of `GNT-42.6-compression-codec`.
///
/// An admitted stream is exactly the declared version octet, the declared decoded length as four
/// unsigned big-endian octets, and exactly that many stored octets. A stream holding more than
/// `COMPRESSION_ENCODED_OCTET_BOUND` octets, and a stream whose declared decoded length exceeds
/// `COMPRESSION_VALUE_OCTET_BOUND` octets, are refused under `codec-expansion-limit` before any
/// part of the stored value is examined, so a short stream that declares an unbounded expansion
/// is refused as an expansion bomb. A stream naming any other version octet is refused under
/// `codec-unsupported-version`, and every other departure is refused under
/// `codec-malformed-input`, naming the zero-based octet index of the first departing position.
pub fn compression_decode(stream: &[u8]) -> Result<Vec<u8>, CodecError> {
    if stream.len() > COMPRESSION_ENCODED_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented compression stream holds {} octets, beyond the declared bound {COMPRESSION_ENCODED_OCTET_BOUND}",
                stream.len()
            ),
        ));
    }
    let Some(version) = stream.first().copied() else {
        return Err(compression_malformed_refusal(
            0,
            "the stream ends before its version octet",
        ));
    };
    if version != COMPRESSION_ALGORITHM_VERSION {
        return Err(CodecError::new(
            CodecDiagnosticCode::UnsupportedVersion,
            format!(
                "the presented compression stream names algorithm version octet {version:#04x}; the declared version octet is {COMPRESSION_ALGORITHM_VERSION:#04x}"
            ),
        ));
    }
    let Some(header) = stream.get(1..5) else {
        return Err(compression_malformed_refusal(
            stream.len(),
            "the stream ends before its length header is complete",
        ));
    };
    let [first, second, third, fourth] = header else {
        return Err(compression_malformed_refusal(
            stream.len(),
            "the stream ends before its length header is complete",
        ));
    };
    let declared = u32::from_be_bytes([*first, *second, *third, *fourth]);
    let length = usize::try_from(declared).unwrap_or(usize::MAX);
    if length > COMPRESSION_VALUE_OCTET_BOUND {
        return Err(CodecError::new(
            CodecDiagnosticCode::ExpansionLimit,
            format!(
                "the presented compression stream declares a stored value of {length} octets, beyond the declared bound {COMPRESSION_VALUE_OCTET_BOUND}"
            ),
        ));
    }
    let payload = stream.get(5..).unwrap_or_default();
    if payload.len() < length {
        return Err(compression_malformed_refusal(
            stream.len(),
            "the stream ends before its stored value is complete",
        ));
    }
    if payload.len() > length {
        return Err(compression_malformed_refusal(
            5 + length,
            "a further octet follows an already complete stored value",
        ));
    }
    Ok(payload.to_vec())
}

/// Encodes one octet sequence into the declared stored form of `GNT-42.6-compression-codec`.
///
/// The published stream is the declared version octet, the input length as four unsigned
/// big-endian octets, and every input octet in order, so it holds exactly five more octets than
/// its input. A sequence holding more than `COMPRESSION_VALUE_OCTET_BOUND` octets is refused
/// under `codec-expansion-limit`, naming the observed octet count and the declared bound, before
/// any part of a result is constructed.
pub fn compression_encode(value: &[u8]) -> Result<Vec<u8>, CodecError> {
    if value.len() > COMPRESSION_VALUE_OCTET_BOUND {
        return Err(compression_value_refusal(value.len()));
    }
    let Ok(length) = u32::try_from(value.len()) else {
        return Err(compression_value_refusal(value.len()));
    };
    let mut stream = Vec::with_capacity(value.len() + 5);
    stream.push(COMPRESSION_ALGORITHM_VERSION);
    stream.extend_from_slice(&length.to_be_bytes());
    stream.extend_from_slice(value);
    Ok(stream)
}

/// Publishes the refusal of one stored value beyond the declared value bound.
fn compression_value_refusal(observed: usize) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::ExpansionLimit,
        format!(
            "the presented octet sequence holds {observed} octets, beyond the declared bound {COMPRESSION_VALUE_OCTET_BOUND}"
        ),
    )
}

/// Publishes the refusal of one compression stream outside the declared stored form.
fn compression_malformed_refusal(index: usize, reason: &str) -> CodecError {
    CodecError::new(
        CodecDiagnosticCode::MalformedInput,
        format!(
            "the presented compression stream departs from the declared stored form at index {index}: {reason}"
        ),
    )
}
