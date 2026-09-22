//! The codec foundation of `GNT-42.0-codec-foundation-scope` and
//! `GNT-42.1-versioned-codec-contract`: the declared `std.codec` family with its five modules,
//! the versioned codec identity and its exact admission rule, the frozen refusal vocabulary and
//! its codec categories of `GNT-29.9-codec-contract`, and the separation between application
//! codecs and the sealed canonical boundary and durable recovery projections.
//!
//! The model is pure: it consumes no host codec library, host encoding facility, ambient
//! registry, platform behavior, timing, or global mutable state, and it declares no concrete
//! codec behavior, which each codec's own clause of Section 42 publishes.

use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdlibDiagnosticCode, StdlibError,
};

/// The declared clauses of Section 42, in specification order.
pub const CODEC_CLAUSES: [&str; 2] = [
    "GNT-42.0-codec-foundation-scope",
    "GNT-42.1-versioned-codec-contract",
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
