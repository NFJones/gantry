//! The data foundation of `GNT-43.0-data-family-scope` and
//! `GNT-43.1-data-value-model-contract`: the declared `std.data` family with its `http`, `mime`,
//! and `url` modules, the versioned value-model identity and its exact admission rule, the frozen
//! refusal vocabulary with its declared refusal categories, and the separation between these pure
//! value models and the capability-backed network contracts of
//! `GNT-29.6-dns-socket-tls-and-http-contracts`.
//!
//! The model is pure: it performs no network I/O, resolves no name, consults no ambient URL,
//! MIME, character-set, or port registry, and reads no platform parser, platform name resolution,
//! locale, timing, environment, filesystem, or global mutable state. No concrete value model's
//! admitted language is declared here; each value model's own clause publishes its admitted
//! language, canonical form, bounds, refusals, and any round-trip promise.

use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdlibDiagnosticCode, StdlibError,
};

/// The declared clauses of Section 43, in specification order.
pub const DATA_CLAUSES: [&str; 2] = [
    "GNT-43.0-data-family-scope",
    "GNT-43.1-data-value-model-contract",
];

/// The one declared version of every value model in this revision
/// (`GNT-43.1-data-value-model-contract`).
pub const DECLARED_DATA_VERSION: u16 = 1;

/// One declared value model of the `std.data` family (`GNT-43.1-data-value-model-contract`).
///
/// The declared set is closed and its canonical order ([`DataModule::ALL`]) is its canonical
/// module name order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataModule {
    /// The `std.data::http` value model.
    Http,
    /// The `std.data::mime` value model.
    Mime,
    /// The `std.data::url` value model.
    Url,
}

impl DataModule {
    /// The closed declared set, in canonical name order.
    pub const ALL: [DataModule; 3] = [Self::Http, Self::Mime, Self::Url];

    /// Returns the wire spelling of this value model
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Mime => "mime",
            Self::Url => "url",
        }
    }

    /// Returns the canonical logical module name of this value model
    /// (`GNT-34.1-canonical-hierarchy-and-package-names`).
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Http => "std.data::http",
            Self::Mime => "std.data::mime",
            Self::Url => "std.data::url",
        }
    }

    /// Returns the one declared version identity of this value model
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn declared_version(self) -> DataVersion {
        DataVersion {
            module: self,
            version: DECLARED_DATA_VERSION,
        }
    }

    /// Decodes one canonical module name; every other spelling is `None`.
    #[must_use]
    pub fn from_module_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|module| module.module_name() == name)
    }
}

/// One selected value-model version identity of `GNT-43.1-data-value-model-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataVersion {
    module: DataModule,
    version: u16,
}

impl DataVersion {
    /// Publishes the one declared version identity of one value model
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn declared(module: DataModule) -> Self {
        module.declared_version()
    }

    /// Admits exactly one declared value-model identity of
    /// `GNT-43.1-data-value-model-contract`.
    ///
    /// The canonical identity spelling is `std.data::<module>@<version>`. An identity naming an
    /// undeclared module or an undeclared version is refused under `data-unsupported-version`,
    /// naming the observed spelling and the declared identity, or the declared set when no
    /// declared module is named, rather than substituted, upgraded, downgraded, inferred, or
    /// approximated. The presented version text is admitted only when it is exactly the
    /// canonical spelling of the declared version: a parseable variant such as a leading zero or
    /// a sign is refused, never normalized to the declared version.
    pub fn admit(presented: &str) -> Result<Self, DataError> {
        let Some((module, version)) = presented.rsplit_once('@') else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some(declared) = DataModule::from_module_name(module) else {
            return Err(Self::undeclared_identity(presented));
        };
        if version == DECLARED_DATA_VERSION.to_string() {
            Ok(declared.declared_version())
        } else {
            Err(DataError::new(
                DataDiagnosticCode::UnsupportedVersion,
                format!(
                    "`{presented}` is not the declared value-model identity `{}`",
                    declared.declared_version().canonical_identity()
                ),
            ))
        }
    }

    /// Publishes the refusal of one identity that names no declared value model
    /// (`GNT-43.1-data-value-model-contract`).
    fn undeclared_identity(presented: &str) -> DataError {
        let declared = DataModule::ALL
            .iter()
            .map(|module| format!("`{}`", module.declared_version().canonical_identity()))
            .collect::<Vec<_>>()
            .join(", ");
        DataError::new(
            DataDiagnosticCode::UnsupportedVersion,
            format!(
                "`{presented}` names no declared value-model identity; the declared identities are {declared}"
            ),
        )
    }

    /// Returns the canonical identity spelling `std.data::<module>@<version>`
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub fn canonical_identity(self) -> String {
        format!("{}@{}", self.module.module_name(), self.version)
    }

    /// Returns the declared value model.
    #[must_use]
    pub const fn module(self) -> DataModule {
        self.module
    }

    /// Returns the declared version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// One declared refusal category of `GNT-43.1-data-value-model-contract`.
///
/// The declared set is closed and its canonical order ([`DataRefusalCategory::ALL`]) is its
/// canonical wire-name order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataRefusalCategory {
    /// Input outside a value model's declared admitted language.
    MalformedInput,
    /// An operation beyond a value model's declared bound.
    ResourceLimit,
    /// An identity naming an undeclared module or version.
    UnsupportedVersion,
}

impl DataRefusalCategory {
    /// The closed declared set, in canonical wire order.
    pub const ALL: [DataRefusalCategory; 3] = [
        Self::MalformedInput,
        Self::ResourceLimit,
        Self::UnsupportedVersion,
    ];

    /// Returns the canonical wire spelling (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::ResourceLimit => "resource-limit",
            Self::UnsupportedVersion => "unsupported-version",
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

/// One frozen data refusal of `GNT-43.1-data-value-model-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataDiagnosticCode {
    /// An identity naming an undeclared module or version.
    UnsupportedVersion,
    /// Input outside a value model's declared admitted language.
    MalformedInput,
    /// An operation beyond a value model's declared bound.
    ExpansionLimit,
}

impl DataDiagnosticCode {
    /// The closed declared set, in canonical spelling order.
    pub const ALL: [DataDiagnosticCode; 3] = [
        Self::ExpansionLimit,
        Self::MalformedInput,
        Self::UnsupportedVersion,
    ];

    /// Returns the frozen refusal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "data-unsupported-version",
            Self::MalformedInput => "data-malformed-input",
            Self::ExpansionLimit => "data-expansion-limit",
        }
    }

    /// Returns the published meaning of this refusal.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => {
                "An identity naming an undeclared value model or version is refused."
            }
            Self::MalformedInput => {
                "Input outside a value model's declared admitted language is refused."
            }
            Self::ExpansionLimit => {
                "An operation beyond a value model's declared bound is refused."
            }
        }
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-43.1-data-value-model-contract"
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub const fn category(self) -> DataRefusalCategory {
        match self {
            Self::UnsupportedVersion => DataRefusalCategory::UnsupportedVersion,
            Self::MalformedInput => DataRefusalCategory::MalformedInput,
            Self::ExpansionLimit => DataRefusalCategory::ResourceLimit,
        }
    }
}

/// One refusal of the data foundation (`GNT-43.1-data-value-model-contract`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataError {
    code: DataDiagnosticCode,
    detail: String,
}

impl DataError {
    /// Publishes one refusal of the named code.
    #[must_use]
    pub fn new(code: DataDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen refusal code.
    #[must_use]
    pub const fn code(&self) -> DataDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-43.1-data-value-model-contract`).
    #[must_use]
    pub fn category(&self) -> DataRefusalCategory {
        self.code.category()
    }
}

/// One declared public item of `std.data` (`GNT-34.6-stability-tiers`,
/// `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The family declares one module item per declared value model: the canonical lowercase logical
/// path of that model, classified as a module because a module belongs to exactly one package
/// (`GNT-34.2-name-classification`), at the stable tier the family publishes. `clauses` records
/// the section clauses the item publishes, in specification order, so an item's declared surface
/// cannot drift from the clauses that justify it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataItemRow {
    /// The declared value model this item declares the module of.
    pub module: DataModule,
    /// The canonical logical item name (`GNT-34.1-canonical-hierarchy-and-package-names`).
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public items of `std.data`, one module per declared value model.
///
/// Each name is the canonical logical spelling of the model's own module spelling
/// ([`DataModule::module_name`]), so the declared rows are derived from the module vocabulary
/// rather than restated beside it, and each row lists every section clause that publishes a fact
/// about that model's surface in specification order.
pub const DATA_ITEMS: [DataItemRow; 3] = [
    DataItemRow {
        module: DataModule::Http,
        name: "std.data::http",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-43.0-data-family-scope",
            "GNT-43.1-data-value-model-contract",
        ],
    },
    DataItemRow {
        module: DataModule::Mime,
        name: "std.data::mime",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-43.0-data-family-scope",
            "GNT-43.1-data-value-model-contract",
        ],
    },
    DataItemRow {
        module: DataModule::Url,
        name: "std.data::url",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-43.0-data-family-scope",
            "GNT-43.1-data-value-model-contract",
        ],
    },
];

/// Declares the published item surface of `std.data` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The owning package must already be declared, and each item takes that package's declared modes
/// and targets, so an item is never applicable outside its own package's applicability
/// (`GNT-34.7-applicability-and-feature-granularity`). A second declaration of one item is refused
/// by the graph rather than merged.
pub fn declare_data_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Data.package_name();
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
    for row in DATA_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the published item surface of `std.data` declared
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
///
/// The family owns this declaration (`GNT-GP-STDLIB-DATA-001`), so the aggregate constructor
/// `canonical_pure_hierarchy` carries packages, applicability, and edges only while this
/// constructor adds the family's reviewed item rows — and with them the package interface digest
/// of `GNT-34.8` over those items. Composing both in one call keeps a consumer of the family
/// surface from reading the package without its published name level.
pub fn canonical_data_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_data_surface(&mut graph)?;
    Ok(graph)
}
