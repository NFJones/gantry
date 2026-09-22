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
pub const DATA_CLAUSES: [&str; 3] = [
    "GNT-43.0-data-family-scope",
    "GNT-43.1-data-value-model-contract",
    "GNT-43.2-url-value-model",
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
            "GNT-43.2-url-value-model",
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

/// The declared text bound of `GNT-43.2-url-value-model`: the largest octet count a presented
/// text and a canonical form hold.
pub const URL_TEXT_OCTET_BOUND: usize = 65_536;

/// The declared scheme-scalar bound of `GNT-43.2-url-value-model`.
pub const URL_SCHEME_SCALAR_BOUND: usize = 64;

/// The declared reg-name scalar bound of `GNT-43.2-url-value-model`.
pub const URL_HOST_SCALAR_BOUND: usize = 255;

/// The declared host-label scalar bound of `GNT-43.2-url-value-model`.
pub const URL_LABEL_SCALAR_BOUND: usize = 63;

/// The declared zone-identifier scalar bound of `GNT-43.2-url-value-model`.
pub const URL_ZONE_SCALAR_BOUND: usize = 63;

/// The declared path segment-count bound of `GNT-43.2-url-value-model`.
pub const URL_SEGMENT_COUNT_BOUND: usize = 256;

/// The declared path-segment octet bound of `GNT-43.2-url-value-model`.
pub const URL_SEGMENT_OCTET_BOUND: usize = 1_024;

/// The declared query octet bound of `GNT-43.2-url-value-model`.
pub const URL_QUERY_OCTET_BOUND: usize = 4_096;

/// The declared fragment octet bound of `GNT-43.2-url-value-model`.
pub const URL_FRAGMENT_OCTET_BOUND: usize = 4_096;

/// One declared host of a URL value (`GNT-43.2-url-value-model`).
///
/// The declared forms are closed: a reg-name, a canonical IPv4 literal, and a canonical IPv6
/// literal with an optional zone identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UrlHost {
    /// A reg-name of one or more labels separated by `.`.
    RegName(String),
    /// A canonical IPv4 literal, four octets in presentation order.
    Ipv4([u8; 4]),
    /// A canonical IPv6 literal, eight 16-bit groups in presentation order, with an optional
    /// zone identifier.
    Ipv6 {
        /// The eight declared groups.
        groups: [u16; 8],
        /// The optional zone identifier.
        zone: Option<String>,
    },
}

/// One URL value of `GNT-43.2-url-value-model`.
///
/// The declared components are a scheme, a host, an optional explicit port, a path of zero or
/// more segments, an optional query, and an optional fragment, and every value is in the
/// canonical form that clause declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url {
    scheme: String,
    host: UrlHost,
    port: Option<u16>,
    segments: Vec<String>,
    query: Option<String>,
    fragment: Option<String>,
}

impl Url {
    /// Constructs one URL value from declared components (`GNT-43.2-url-value-model`).
    ///
    /// Each component is admitted by its own declared rule, so every constructed value is in
    /// canonical form; a component outside its admitted form is refused under the declared
    /// malformed-input refusal naming the zero-based index within the component or under the
    /// declared expansion-limit refusal naming the component's observed measure and declared
    /// bound, and a value whose canonical form would exceed `URL_TEXT_OCTET_BOUND` octets is
    /// refused before any part of it is constructed.
    pub fn new(
        scheme: &str,
        host: UrlHost,
        port: Option<u16>,
        segments: Vec<String>,
        query: Option<String>,
        fragment: Option<String>,
    ) -> Result<Self, DataError> {
        admit_scheme(scheme, 0)?;
        match &host {
            UrlHost::RegName(name) => admit_reg_name(name, 0)?,
            UrlHost::Ipv4(_) => {}
            UrlHost::Ipv6 { zone, .. } => {
                if let Some(zone) = zone {
                    admit_zone(zone, 0)?;
                }
            }
        }
        if port == Some(0) {
            return Err(url_malformed(
                0,
                "a port spells an integer from 1 through 65535",
            ));
        }
        if segments.len() > URL_SEGMENT_COUNT_BOUND {
            return Err(url_bound(
                segments.len(),
                URL_SEGMENT_COUNT_BOUND,
                "the path segment count",
            ));
        }
        for segment in &segments {
            admit_segment(segment, 0)?;
        }
        if let Some(query) = &query {
            admit_query(query, 0)?;
        }
        if let Some(fragment) = &fragment {
            admit_fragment(fragment, 0)?;
        }
        let value = Self {
            scheme: scheme.to_owned(),
            host,
            port,
            segments,
            query,
            fragment,
        };
        let text = value.canonical_text();
        if text.len() > URL_TEXT_OCTET_BOUND {
            return Err(url_bound(
                text.len(),
                URL_TEXT_OCTET_BOUND,
                "the canonical form",
            ));
        }
        Ok(value)
    }

    /// Parses the canonical form of a URL value (`GNT-43.2-url-value-model`).
    ///
    /// The parse is the declared left-to-right examination: the text bound is decided first, then
    /// each component in order, and the first departure decides the refusal.
    pub fn parse(text: &str) -> Result<Self, DataError> {
        let bytes = text.as_bytes();
        if bytes.len() > URL_TEXT_OCTET_BOUND {
            return Err(url_bound(
                bytes.len(),
                URL_TEXT_OCTET_BOUND,
                "the presented text",
            ));
        }
        let Some(colon) = text.find(':') else {
            let mut position = 0_usize;
            while position < bytes.len() && is_scheme_octet(bytes[position]) {
                position += 1;
            }
            return Err(url_malformed(
                position,
                "the scheme separator `://` is required",
            ));
        };
        admit_scheme(&text[..colon], 0)?;
        for offset in 1..=2_usize {
            let position = colon + offset;
            if bytes.get(position) != Some(&b'/') {
                return Err(url_malformed(
                    position.min(bytes.len()),
                    "the scheme separator `://` needs two solidus octets",
                ));
            }
        }
        let mut index = colon + 3;
        let authority_start = index;
        let mut authority_end = authority_start;
        while authority_end < bytes.len() && !matches!(bytes[authority_end], b'/' | b'?' | b'#') {
            authority_end += 1;
        }
        if authority_end == authority_start {
            return Err(url_malformed(authority_start, "the authority holds a host"));
        }
        let (host, port) = admit_authority(&text[authority_start..authority_end], authority_start)?;
        index = authority_end;
        if index == bytes.len() || bytes[index] != b'/' {
            return Err(url_malformed(
                index,
                "the canonical form writes the path separator `/`",
            ));
        }
        let mut segments = Vec::new();
        if index < bytes.len() && bytes[index] == b'/' {
            let body_start = index + 1;
            let mut body_end = body_start;
            while body_end < bytes.len() && !matches!(bytes[body_end], b'?' | b'#') {
                body_end += 1;
            }
            let body = &text[body_start..body_end];
            let count = body.split('/').count();
            if count > URL_SEGMENT_COUNT_BOUND {
                return Err(url_bound(
                    count,
                    URL_SEGMENT_COUNT_BOUND,
                    "the path segment count",
                ));
            }
            let mut offset = body_start;
            for segment in body.split('/') {
                admit_segment(segment, offset)?;
                segments.push(segment.to_owned());
                offset += segment.len() + 1;
            }
            index = body_end;
        }
        let mut query = None;
        if index < bytes.len() && bytes[index] == b'?' {
            let query_start = index + 1;
            let mut query_end = query_start;
            while query_end < bytes.len() && bytes[query_end] != b'#' {
                query_end += 1;
            }
            let query_text = &text[query_start..query_end];
            admit_query(query_text, query_start)?;
            query = Some(query_text.to_owned());
            index = query_end;
        }
        let mut fragment = None;
        if index < bytes.len() && bytes[index] == b'#' {
            let fragment_start = index + 1;
            let fragment_text = &text[fragment_start..];
            admit_fragment(fragment_text, fragment_start)?;
            fragment = Some(fragment_text.to_owned());
            index = bytes.len();
        }
        if index != bytes.len() {
            return Err(url_malformed(
                index,
                "the canonical form holds nothing after the fragment",
            ));
        }
        Ok(Self {
            scheme: text[..colon].to_owned(),
            host,
            port,
            segments,
            query,
            fragment,
        })
    }

    /// Returns the declared scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the declared host.
    #[must_use]
    pub fn host(&self) -> &UrlHost {
        &self.host
    }

    /// Returns the declared explicit port, when the value holds one.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the declared path segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Returns the declared query, when the value holds one.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Returns the declared fragment, when the value holds one.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Publishes the canonical form of this value (`GNT-43.2-url-value-model`).
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&self.scheme);
        text.push_str("://");
        match &self.host {
            UrlHost::RegName(name) => text.push_str(name),
            UrlHost::Ipv4(octets) => {
                text.push_str(&format!(
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], octets[3]
                ));
            }
            UrlHost::Ipv6 { groups, zone } => {
                text.push('[');
                text.push_str(&render_ipv6(groups));
                if let Some(zone) = zone {
                    text.push_str("%25");
                    text.push_str(zone);
                }
                text.push(']');
            }
        }
        if let Some(port) = self.port {
            text.push_str(&format!(":{port}"));
        }
        text.push('/');
        text.push_str(&self.segments.join("/"));
        if let Some(query) = &self.query {
            text.push('?');
            text.push_str(query);
        }
        if let Some(fragment) = &self.fragment {
            text.push('#');
            text.push_str(fragment);
        }
        text
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.canonical_text())
    }
}

/// Publishes one malformed-input refusal naming the zero-based octet index of a departure
/// (`GNT-43.2-url-value-model`).
fn url_malformed(index: usize, detail: &'static str) -> DataError {
    DataError::new(
        DataDiagnosticCode::MalformedInput,
        format!("octet {index}: {detail}"),
    )
}

/// Publishes one expansion-limit refusal naming an observed measure and the declared bound
/// (`GNT-43.2-url-value-model`).
fn url_bound(observed: usize, declared: usize, what: &'static str) -> DataError {
    DataError::new(
        DataDiagnosticCode::ExpansionLimit,
        format!("{what} holds {observed}; the declared bound is {declared}"),
    )
}

/// Returns whether the octet is a scheme octet (`GNT-43.2-url-value-model`).
fn is_scheme_octet(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
}

/// Returns whether the octet is a reg-name octet (`GNT-43.2-url-value-model`).
fn is_reg_name_octet(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

/// Returns whether the octet is a path-set octet (`GNT-43.2-url-value-model`).
fn is_path_octet(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

/// Returns whether the octet is a query-set octet (`GNT-43.2-url-value-model`).
fn is_query_octet(byte: u8) -> bool {
    is_path_octet(byte) || matches!(byte, b'/' | b'?')
}

/// Returns whether the octet is a zone-identifier octet (`GNT-43.2-url-value-model`).
fn is_zone_octet(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Returns whether the octet is an uppercase hexadecimal digit or a decimal digit
/// (`GNT-43.2-url-value-model`).
fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

/// Returns the value of one hexadecimal digit (`GNT-43.2-url-value-model`).
const fn hex_value(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else if byte.is_ascii_uppercase() {
        byte - b'A' + 10
    } else {
        byte - b'a' + 10
    }
}

/// Admits one canonical percent escape (`GNT-43.2-url-value-model`).
fn canonical_escape(
    bytes: &[u8],
    index: usize,
    base: usize,
    admitted: fn(u8) -> bool,
) -> Result<usize, DataError> {
    let digits = "a percent escape holds two uppercase hexadecimal digits";
    let Some(high) = bytes.get(index + 1) else {
        return Err(url_malformed(base + index, digits));
    };
    if !is_upper_hex(*high) {
        return Err(url_malformed(base + index + 1, digits));
    }
    let Some(low) = bytes.get(index + 2) else {
        return Err(url_malformed(base + index + 2, digits));
    };
    if !is_upper_hex(*low) {
        return Err(url_malformed(base + index + 2, digits));
    }
    let octet = hex_value(*high) * 16 + hex_value(*low);
    if admitted(octet) {
        return Err(url_malformed(
            base + index,
            "a percent escape encodes an octet the position admits unescaped",
        ));
    }
    Ok(index + 3)
}

/// Admits an octet sequence over one declared set and its canonical escapes
/// (`GNT-43.2-url-value-model`).
fn admit_octets(
    bytes: &[u8],
    base: usize,
    admitted: fn(u8) -> bool,
    detail: &'static str,
) -> Result<(), DataError> {
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            index = canonical_escape(bytes, index, base, admitted)?;
            continue;
        }
        if !admitted(bytes[index]) {
            return Err(url_malformed(base + index, detail));
        }
        index += 1;
    }
    Ok(())
}

/// Admits one scheme (`GNT-43.2-url-value-model`).
fn admit_scheme(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_SCHEME_SCALAR_BOUND {
        return Err(url_bound(
            bytes.len(),
            URL_SCHEME_SCALAR_BOUND,
            "the scheme",
        ));
    }
    if !bytes.first().is_some_and(u8::is_ascii_lowercase) {
        return Err(url_malformed(
            base,
            "a scheme begins with a lowercase ASCII letter",
        ));
    }
    for (index, byte) in bytes.iter().enumerate().skip(1) {
        if !is_scheme_octet(*byte) {
            return Err(url_malformed(
                base + index,
                "a scheme holds lowercase letters, digits, `+`, `-`, and `.`",
            ));
        }
    }
    Ok(())
}

/// Admits one reg-name (`GNT-43.2-url-value-model`).
fn admit_reg_name(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_HOST_SCALAR_BOUND {
        return Err(url_bound(
            bytes.len(),
            URL_HOST_SCALAR_BOUND,
            "the reg-name host",
        ));
    }
    if bytes.is_empty() {
        return Err(url_malformed(base, "a reg-name holds one or more labels"));
    }
    let mut label_start = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'.' {
            let label_len = index - label_start;
            if label_len == 0 {
                return Err(url_malformed(
                    base + index,
                    "a reg-name holds no empty label",
                ));
            }
            if label_len > URL_LABEL_SCALAR_BOUND {
                return Err(url_bound(label_len, URL_LABEL_SCALAR_BOUND, "a host label"));
            }
            label_start = index + 1;
            continue;
        }
        if !is_reg_name_octet(*byte) {
            return Err(url_malformed(
                base + index,
                "a reg-name holds lowercase letters, digits, and `-`",
            ));
        }
    }
    let label_len = bytes.len() - label_start;
    if label_len == 0 {
        return Err(url_malformed(
            base + bytes.len() - 1,
            "a reg-name holds no empty trailing label",
        ));
    }
    if label_len > URL_LABEL_SCALAR_BOUND {
        return Err(url_bound(label_len, URL_LABEL_SCALAR_BOUND, "a host label"));
    }
    Ok(())
}

/// Admits one canonical IPv4 literal (`GNT-43.2-url-value-model`).
fn admit_ipv4(text: &str, base: usize) -> Result<[u8; 4], DataError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(url_malformed(base, "an IPv4 part holds one or more digits"));
    }
    let mut octets = [0_u8; 4];
    let mut start = 0_usize;
    for (part, slot) in octets.iter_mut().enumerate() {
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'.' {
            end += 1;
        }
        let digits = &bytes[start..end];
        if digits.is_empty() {
            return Err(url_malformed(
                base + start,
                "an IPv4 part holds one or more digits",
            ));
        }
        let mut value = 0_u32;
        for (offset, digit) in digits.iter().enumerate() {
            if !digit.is_ascii_digit() {
                return Err(url_malformed(
                    base + start + offset,
                    "an IPv4 part holds digits",
                ));
            }
            value = value * 10 + u32::from(*digit - b'0');
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(url_malformed(
                base + start + 1,
                "an IPv4 part holds no leading zero",
            ));
        }
        if value > 255 || digits.len() > 3 {
            return Err(url_malformed(
                base + end - 1,
                "an IPv4 part spells an integer from 0 through 255",
            ));
        }
        *slot = value as u8;
        if part < 3 {
            if end >= bytes.len() {
                return Err(url_malformed(
                    base + bytes.len(),
                    "an IPv4 literal holds exactly four parts separated by `.`",
                ));
            }
            start = end + 1;
        } else if end != bytes.len() {
            return Err(url_malformed(
                base + end,
                "an IPv4 literal holds exactly four parts",
            ));
        }
    }
    Ok(octets)
}

/// Admits one IPv6 group list, returning each group with its absolute start offset
/// (`GNT-43.2-url-value-model`).
fn parse_ipv6_side(text: &str, base: usize) -> Result<Vec<(usize, u16)>, DataError> {
    let mut groups = Vec::new();
    if text.is_empty() {
        return Ok(groups);
    }
    let mut offset = 0_usize;
    for piece in text.split(':') {
        if piece.is_empty() {
            return Err(url_malformed(
                base + offset,
                "an IPv6 group holds one or more digits",
            ));
        }
        let mut value = 0_u16;
        for (index, byte) in piece.bytes().enumerate() {
            if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
                return Err(url_malformed(
                    base + offset + index,
                    "an IPv6 group holds lowercase hexadecimal digits",
                ));
            }
            if index >= 4 {
                return Err(url_malformed(
                    base + offset + index,
                    "an IPv6 group holds at most four digits",
                ));
            }
            value = value * 16 + u16::from(hex_value(byte));
        }
        groups.push((base + offset, value));
        offset += piece.len() + 1;
    }
    Ok(groups)
}

/// Parses one canonical IPv6 address into its eight groups (`GNT-43.2-url-value-model`).
fn parse_ipv6_groups(text: &str, base: usize) -> Result<[u16; 8], DataError> {
    if text.is_empty() {
        return Err(url_malformed(
            base,
            "an IPv6 literal holds at least one group",
        ));
    }
    let (left_text, right_text, compressed) = match text.split_once("::") {
        Some((left, right)) => {
            if let Some(position) = right.find("::") {
                return Err(url_malformed(
                    base + left.len() + 2 + position,
                    "an IPv6 literal holds at most one `::`",
                ));
            }
            (left, right, true)
        }
        None => (text, "", false),
    };
    let left = parse_ipv6_side(left_text, base)?;
    let right = parse_ipv6_side(right_text, base + left_text.len() + 2)?;
    let mut groups = [0_u16; 8];
    if compressed {
        if let Some((offset, _)) = left.get(7) {
            return Err(url_malformed(
                *offset,
                "the `::` stands for at least one zero group",
            ));
        }
        if let Some((offset, _)) = right.get(7 - left.len()) {
            return Err(url_malformed(
                *offset,
                "the `::` stands for at least one zero group",
            ));
        }
        for (index, (_, value)) in left.iter().enumerate() {
            groups[index] = *value;
        }
        let right_start = 8 - right.len();
        for (index, (_, value)) in right.iter().enumerate() {
            groups[right_start + index] = *value;
        }
    } else {
        for (index, (offset, value)) in left.iter().enumerate() {
            if index >= 8 {
                return Err(url_malformed(
                    *offset,
                    "an IPv6 literal without `::` holds exactly eight groups",
                ));
            }
            groups[index] = *value;
        }
        if left.len() < 8 {
            return Err(url_malformed(
                base + text.len(),
                "an IPv6 literal without `::` holds exactly eight groups",
            ));
        }
    }
    Ok(groups)
}

/// Renders one IPv6 address in the declared canonical spelling (`GNT-43.2-url-value-model`).
fn render_ipv6(groups: &[u16; 8]) -> String {
    let mut best_start = 0_usize;
    let mut best_len = 0_usize;
    let mut index = 0_usize;
    while index < 8 {
        if groups[index] == 0 {
            let start = index;
            while index < 8 && groups[index] == 0 {
                index += 1;
            }
            let len = index - start;
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            index += 1;
        }
    }
    let mut rendered = String::new();
    let mut position = 0_usize;
    while position < 8 {
        if best_len >= 2 && position == best_start {
            rendered.push_str("::");
            position += best_len;
            continue;
        }
        if !rendered.is_empty() && !rendered.ends_with(':') {
            rendered.push(':');
        }
        rendered.push_str(&format!("{:x}", groups[position]));
        position += 1;
    }
    rendered
}

/// Admits one canonical IPv6 literal, with its optional zone identifier
/// (`GNT-43.2-url-value-model`).
fn admit_ipv6_literal(text: &str, base: usize) -> Result<([u16; 8], Option<String>), DataError> {
    let (address_text, zone_text) = match text.split_once("%25") {
        Some((address, zone)) => (address, Some(zone)),
        None => (text, None),
    };
    let groups = parse_ipv6_groups(address_text, base)?;
    let rendered = render_ipv6(&groups);
    if rendered != address_text {
        let limit = rendered.len().min(address_text.len());
        let mut index = 0_usize;
        while index < limit && rendered.as_bytes()[index] == address_text.as_bytes()[index] {
            index += 1;
        }
        return Err(url_malformed(
            base + index,
            "an IPv6 literal uses the declared canonical spelling",
        ));
    }
    let zone = match zone_text {
        Some(zone) => {
            admit_zone(zone, base + address_text.len() + 3)?;
            Some(zone.to_owned())
        }
        None => None,
    };
    Ok((groups, zone))
}

/// Admits one zone identifier (`GNT-43.2-url-value-model`).
fn admit_zone(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_ZONE_SCALAR_BOUND {
        return Err(url_bound(
            bytes.len(),
            URL_ZONE_SCALAR_BOUND,
            "the zone identifier",
        ));
    }
    if bytes.is_empty() {
        return Err(url_malformed(
            base,
            "a zone identifier holds one or more octets",
        ));
    }
    admit_octets(
        bytes,
        base,
        is_zone_octet,
        "a zone identifier holds lowercase letters, digits, `-`, `.`, `_`, and `~`",
    )
}

/// Admits one port (`GNT-43.2-url-value-model`).
fn admit_port(text: &str, base: usize) -> Result<u16, DataError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(url_malformed(base, "a port holds one or more digits"));
    }
    let mut value = 0_u32;
    for (index, byte) in bytes.iter().enumerate() {
        if !byte.is_ascii_digit() {
            return Err(url_malformed(base + index, "a port holds digits"));
        }
        if index == 0 && *byte == b'0' {
            return Err(url_malformed(
                base,
                "a port holds no leading zero and is not the value 0",
            ));
        }
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(*byte - b'0'));
        if value > 65_535 {
            return Err(url_malformed(
                base + index,
                "a port spells an integer from 1 through 65535",
            ));
        }
    }
    Ok(value as u16)
}

/// Admits one authority, returning its host and its optional port
/// (`GNT-43.2-url-value-model`).
fn admit_authority(text: &str, base: usize) -> Result<(UrlHost, Option<u16>), DataError> {
    if let Some(rest) = text.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(url_malformed(
                base + text.len(),
                "an IPv6 literal closes with `]`",
            ));
        };
        let (groups, zone) = admit_ipv6_literal(&rest[..close], base + 1)?;
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(port) => Some(admit_port(port, base + close + 2)?),
            None => {
                if after.is_empty() {
                    None
                } else {
                    return Err(url_malformed(
                        base + close + 1,
                        "an IPv6 literal is followed by `:` and its port",
                    ));
                }
            }
        };
        return Ok((UrlHost::Ipv6 { groups, zone }, port));
    }
    let (host_text, port_text) = match text.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    if host_text.is_empty() {
        return Err(url_malformed(base, "a host holds one or more labels"));
    }
    let host = if host_text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        UrlHost::Ipv4(admit_ipv4(host_text, base)?)
    } else {
        admit_reg_name(host_text, base)?;
        UrlHost::RegName(host_text.to_owned())
    };
    let port = match port_text {
        Some(port) => Some(admit_port(port, base + host_text.len() + 1)?),
        None => None,
    };
    Ok((host, port))
}

/// Admits one path segment (`GNT-43.2-url-value-model`).
fn admit_segment(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_SEGMENT_OCTET_BOUND {
        return Err(url_bound(
            bytes.len(),
            URL_SEGMENT_OCTET_BOUND,
            "a path segment",
        ));
    }
    if text == "." || text == ".." {
        return Err(url_malformed(base, "a path segment is never `.` or `..`"));
    }
    admit_octets(
        bytes,
        base,
        is_path_octet,
        "a path segment holds the declared path set",
    )
}

/// Admits one query (`GNT-43.2-url-value-model`).
fn admit_query(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_QUERY_OCTET_BOUND {
        return Err(url_bound(bytes.len(), URL_QUERY_OCTET_BOUND, "the query"));
    }
    admit_octets(
        bytes,
        base,
        is_query_octet,
        "a query holds the declared query set",
    )
}

/// Admits one fragment (`GNT-43.2-url-value-model`).
fn admit_fragment(text: &str, base: usize) -> Result<(), DataError> {
    let bytes = text.as_bytes();
    if bytes.len() > URL_FRAGMENT_OCTET_BOUND {
        return Err(url_bound(
            bytes.len(),
            URL_FRAGMENT_OCTET_BOUND,
            "the fragment",
        ));
    }
    admit_octets(
        bytes,
        base,
        is_query_octet,
        "a fragment holds the declared query set",
    )
}
