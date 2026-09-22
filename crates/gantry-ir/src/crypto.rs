//! The crypto foundation of `GNT-44.0-crypto-foundation-scope` and
//! `GNT-44.1-crypto-algorithm-contract`: the declared `std.crypto` family with its `hash` and
//! `signature` modules, the versioned algorithm identity and its exact admission rule, the frozen
//! refusal vocabulary with its declared refusal categories, and the separation between these pure
//! read-only algorithms and signing, secret-key material, credentials, and protected operations,
//! which host capabilities alone own.
//!
//! The model is pure: it consumes no platform cryptographic API, host crypto library, hardware
//! facility, ambient provider registry, random source, timing, environment, locale, filesystem,
//! or global mutable state. No concrete algorithm behavior is declared here; each algorithm's own
//! clause publishes its digest or verification contract, vectors, and bounds.

use crate::stdlib::{
    NameClass, PackageFamily, StabilityTier, StdGraph, StdItem, StdlibDiagnosticCode, StdlibError,
};

/// The declared clauses of Section 44, in specification order.
pub const CRYPTO_CLAUSES: [&str; 2] = [
    "GNT-44.0-crypto-foundation-scope",
    "GNT-44.1-crypto-algorithm-contract",
];

/// The one declared version of every algorithm in this revision
/// (`GNT-44.1-crypto-algorithm-contract`).
pub const DECLARED_ALGORITHM_VERSION: u16 = 1;

/// One declared module of the `std.crypto` family (`GNT-44.1-crypto-algorithm-contract`).
///
/// The declared set is closed and its canonical order ([`CryptoModule::ALL`]) is its canonical
/// module name order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CryptoModule {
    /// The `std.crypto::hash` module.
    Hash,
    /// The `std.crypto::signature` module.
    Signature,
}

impl CryptoModule {
    /// The closed declared set, in canonical name order.
    pub const ALL: [CryptoModule; 2] = [Self::Hash, Self::Signature];

    /// Returns the wire spelling of this module (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Signature => "signature",
        }
    }

    /// Returns the canonical logical module name of this module
    /// (`GNT-34.1-canonical-hierarchy-and-package-names`).
    #[must_use]
    pub const fn module_name(self) -> &'static str {
        match self {
            Self::Hash => "std.crypto::hash",
            Self::Signature => "std.crypto::signature",
        }
    }

    /// Returns the algorithm this module declares in this revision
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared_algorithm(self) -> &'static str {
        match self {
            Self::Hash => "sha256",
            Self::Signature => "ed25519",
        }
    }

    /// Returns the one declared identity of this module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared_identity(self) -> AlgorithmIdentity {
        AlgorithmIdentity {
            module: self,
            algorithm: self.declared_algorithm(),
            version: DECLARED_ALGORITHM_VERSION,
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

/// One selected algorithm identity of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentity {
    module: CryptoModule,
    algorithm: &'static str,
    version: u16,
}

impl AlgorithmIdentity {
    /// Publishes the one declared identity of one module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn declared(module: CryptoModule) -> Self {
        module.declared_identity()
    }

    /// Admits exactly one declared algorithm identity of
    /// `GNT-44.1-crypto-algorithm-contract`.
    ///
    /// The canonical identity spelling is `std.crypto::<module>::<algorithm>@<version>`. An
    /// identity naming an undeclared module, an undeclared algorithm, or an undeclared version is
    /// refused under `crypto-unsupported-algorithm`, naming the observed spelling and the declared
    /// identity, or the declared set when no declared module is named, rather than substituted,
    /// upgraded, downgraded, negotiated by a display label, inferred from input, or approximated.
    /// The presented version text is admitted only when it is exactly the canonical spelling of
    /// the declared version: a parseable variant such as a leading zero or a sign is refused,
    /// never normalized to the declared version.
    pub fn admit(presented: &str) -> Result<Self, CryptoError> {
        let Some((identity, version)) = presented.rsplit_once('@') else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some((module_name, algorithm)) = identity.rsplit_once("::") else {
            return Err(Self::undeclared_identity(presented));
        };
        let Some(module) = CryptoModule::from_module_name(module_name) else {
            return Err(Self::undeclared_identity(presented));
        };
        let declared = module.declared_identity();
        if algorithm != declared.algorithm || version != DECLARED_ALGORITHM_VERSION.to_string() {
            return Err(CryptoError::new(
                CryptoDiagnosticCode::UnsupportedAlgorithm,
                format!(
                    "`{presented}` is not the declared algorithm identity `{}`",
                    declared.canonical_identity()
                ),
            ));
        }
        Ok(declared)
    }

    /// Publishes the refusal of one identity that names no declared module
    /// (`GNT-44.1-crypto-algorithm-contract`).
    fn undeclared_identity(presented: &str) -> CryptoError {
        let declared = CryptoModule::ALL
            .iter()
            .map(|module| format!("`{}`", module.declared_identity().canonical_identity()))
            .collect::<Vec<_>>()
            .join(", ");
        CryptoError::new(
            CryptoDiagnosticCode::UnsupportedAlgorithm,
            format!(
                "`{presented}` names no declared algorithm identity; the declared identities are {declared}"
            ),
        )
    }

    /// Returns the canonical identity spelling `std.crypto::<module>::<algorithm>@<version>`
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn canonical_identity(self) -> String {
        format!(
            "{}::{}@{}",
            self.module.module_name(),
            self.algorithm,
            self.version
        )
    }

    /// Returns the declared module.
    #[must_use]
    pub const fn module(self) -> CryptoModule {
        self.module
    }

    /// Returns the declared algorithm.
    #[must_use]
    pub const fn algorithm(self) -> &'static str {
        self.algorithm
    }

    /// Returns the declared version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }
}

/// One declared refusal category of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoRefusalCategory {
    /// Input outside an algorithm's declared admitted language.
    MalformedInput,
    /// An identity naming an undeclared module, algorithm, or version.
    UnsupportedAlgorithm,
    /// An operation beyond a declared input or work bound.
    WorkLimit,
}

impl CryptoRefusalCategory {
    /// The closed declared set, in canonical wire order.
    pub const ALL: [CryptoRefusalCategory; 3] = [
        Self::MalformedInput,
        Self::UnsupportedAlgorithm,
        Self::WorkLimit,
    ];

    /// Returns the canonical wire spelling (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::UnsupportedAlgorithm => "unsupported-algorithm",
            Self::WorkLimit => "work-limit",
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

/// One frozen crypto refusal of `GNT-44.1-crypto-algorithm-contract`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoDiagnosticCode {
    /// Input outside an algorithm's declared admitted language.
    MalformedInput,
    /// An identity naming an undeclared module, algorithm, or version.
    UnsupportedAlgorithm,
    /// An operation beyond a declared input or work bound.
    WorkLimit,
}

impl CryptoDiagnosticCode {
    /// The closed declared set, in canonical spelling order.
    pub const ALL: [CryptoDiagnosticCode; 3] = [
        Self::MalformedInput,
        Self::UnsupportedAlgorithm,
        Self::WorkLimit,
    ];

    /// Returns the frozen refusal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedInput => "crypto-malformed-input",
            Self::UnsupportedAlgorithm => "crypto-unsupported-algorithm",
            Self::WorkLimit => "crypto-work-limit",
        }
    }

    /// Returns the published meaning of this refusal.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::MalformedInput => {
                "Input outside an algorithm's declared admitted language is refused."
            }
            Self::UnsupportedAlgorithm => {
                "An identity naming an undeclared module, algorithm, or version is refused."
            }
            Self::WorkLimit => "An operation beyond a declared input or work bound is refused.",
        }
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        "GNT-44.1-crypto-algorithm-contract"
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub const fn category(self) -> CryptoRefusalCategory {
        match self {
            Self::MalformedInput => CryptoRefusalCategory::MalformedInput,
            Self::UnsupportedAlgorithm => CryptoRefusalCategory::UnsupportedAlgorithm,
            Self::WorkLimit => CryptoRefusalCategory::WorkLimit,
        }
    }
}

/// One refusal of the crypto foundation (`GNT-44.1-crypto-algorithm-contract`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoError {
    code: CryptoDiagnosticCode,
    detail: String,
}

impl CryptoError {
    /// Publishes one refusal of the named code.
    #[must_use]
    pub fn new(code: CryptoDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the frozen refusal code.
    #[must_use]
    pub const fn code(&self) -> CryptoDiagnosticCode {
        self.code
    }

    /// Returns the refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the one owning clause of this refusal
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn requirement(&self) -> &'static str {
        self.code.requirement()
    }

    /// Returns the one refusal category this refusal classifies under
    /// (`GNT-44.1-crypto-algorithm-contract`).
    #[must_use]
    pub fn category(&self) -> CryptoRefusalCategory {
        self.code.category()
    }
}

/// One declared public item of `std.crypto` (`GNT-34.6-stability-tiers`,
/// `GNT-34.8-defining-identity-and-interface-digest`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoItemRow {
    /// The declared module this item declares.
    pub module: CryptoModule,
    /// The canonical logical item name (`GNT-34.1-canonical-hierarchy-and-package-names`).
    pub name: &'static str,
    /// The declared name classification of `GNT-34.2-name-classification`.
    pub class: NameClass,
    /// The declared stability tier of `GNT-34.6-stability-tiers`.
    pub tier: StabilityTier,
    /// The section clauses this item publishes, in specification order.
    pub clauses: &'static [&'static str],
}

/// The declared public items of `std.crypto`, one module per declared algorithm family.
pub const CRYPTO_ITEMS: [CryptoItemRow; 2] = [
    CryptoItemRow {
        module: CryptoModule::Hash,
        name: "std.crypto::hash",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-44.0-crypto-foundation-scope",
            "GNT-44.1-crypto-algorithm-contract",
        ],
    },
    CryptoItemRow {
        module: CryptoModule::Signature,
        name: "std.crypto::signature",
        class: NameClass::Module,
        tier: StabilityTier::Stable,
        clauses: &[
            "GNT-44.0-crypto-foundation-scope",
            "GNT-44.1-crypto-algorithm-contract",
        ],
    },
];

/// Declares the published item surface of `std.crypto` over one standard-library graph
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
pub fn declare_crypto_surface(graph: &mut StdGraph) -> Result<(), StdlibError> {
    let owner = PackageFamily::Crypto.package_name();
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
    for row in CRYPTO_ITEMS {
        graph.declare_item(StdItem::new(
            row.name, row.class, row.tier, &modes, &targets,
        )?)?;
    }
    Ok(())
}

/// Returns the canonical pure hierarchy with the published item surface of `std.crypto` declared
/// (`GNT-34.6-stability-tiers`, `GNT-34.8-defining-identity-and-interface-digest`).
pub fn canonical_crypto_hierarchy() -> Result<StdGraph, StdlibError> {
    let mut graph = crate::stdlib::canonical_pure_hierarchy()?;
    declare_crypto_surface(&mut graph)?;
    Ok(graph)
}
