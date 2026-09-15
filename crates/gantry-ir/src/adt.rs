//! Section 36 recursive algebraic data types, aliases, visibility, and constants.
//!
//! The model is a declaration model only: declarations carry no bodies, no
//! initializers, and no effect-capable members, so nothing here executes at package
//! load. Effect, cycle, overflow, and general evaluation-limit rules for constants
//! stay owned by Section 32 (`GNT-32.8`, `GNT-32.9`); this module owns only the ADT
//! constant site's finite constructor tree and its own charge against a declared budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The clauses of SPEC.md Section 36, in declaration order.
pub const ADT_CLAUSES: [&str; 13] = [
    "GNT-36.0-recursive-algebraic-data-types",
    "GNT-36.1-declaration-and-constructor-identity",
    "GNT-36.2-guarded-productive-recursion",
    "GNT-36.3-mutual-recursion-and-order-independence",
    "GNT-36.4-aliases-and-alias-cycles",
    "GNT-36.5-visibility-and-reference-admission",
    "GNT-36.6-destructuring-and-pattern-identity",
    "GNT-36.7-match-coverage-and-exhaustiveness",
    "GNT-36.8-bounded-constant-values",
    "GNT-36.9-package-load-non-execution",
    "GNT-36.10-schema-closure-and-boundary-independence",
    "GNT-36.11-durable-round-trips-and-interface-identity",
    "GNT-36.12-adt-non-claims",
];

/// Length-prefixed canonical encoding of one schema component (`GNT-36.10`).
fn encode_component(component: &str) -> String {
    format!("{}:{component}", component.len())
}

/// The frozen Section 36 diagnostics, each naming exactly one owning clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdtDiagnosticCode {
    /// `GNT-36.1`: a type, constructor, or tag is declared twice.
    DuplicateConstructor,
    /// `GNT-36.1`: a constructor departs from its type's parameter list or field count.
    ConstructorArity,
    /// `GNT-36.2`: a declared type has no finite value.
    UnproductiveRecursion,
    /// `GNT-36.3`: a reference names no declaration in the package.
    UnresolvedReference,
    /// `GNT-36.4`: the alias-only relation contains a cycle.
    AliasCycle,
    /// `GNT-36.4`: an alias departs from its resolved target's parameter list.
    AliasArity,
    /// `GNT-36.5`: a reference reaches a less open declaration.
    InvisibleReference,
    /// `GNT-36.6`: a pattern names a constructor the matched type does not declare.
    UnknownConstructor,
    /// `GNT-36.6`: a sub-pattern form does not match its field position.
    PatternShape,
    /// `GNT-36.7`: a match leaves a declared constructor path uncovered.
    IncompleteMatch,
    /// `GNT-36.8`: a constant site is not a finite constructor tree.
    ConstantForm,
    /// `GNT-36.8`: a constant site exceeds its declared node or depth budget.
    ConstantLimit,
    /// `GNT-36.9`: a mutable package global is declared.
    MutableGlobal,
    /// `GNT-36.10`: a schema depends on a boundary encoding or storage order.
    SchemaDivergence,
    /// `GNT-36.11`: a durable projection omits, reorders, or alters declarations.
    RoundTripLoss,
    /// `GNT-36.12`: a non-claim is presented as a guarantee.
    NonClaimAsGuarantee,
}

impl AdtDiagnosticCode {
    /// Every code, in declaration order.
    pub const ALL: [Self; 16] = [
        Self::DuplicateConstructor,
        Self::ConstructorArity,
        Self::UnproductiveRecursion,
        Self::UnresolvedReference,
        Self::AliasCycle,
        Self::AliasArity,
        Self::InvisibleReference,
        Self::UnknownConstructor,
        Self::PatternShape,
        Self::IncompleteMatch,
        Self::ConstantForm,
        Self::ConstantLimit,
        Self::MutableGlobal,
        Self::SchemaDivergence,
        Self::RoundTripLoss,
        Self::NonClaimAsGuarantee,
    ];

    /// The frozen diagnostic spelling.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::DuplicateConstructor => "adt-duplicate-constructor",
            Self::ConstructorArity => "adt-constructor-arity",
            Self::UnproductiveRecursion => "adt-unproductive-recursion",
            Self::UnresolvedReference => "adt-unresolved-reference",
            Self::AliasCycle => "adt-alias-cycle",
            Self::AliasArity => "adt-alias-arity",
            Self::InvisibleReference => "adt-invisible-reference",
            Self::UnknownConstructor => "adt-unknown-constructor",
            Self::PatternShape => "adt-pattern-shape",
            Self::IncompleteMatch => "adt-incomplete-match",
            Self::ConstantForm => "adt-constant-form",
            Self::ConstantLimit => "adt-constant-limit",
            Self::MutableGlobal => "adt-mutable-global",
            Self::SchemaDivergence => "adt-schema-divergence",
            Self::RoundTripLoss => "adt-round-trip-loss",
            Self::NonClaimAsGuarantee => "adt-non-claim-as-guarantee",
        }
    }

    /// The clause that owns this diagnostic.
    #[must_use]
    pub fn clause(self) -> &'static str {
        match self {
            Self::DuplicateConstructor | Self::ConstructorArity => {
                "GNT-36.1-declaration-and-constructor-identity"
            }
            Self::UnproductiveRecursion => "GNT-36.2-guarded-productive-recursion",
            Self::UnresolvedReference => "GNT-36.3-mutual-recursion-and-order-independence",
            Self::AliasCycle | Self::AliasArity => "GNT-36.4-aliases-and-alias-cycles",
            Self::InvisibleReference => "GNT-36.5-visibility-and-reference-admission",
            Self::UnknownConstructor => "GNT-36.6-destructuring-and-pattern-identity",
            Self::PatternShape => "GNT-36.6-destructuring-and-pattern-identity",
            Self::IncompleteMatch => "GNT-36.7-match-coverage-and-exhaustiveness",
            Self::ConstantForm | Self::ConstantLimit => "GNT-36.8-bounded-constant-values",
            Self::MutableGlobal => "GNT-36.9-package-load-non-execution",
            Self::SchemaDivergence => "GNT-36.10-schema-closure-and-boundary-independence",
            Self::RoundTripLoss => "GNT-36.11-durable-round-trips-and-interface-identity",
            Self::NonClaimAsGuarantee => "GNT-36.12-adt-non-claims",
        }
    }
}

/// A refusal carrying its frozen code and a detail string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtError {
    code: AdtDiagnosticCode,
    detail: String,
}

impl AdtError {
    /// Builds a refusal.
    #[must_use]
    pub fn new(code: AdtDiagnosticCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// The frozen code.
    #[must_use]
    pub fn code(&self) -> AdtDiagnosticCode {
        self.code
    }

    /// The refusal detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for AdtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.code(), self.detail)
    }
}

/// Declaration and reference visibility (`GNT-36.5`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdtVisibility {
    /// Visible only inside the declaring module.
    Private,
    /// Visible inside the declaring package.
    Package,
    /// Visible to every package.
    Public,
}

impl AdtVisibility {
    /// Every visibility, from most private to most open.
    pub const ALL: [Self; 3] = [Self::Private, Self::Package, Self::Public];

    /// The canonical spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Package => "package",
            Self::Public => "public",
        }
    }

    fn openness(self) -> u8 {
        match self {
            Self::Private => 0,
            Self::Package => 1,
            Self::Public => 2,
        }
    }

    /// Whether a reference from `site` may reach a declaration of this visibility.
    #[must_use]
    pub fn admits_reference_from(self, site: Self) -> bool {
        site.openness() <= self.openness()
    }
}

/// One declared constructor field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtField {
    /// The field name.
    pub name: String,
    /// The declared type name of the field.
    pub type_name: String,
}

/// One declared constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtConstructor {
    /// The constructor name.
    pub name: String,
    /// The declared portable tag, unique inside the owning type.
    pub tag: u32,
    /// The constructor's parameter list, which must equal the owning type's (`GNT-36.1`).
    pub parameters: Vec<String>,
    /// The declared fields, in declaration order.
    pub fields: Vec<AdtField>,
}

/// One declared algebraic data type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtTypeDeclaration {
    /// The type name.
    pub name: String,
    /// The type's visibility.
    pub visibility: AdtVisibility,
    /// The declared parameters, in declaration order.
    pub parameters: Vec<String>,
    /// The declared constructors.
    pub constructors: Vec<AdtConstructor>,
}

/// One declared alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtAliasDeclaration {
    /// The alias name.
    pub name: String,
    /// The alias visibility.
    pub visibility: AdtVisibility,
    /// The declared parameters, in declaration order.
    pub parameters: Vec<String>,
    /// The resolved target name.
    pub target: String,
}

/// A finite constant constructor tree (`GNT-36.8`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdtConstantTree {
    /// A scalar leaf.
    Scalar(i64),
    /// A constructor node with one argument per declared field.
    Constructor {
        /// The type the constructor belongs to.
        type_name: String,
        /// The constructor name.
        constructor: String,
        /// The arguments, in declared field order.
        arguments: Vec<AdtConstantTree>,
    },
}

/// A constant site value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdtConstantValue {
    /// A finite constructor tree.
    Tree(AdtConstantTree),
    /// A deferred value that would require package-load execution.
    Deferred {
        /// Why the value cannot be published as a finite tree.
        reason: String,
    },
}

/// One declared constant site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtConstantSite {
    /// The site name.
    pub name: String,
    /// The site visibility.
    pub visibility: AdtVisibility,
    /// The declared type of the value.
    pub type_name: String,
    /// The declared value.
    pub value: AdtConstantValue,
}

/// The declared node and depth budget of a constant site (`GNT-36.8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdtConstantBudget {
    /// The maximum admitted node count.
    pub max_nodes: usize,
    /// The maximum admitted depth.
    pub max_depth: usize,
}

impl AdtConstantBudget {
    /// A budget admitting the given node count and depth.
    #[must_use]
    pub fn new(max_nodes: usize, max_depth: usize) -> Self {
        Self {
            max_nodes,
            max_depth,
        }
    }
}

/// The charge of one constant site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdtCharge {
    /// The charged node count.
    pub nodes: usize,
    /// The charged depth.
    pub depth: usize,
}

/// One destructuring pattern (`GNT-36.6`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtPattern {
    /// The named constructor.
    pub constructor: String,
    /// One sub-pattern per declared field.
    pub arguments: Vec<AdtSubPattern>,
}

/// One sub-pattern of a constructor pattern (`GNT-36.6`).
///
/// A field whose type resolves to a declared type carries a constructor pattern, and a field whose
/// type resolves to a scalar leaf carries a scalar form that names no constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdtSubPattern {
    /// A constructor pattern for a field of declared type.
    Constructor(AdtPattern),
    /// A scalar form (binding, wildcard, or literal) for a field of scalar leaf type.
    Scalar,
}

/// The outcome of a match-coverage check (`GNT-36.7`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtMatchReport {
    /// The covered constructor names, in declared tag order.
    pub covered: Vec<String>,
    /// The number of recursive sub-pattern checks performed.
    pub checked_paths: usize,
}

/// A package-load fact for a declaration set (`GNT-36.9`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdtPackageLoad {
    /// The number of declared types, aliases, and constant sites.
    pub declarations: usize,
    /// The number of source statements executed at package load.
    pub executed_statements: usize,
    /// The number of declarations executed at package load.
    pub executed_declarations: usize,
}

/// The nonsemantic boundary labels of a declaration set (`GNT-36.10`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdtBoundaryLabels {
    labels: BTreeMap<(String, String), String>,
}

impl AdtBoundaryLabels {
    /// An empty label set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the external spelling of one constructor.
    pub fn label(&mut self, type_name: &str, constructor: &str, external: &str) {
        self.labels.insert(
            (type_name.to_owned(), constructor.to_owned()),
            external.to_owned(),
        );
    }

    /// The external spelling of one constructor, when registered.
    #[must_use]
    pub fn get(&self, type_name: &str, constructor: &str) -> Option<&str> {
        self.labels
            .get(&(type_name.to_owned(), constructor.to_owned()))
            .map(String::as_str)
    }
}

/// The identity of one constructor (`GNT-36.1`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdtConstructorIdentity(String);

impl AdtConstructorIdentity {
    /// The canonical identity text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The durable projection of a declaration set (`GNT-36.11`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdtDurableProjection {
    /// The owning package identity.
    pub package: String,
    /// The declared leaf type names.
    pub leaves: Vec<String>,
    /// The declared types, in canonical name order with constructors in tag order.
    pub types: Vec<AdtTypeDeclaration>,
    /// The declared aliases, in canonical name order.
    pub aliases: Vec<AdtAliasDeclaration>,
    /// The declared constant sites, in canonical name order.
    pub constants: Vec<AdtConstantSite>,
    /// The identity the projection must rebuild.
    pub identity: String,
}

/// Builds and validates a declaration set.
#[derive(Clone, Debug)]
pub struct AdtPackageBuilder {
    package: String,
    leaves: BTreeSet<String>,
    types: Vec<AdtTypeDeclaration>,
    aliases: Vec<AdtAliasDeclaration>,
    constants: Vec<AdtConstantSite>,
}

impl AdtPackageBuilder {
    /// Starts a declaration set for one package.
    #[must_use]
    pub fn new(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            leaves: BTreeSet::new(),
            types: Vec::new(),
            aliases: Vec::new(),
            constants: Vec::new(),
        }
    }

    /// Registers a leaf type name provided by another section.
    pub fn declare_leaf(&mut self, name: &str) {
        self.leaves.insert(name.to_owned());
    }

    /// Declares one type, refusing duplicates and irregular constructors.
    pub fn declare_type(&mut self, declaration: AdtTypeDeclaration) -> Result<(), AdtError> {
        if declaration.constructors.is_empty() {
            return Err(AdtError::new(
                AdtDiagnosticCode::DuplicateConstructor,
                format!("type {} declares no constructor", declaration.name),
            ));
        }
        if self
            .types
            .iter()
            .any(|existing| existing.name == declaration.name)
            || self
                .aliases
                .iter()
                .any(|alias| alias.name == declaration.name)
        {
            return Err(AdtError::new(
                AdtDiagnosticCode::DuplicateConstructor,
                format!("type {} is declared twice", declaration.name),
            ));
        }
        let mut names = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for constructor in &declaration.constructors {
            if !names.insert(constructor.name.clone()) || !tags.insert(constructor.tag) {
                return Err(AdtError::new(
                    AdtDiagnosticCode::DuplicateConstructor,
                    format!(
                        "type {} declares constructor {}#{} twice",
                        declaration.name, constructor.name, constructor.tag
                    ),
                ));
            }
            if constructor.parameters != declaration.parameters {
                return Err(AdtError::new(
                    AdtDiagnosticCode::ConstructorArity,
                    format!(
                        "{}::{} declares parameters [{}] but its type declares [{}]",
                        declaration.name,
                        constructor.name,
                        constructor.parameters.join(","),
                        declaration.parameters.join(",")
                    ),
                ));
            }
        }
        self.types.push(declaration);
        Ok(())
    }

    /// Declares one alias.
    pub fn declare_alias(&mut self, declaration: AdtAliasDeclaration) -> Result<(), AdtError> {
        if self
            .types
            .iter()
            .any(|entry| entry.name == declaration.name)
            || self
                .aliases
                .iter()
                .any(|entry| entry.name == declaration.name)
        {
            return Err(AdtError::new(
                AdtDiagnosticCode::DuplicateConstructor,
                format!("alias {} is declared twice", declaration.name),
            ));
        }
        self.aliases.push(declaration);
        Ok(())
    }

    /// Declares one constant site.
    pub fn declare_constant(&mut self, site: AdtConstantSite) -> Result<(), AdtError> {
        if self.constants.iter().any(|entry| entry.name == site.name) {
            return Err(AdtError::new(
                AdtDiagnosticCode::DuplicateConstructor,
                format!("constant site {} is declared twice", site.name),
            ));
        }
        self.constants.push(site);
        Ok(())
    }

    /// Refuses a mutable package global (`GNT-36.9`).
    pub fn declare_mutable_global(&self, name: &str) -> Result<(), AdtError> {
        Err(AdtError::new(
            AdtDiagnosticCode::MutableGlobal,
            format!("mutable package global {name} is not admitted"),
        ))
    }

    /// Validates and publishes the declaration set.
    pub fn finish(self) -> Result<AdtPackageModel, AdtError> {
        let mut model = AdtPackageModel {
            package: self.package,
            leaves: self.leaves,
            types: self.types,
            aliases: self.aliases,
            constants: self.constants,
            labels: AdtBoundaryLabels::new(),
        };
        model.resolve()?;
        model.check_visibility()?;
        model.check_productivity()?;
        model.check_constants()?;
        Ok(model)
    }
}

/// A validated declaration set.
#[derive(Clone, Debug)]
pub struct AdtPackageModel {
    package: String,
    leaves: BTreeSet<String>,
    types: Vec<AdtTypeDeclaration>,
    aliases: Vec<AdtAliasDeclaration>,
    constants: Vec<AdtConstantSite>,
    labels: AdtBoundaryLabels,
}

impl AdtPackageModel {
    /// The owning package identity.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// The declared type names, in declaration order.
    #[must_use]
    pub fn type_names(&self) -> Vec<&str> {
        self.types.iter().map(|entry| entry.name.as_str()).collect()
    }

    /// Resolves a name through aliases to a declared type, when one exists.
    #[must_use]
    pub fn resolve_type<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        if self.types.iter().any(|entry| entry.name == name) {
            return Some(name);
        }
        self.aliases
            .iter()
            .find(|entry| entry.name == name)
            .and_then(|entry| self.resolve_type(&entry.target))
    }

    /// Resolves a name through aliases to a declared type or scalar leaf (`GNT-36.4`).
    #[must_use]
    pub fn resolve_name<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        if self.types.iter().any(|entry| entry.name == name) || self.leaves.contains(name) {
            return Some(name);
        }
        self.aliases
            .iter()
            .find(|entry| entry.name == name)
            .and_then(|entry| self.resolve_name(&entry.target))
    }

    /// The identity of one constructor.
    #[must_use]
    pub fn constructor_identity(
        &self,
        type_name: &str,
        constructor_name: &str,
    ) -> Option<AdtConstructorIdentity> {
        let resolved = self.resolve_type(type_name)?;
        let declaration = self.types.iter().find(|entry| entry.name == resolved)?;
        let constructor = declaration
            .constructors
            .iter()
            .find(|entry| entry.name == constructor_name)?;
        let fields: Vec<String> = constructor
            .fields
            .iter()
            .map(|field| {
                encode_component(
                    self.resolve_name(&field.type_name)
                        .unwrap_or(&field.type_name),
                )
            })
            .collect();
        Some(AdtConstructorIdentity(format!(
            "{}::{}::{}.{}#({})",
            encode_component(&self.package),
            encode_component(resolved),
            encode_component(&constructor.name),
            constructor.tag,
            fields.join(",")
        )))
    }

    /// The canonical schema, closed over declarations and independent of boundary labels.
    #[must_use]
    pub fn canonical_schema(&self) -> String {
        let mut lines = vec![format!("package {}", encode_component(&self.package))];
        for leaf in &self.leaves {
            lines.push(format!("leaf {}", encode_component(leaf)));
        }
        let mut types: Vec<&AdtTypeDeclaration> = self.types.iter().collect();
        types.sort_by(|left, right| left.name.cmp(&right.name));
        for declaration in types {
            lines.push(format!(
                "type {} {} params[{}]",
                encode_component(&declaration.name),
                declaration.visibility.as_str(),
                declaration
                    .parameters
                    .iter()
                    .map(|parameter| encode_component(parameter))
                    .collect::<Vec<String>>()
                    .join(",")
            ));
            let mut constructors: Vec<&AdtConstructor> = declaration.constructors.iter().collect();
            constructors.sort_by_key(|constructor| constructor.tag);
            for constructor in constructors {
                lines.push(format!(
                    "construct {}#{} fields[{}]",
                    encode_component(&constructor.name),
                    constructor.tag,
                    constructor
                        .fields
                        .iter()
                        .map(|field| format!(
                            "{}:{}",
                            encode_component(&field.name),
                            encode_component(
                                self.resolve_name(&field.type_name)
                                    .unwrap_or(&field.type_name)
                            )
                        ))
                        .collect::<Vec<String>>()
                        .join(";")
                ));
            }
        }
        let mut aliases: Vec<&AdtAliasDeclaration> = self.aliases.iter().collect();
        aliases.sort_by(|left, right| left.name.cmp(&right.name));
        for alias in aliases {
            lines.push(format!(
                "alias {} {} params[{}] -> {}",
                encode_component(&alias.name),
                alias.visibility.as_str(),
                alias
                    .parameters
                    .iter()
                    .map(|parameter| encode_component(parameter))
                    .collect::<Vec<String>>()
                    .join(","),
                encode_component(self.resolve_name(&alias.target).unwrap_or(&alias.target))
            ));
        }
        let mut constants: Vec<&AdtConstantSite> = self.constants.iter().collect();
        constants.sort_by(|left, right| left.name.cmp(&right.name));
        for site in constants {
            lines.push(format!(
                "constant {} {} : {} = {}",
                encode_component(&site.name),
                site.visibility.as_str(),
                encode_component(
                    self.resolve_name(&site.type_name)
                        .unwrap_or(&site.type_name)
                ),
                match &site.value {
                    AdtConstantValue::Tree(tree) => self.encode_tree(tree),
                    AdtConstantValue::Deferred { .. } => "deferred".to_owned(),
                }
            ));
        }
        lines.join("\n")
    }

    /// Encodes one constant tree with alias-resolved node type names (`GNT-36.4`).
    ///
    /// An alias never creates a second identity for its target, so a node spelled with
    /// an alias encodes exactly like the same node spelled with the resolved
    /// declaration: no alias spelling reaches the canonical schema or the identity.
    fn encode_tree(&self, tree: &AdtConstantTree) -> String {
        match tree {
            AdtConstantTree::Scalar(value) => format!("scalar({value})"),
            AdtConstantTree::Constructor {
                type_name,
                constructor,
                arguments,
            } => format!(
                "node({}::{}{})",
                encode_component(self.resolve_name(type_name).unwrap_or(type_name)),
                encode_component(constructor),
                arguments
                    .iter()
                    .map(|argument| format!("[{}]", self.encode_tree(argument)))
                    .collect::<Vec<String>>()
                    .join("")
            ),
        }
    }

    /// The stable identity of the declaration set.
    #[must_use]
    pub fn identity(&self) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.canonical_schema().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{}:{hash:016x}", self.package)
    }

    /// The boundary labels of this declaration set (nonsemantic).
    #[must_use]
    pub fn boundary_labels(&self) -> &AdtBoundaryLabels {
        &self.labels
    }

    /// Returns the same declarations carrying the given boundary labels.
    #[must_use]
    pub fn with_boundary_labels(&self, labels: AdtBoundaryLabels) -> Self {
        let mut clone = self.clone();
        clone.labels = labels;
        clone
    }

    /// Refuses a presented schema that diverges from the canonical schema (`GNT-36.10`).
    pub fn verify_schema(&self, presented: &str) -> Result<(), AdtError> {
        let canonical = self.canonical_schema();
        if canonical == presented {
            Ok(())
        } else {
            Err(AdtError::new(
                AdtDiagnosticCode::SchemaDivergence,
                "presented schema diverges from the canonical declaration schema",
            ))
        }
    }

    /// Checks that the given patterns cover every declared constructor path (`GNT-36.7`).
    pub fn match_coverage(
        &self,
        type_name: &str,
        patterns: &[AdtPattern],
    ) -> Result<AdtMatchReport, AdtError> {
        let resolved = self.resolve_type(type_name).ok_or_else(|| {
            AdtError::new(
                AdtDiagnosticCode::UnresolvedReference,
                format!("type {type_name} is not declared"),
            )
        })?;
        let declaration = self
            .types
            .iter()
            .find(|entry| entry.name == resolved)
            .ok_or_else(|| {
                AdtError::new(
                    AdtDiagnosticCode::UnresolvedReference,
                    format!("type {resolved} is not declared"),
                )
            })?;
        let mut covered = Vec::new();
        let mut checked_paths = 0;
        let mut ordered: Vec<&AdtConstructor> = declaration.constructors.iter().collect();
        ordered.sort_by_key(|constructor| constructor.tag);
        for constructor in ordered {
            let pattern = patterns
                .iter()
                .find(|entry| entry.constructor == constructor.name)
                .ok_or_else(|| {
                    AdtError::new(
                        AdtDiagnosticCode::IncompleteMatch,
                        format!("{}::{} is not covered", resolved, constructor.name),
                    )
                })?;
            checked_paths += 1;
            if pattern.arguments.len() != constructor.fields.len() {
                return Err(AdtError::new(
                    AdtDiagnosticCode::ConstructorArity,
                    format!(
                        "{}::{} takes {} sub-patterns",
                        resolved,
                        constructor.name,
                        constructor.fields.len()
                    ),
                ));
            }
            for (field, argument) in constructor.fields.iter().zip(&pattern.arguments) {
                self.check_sub_pattern(&field.type_name, argument, &mut checked_paths)?;
            }
            covered.push(constructor.name.clone());
        }
        for pattern in patterns {
            if !declaration
                .constructors
                .iter()
                .any(|constructor| constructor.name == pattern.constructor)
            {
                return Err(AdtError::new(
                    AdtDiagnosticCode::UnknownConstructor,
                    format!(
                        "pattern names {}::{} which the type does not declare",
                        resolved, pattern.constructor
                    ),
                ));
            }
        }
        Ok(AdtMatchReport {
            covered,
            checked_paths,
        })
    }

    fn check_sub_pattern(
        &self,
        type_name: &str,
        pattern: &AdtSubPattern,
        checked_paths: &mut usize,
    ) -> Result<(), AdtError> {
        match self.resolve_type(type_name) {
            Some(resolved) => {
                let AdtSubPattern::Constructor(pattern) = pattern else {
                    // A binding, wildcard, or literal covers its whole subtree (`GNT-36.7`).
                    return Ok(());
                };
                let declaration = self
                    .types
                    .iter()
                    .find(|entry| entry.name == resolved)
                    .ok_or_else(|| {
                        AdtError::new(
                            AdtDiagnosticCode::UnresolvedReference,
                            format!("type {resolved} is not declared"),
                        )
                    })?;
                let constructor = declaration
                    .constructors
                    .iter()
                    .find(|entry| entry.name == pattern.constructor)
                    .ok_or_else(|| {
                        AdtError::new(
                            AdtDiagnosticCode::UnknownConstructor,
                            format!(
                                "pattern names {}::{} which the type does not declare",
                                resolved, pattern.constructor
                            ),
                        )
                    })?;
                if constructor.fields.len() != pattern.arguments.len() {
                    return Err(AdtError::new(
                        AdtDiagnosticCode::ConstructorArity,
                        format!(
                            "{}::{} takes {} sub-patterns",
                            resolved,
                            pattern.constructor,
                            constructor.fields.len()
                        ),
                    ));
                }
                *checked_paths += 1;
                for (field, argument) in constructor.fields.iter().zip(&pattern.arguments) {
                    self.check_sub_pattern(&field.type_name, argument, checked_paths)?;
                }
                Ok(())
            }
            None => match self.resolve_name(type_name) {
                Some(resolved) if self.leaves.contains(resolved) => match pattern {
                    AdtSubPattern::Scalar => Ok(()),
                    AdtSubPattern::Constructor(_) => Err(AdtError::new(
                        AdtDiagnosticCode::PatternShape,
                        format!(
                            "{type_name} resolves to scalar leaf {resolved}; scalar leaves admit no constructor sub-pattern"
                        ),
                    )),
                },
                _ => Ok(()),
            },
        }
    }

    /// Charges one constant site against a budget (`GNT-36.8`).
    pub fn charge_constant(
        &self,
        name: &str,
        budget: &AdtConstantBudget,
    ) -> Result<AdtCharge, AdtError> {
        let site = self
            .constants
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| {
                AdtError::new(
                    AdtDiagnosticCode::ConstantForm,
                    format!("constant site {name} is not declared"),
                )
            })?;
        let tree = match &site.value {
            AdtConstantValue::Tree(tree) => tree,
            AdtConstantValue::Deferred { reason } => {
                return Err(AdtError::new(
                    AdtDiagnosticCode::ConstantForm,
                    format!("constant site {name} is deferred: {reason}"),
                ));
            }
        };
        let charge = AdtCharge {
            nodes: tree.nodes(),
            depth: tree.depth(),
        };
        if charge.nodes > budget.max_nodes || charge.depth > budget.max_depth {
            return Err(AdtError::new(
                AdtDiagnosticCode::ConstantLimit,
                format!(
                    "constant site {name} charges {} nodes and depth {}",
                    charge.nodes, charge.depth
                ),
            ));
        }
        Ok(charge)
    }

    /// The package-load fact of this declaration set (`GNT-36.9`).
    #[must_use]
    pub fn package_load(&self) -> AdtPackageLoad {
        AdtPackageLoad {
            declarations: self.types.len() + self.aliases.len() + self.constants.len(),
            executed_statements: 0,
            executed_declarations: 0,
        }
    }

    /// The durable projection of this declaration set (`GNT-36.11`).
    #[must_use]
    pub fn durable_projection(&self) -> AdtDurableProjection {
        let mut types = self.types.clone();
        types.sort_by(|left, right| left.name.cmp(&right.name));
        for declaration in &mut types {
            declaration
                .constructors
                .sort_by_key(|constructor| constructor.tag);
        }
        let mut aliases = self.aliases.clone();
        aliases.sort_by(|left, right| left.name.cmp(&right.name));
        let mut constants = self.constants.clone();
        constants.sort_by(|left, right| left.name.cmp(&right.name));
        AdtDurableProjection {
            package: self.package.clone(),
            leaves: self.leaves.iter().cloned().collect(),
            types,
            aliases,
            constants,
            identity: self.identity(),
        }
    }

    /// Rebuilds a declaration set from a durable projection.
    pub fn from_projection(projection: &AdtDurableProjection) -> Result<Self, AdtError> {
        // A projection is derived from a validated model, so a carried declaration the
        // rebuild refuses is an omitted, reordered, or altered one: the refusal names
        // the round trip rather than the clause that would own the same declaration in
        // an ordinary declaration set (`GNT-36.11`).
        let rebuild = || -> Result<Self, AdtError> {
            let mut builder = AdtPackageBuilder::new(projection.package.clone());
            for leaf in &projection.leaves {
                builder.declare_leaf(leaf);
            }
            for declaration in &projection.types {
                builder.declare_type(declaration.clone())?;
            }
            for alias in &projection.aliases {
                builder.declare_alias(alias.clone())?;
            }
            for site in &projection.constants {
                builder.declare_constant(site.clone())?;
            }
            builder.finish()
        };
        let model = rebuild().map_err(|error| {
            AdtError::new(
                AdtDiagnosticCode::RoundTripLoss,
                format!(
                    "the projection carries a declaration that does not rebuild ({}): {}",
                    error.code().code(),
                    error.detail()
                ),
            )
        })?;
        let canonical = model.durable_projection();
        if canonical.leaves != projection.leaves
            || canonical.types != projection.types
            || canonical.aliases != projection.aliases
            || canonical.constants != projection.constants
        {
            return Err(AdtError::new(
                AdtDiagnosticCode::RoundTripLoss,
                "the projection omits, reorders, duplicates, or alters a carried declaration",
            ));
        }
        if model.identity() != projection.identity {
            return Err(AdtError::new(
                AdtDiagnosticCode::RoundTripLoss,
                "the projection does not rebuild the projected identity",
            ));
        }
        Ok(model)
    }

    fn resolve(&mut self) -> Result<(), AdtError> {
        let mut available: BTreeSet<String> = self.leaves.clone();
        available.extend(self.types.iter().map(|entry| entry.name.clone()));
        available.extend(self.aliases.iter().map(|entry| entry.name.clone()));

        for alias in &self.aliases {
            if !available.contains(&alias.target) {
                return Err(AdtError::new(
                    AdtDiagnosticCode::UnresolvedReference,
                    format!(
                        "alias {} names undeclared type {}",
                        alias.name, alias.target
                    ),
                ));
            }
            let mut visited = BTreeSet::new();
            let mut current = alias.name.clone();
            while let Some(next) = self
                .aliases
                .iter()
                .find(|entry| entry.name == current)
                .map(|entry| entry.target.clone())
            {
                if !visited.insert(current.clone()) || next == alias.name {
                    return Err(AdtError::new(
                        AdtDiagnosticCode::AliasCycle,
                        format!("alias {} participates in an alias-only cycle", alias.name),
                    ));
                }
                current = next;
            }
            let expected = self.alias_target_parameters(&alias.target);
            if alias.parameters != expected {
                return Err(AdtError::new(
                    AdtDiagnosticCode::AliasArity,
                    format!(
                        "alias {} declares parameters [{}] but its resolved target {} declares [{}]",
                        alias.name,
                        alias.parameters.join(", "),
                        alias.target,
                        expected.join(", ")
                    ),
                ));
            }
        }
        for declaration in &self.types {
            for constructor in &declaration.constructors {
                for field in &constructor.fields {
                    if !available.contains(&field.type_name) {
                        return Err(AdtError::new(
                            AdtDiagnosticCode::UnresolvedReference,
                            format!(
                                "{}::{}.{} names undeclared type {}",
                                declaration.name, constructor.name, field.name, field.type_name
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// The exact parameter list an alias target requires (`GNT-36.4`).
    fn alias_target_parameters(&self, target: &str) -> Vec<String> {
        if let Some(declaration) = self.types.iter().find(|entry| entry.name == target) {
            return declaration.parameters.clone();
        }
        if let Some(alias) = self.aliases.iter().find(|entry| entry.name == target) {
            return alias.parameters.clone();
        }
        Vec::new()
    }

    fn check_visibility(&self) -> Result<(), AdtError> {
        for declaration in &self.types {
            for constructor in &declaration.constructors {
                for field in &constructor.fields {
                    let referenced = self
                        .types
                        .iter()
                        .find(|entry| entry.name == field.type_name)
                        .map(|entry| entry.visibility)
                        .or_else(|| {
                            self.aliases
                                .iter()
                                .find(|entry| entry.name == field.type_name)
                                .map(|entry| entry.visibility)
                        });
                    if let Some(visibility) = referenced
                        && !visibility.admits_reference_from(declaration.visibility)
                    {
                        return Err(AdtError::new(
                            AdtDiagnosticCode::InvisibleReference,
                            format!(
                                "{} {} references {} {}",
                                declaration.visibility.as_str(),
                                declaration.name,
                                visibility.as_str(),
                                field.type_name
                            ),
                        ));
                    }
                }
            }
        }
        for alias in &self.aliases {
            let referenced = self
                .types
                .iter()
                .find(|entry| entry.name == alias.target)
                .map(|entry| entry.visibility)
                .or_else(|| {
                    self.aliases
                        .iter()
                        .find(|entry| entry.name == alias.target)
                        .map(|entry| entry.visibility)
                });
            if let Some(visibility) = referenced
                && !visibility.admits_reference_from(alias.visibility)
            {
                return Err(AdtError::new(
                    AdtDiagnosticCode::InvisibleReference,
                    format!(
                        "{} alias {} references {} {}",
                        alias.visibility.as_str(),
                        alias.name,
                        visibility.as_str(),
                        alias.target
                    ),
                ));
            }
        }
        for site in &self.constants {
            let referenced = self
                .types
                .iter()
                .find(|entry| entry.name == site.type_name)
                .map(|entry| entry.visibility)
                .or_else(|| {
                    self.aliases
                        .iter()
                        .find(|entry| entry.name == site.type_name)
                        .map(|entry| entry.visibility)
                });
            if let Some(visibility) = referenced
                && !visibility.admits_reference_from(site.visibility)
            {
                return Err(AdtError::new(
                    AdtDiagnosticCode::InvisibleReference,
                    format!(
                        "{} constant {} references {} {}",
                        site.visibility.as_str(),
                        site.name,
                        visibility.as_str(),
                        site.type_name
                    ),
                ));
            }
        }
        Ok(())
    }

    fn check_productivity(&self) -> Result<(), AdtError> {
        let mut buildable: BTreeSet<String> = self.leaves.clone();
        loop {
            let mut changed = false;
            for declaration in &self.types {
                if buildable.contains(&declaration.name) {
                    continue;
                }
                let inhabited = declaration.constructors.iter().any(|constructor| {
                    constructor.fields.iter().all(|field| {
                        self.resolve_name(&field.type_name)
                            .map(|resolved| buildable.contains(resolved))
                            .unwrap_or_else(|| buildable.contains(&field.type_name))
                    })
                });
                if inhabited {
                    buildable.insert(declaration.name.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for declaration in &self.types {
            if !buildable.contains(&declaration.name) {
                return Err(AdtError::new(
                    AdtDiagnosticCode::UnproductiveRecursion,
                    format!(
                        "type {} has no finite value: every constructor recurses",
                        declaration.name
                    ),
                ));
            }
        }
        Ok(())
    }

    fn check_constants(&self) -> Result<(), AdtError> {
        for site in &self.constants {
            let resolved = self.resolve_type(&site.type_name).ok_or_else(|| {
                AdtError::new(
                    AdtDiagnosticCode::UnresolvedReference,
                    format!(
                        "constant {} names undeclared type {}",
                        site.name, site.type_name
                    ),
                )
            })?;
            match &site.value {
                AdtConstantValue::Deferred { reason } => {
                    return Err(AdtError::new(
                        AdtDiagnosticCode::ConstantForm,
                        format!("constant {} is deferred: {reason}", site.name),
                    ));
                }
                AdtConstantValue::Tree(tree) => {
                    self.check_tree(resolved, tree)?;
                }
            }
        }
        Ok(())
    }

    fn check_tree(&self, type_name: &str, tree: &AdtConstantTree) -> Result<(), AdtError> {
        let resolved = self.resolve_type(type_name);
        match (resolved, tree) {
            (
                Some(resolved),
                AdtConstantTree::Constructor {
                    type_name: node_type,
                    constructor,
                    arguments,
                },
            ) => {
                if self.resolve_type(node_type).unwrap_or(node_type) != resolved {
                    return Err(AdtError::new(
                        AdtDiagnosticCode::ConstantForm,
                        format!("{node_type}::{constructor} is not a value of {resolved}"),
                    ));
                }
                let declaration = self
                    .types
                    .iter()
                    .find(|entry| entry.name == resolved)
                    .ok_or_else(|| {
                        AdtError::new(
                            AdtDiagnosticCode::UnresolvedReference,
                            format!("type {resolved} is not declared"),
                        )
                    })?;
                let declared = declaration
                    .constructors
                    .iter()
                    .find(|entry| entry.name == *constructor)
                    .ok_or_else(|| {
                        AdtError::new(
                            AdtDiagnosticCode::UnknownConstructor,
                            format!("{resolved} does not declare {constructor}"),
                        )
                    })?;
                if declared.fields.len() != arguments.len() {
                    return Err(AdtError::new(
                        AdtDiagnosticCode::ConstructorArity,
                        format!(
                            "{resolved}::{constructor} takes {} arguments",
                            declared.fields.len()
                        ),
                    ));
                }
                for (field, argument) in declared.fields.iter().zip(arguments) {
                    self.check_tree(&field.type_name, argument)?;
                }
                Ok(())
            }
            (Some(resolved), AdtConstantTree::Scalar(_)) => Err(AdtError::new(
                AdtDiagnosticCode::ConstantForm,
                format!("{resolved} is not a scalar leaf type"),
            )),
            (None, AdtConstantTree::Scalar(_)) => Ok(()),
            (None, AdtConstantTree::Constructor { constructor, .. }) => Err(AdtError::new(
                AdtDiagnosticCode::UnresolvedReference,
                format!("{type_name} does not declare {constructor}"),
            )),
        }
    }
}

impl AdtConstantTree {
    /// The charged node count of the tree.
    #[must_use]
    pub fn nodes(&self) -> usize {
        match self {
            Self::Scalar(_) => 1,
            Self::Constructor { arguments, .. } => {
                1 + arguments.iter().map(Self::nodes).sum::<usize>()
            }
        }
    }

    /// The charged depth of the tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Scalar(_) => 1,
            Self::Constructor { arguments, .. } => {
                1 + arguments.iter().map(Self::depth).max().unwrap_or(0)
            }
        }
    }
}

/// A Section 36 non-claim (`GNT-36.12`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdtNonClaimName {
    /// Runtime representation or memory layout.
    RuntimeRepresentation,
    /// Cyclic or shared runtime values.
    CyclicValues,
    /// Dynamic dispatch or trait solving.
    DynamicDispatch,
    /// Boundary wire formats or codecs.
    BoundaryFormats,
    /// Hidden initializers.
    HiddenInitializers,
    /// Mutable package globals.
    MutableGlobals,
    /// Unguarded or unproductive recursion.
    UnguardedRecursion,
    /// Validity derived from boundary or recovery eligibility.
    BoundaryValidity,
}

impl AdtNonClaimName {
    /// Every declared non-claim, in declaration order.
    pub const ALL: [Self; 8] = [
        Self::RuntimeRepresentation,
        Self::CyclicValues,
        Self::DynamicDispatch,
        Self::BoundaryFormats,
        Self::HiddenInitializers,
        Self::MutableGlobals,
        Self::UnguardedRecursion,
        Self::BoundaryValidity,
    ];

    /// The canonical spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeRepresentation => "runtime-representation",
            Self::CyclicValues => "cyclic-values",
            Self::DynamicDispatch => "dynamic-dispatch",
            Self::BoundaryFormats => "boundary-formats",
            Self::HiddenInitializers => "hidden-initializers",
            Self::MutableGlobals => "mutable-globals",
            Self::UnguardedRecursion => "unguarded-recursion",
            Self::BoundaryValidity => "boundary-validity",
        }
    }
}

/// One asserted non-claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdtNonClaimAssertion {
    /// The asserted non-claim.
    pub name: AdtNonClaimName,
    /// Whether the assertion presents the non-claim as a guarantee.
    pub claims_as_guarantee: bool,
}

/// Verifies that every non-claim is asserted and none is presented as a guarantee.
pub fn check_adt_non_claims(assertions: &[AdtNonClaimAssertion]) -> Result<(), AdtError> {
    for name in AdtNonClaimName::ALL {
        let asserted = assertions.iter().find(|entry| entry.name == name);
        match asserted {
            None => {
                return Err(AdtError::new(
                    AdtDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is not asserted", name.as_str()),
                ));
            }
            Some(entry) if entry.claims_as_guarantee => {
                return Err(AdtError::new(
                    AdtDiagnosticCode::NonClaimAsGuarantee,
                    format!("non-claim {} is presented as a guarantee", name.as_str()),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}
