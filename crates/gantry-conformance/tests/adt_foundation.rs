//! Section 36 recursive algebraic data type evidence.

use gantry::ir::{
    ADT_CLAUSES, AdtAliasDeclaration, AdtBoundaryLabels, AdtConstantBudget, AdtConstantSite,
    AdtConstantTree, AdtConstantValue, AdtConstructor, AdtDiagnosticCode, AdtDurableProjection,
    AdtError, AdtField, AdtMatchReport, AdtNonClaimAssertion, AdtNonClaimName, AdtPackageBuilder,
    AdtPackageModel, AdtPattern, AdtTypeDeclaration, AdtVisibility, check_adt_non_claims,
};

/// Returns the refusal produced by one rejected decision.
trait Refused<E> {
    fn refused(self, context: &str) -> E;
}

impl<T, E> Refused<E> for Result<T, E> {
    fn refused(self, context: &str) -> E {
        match self {
            Ok(_) => panic!("{context}: the decision must be refused"),
            Err(error) => error,
        }
    }
}

fn field(name: &str, type_name: &str) -> AdtField {
    AdtField {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
    }
}

fn constructor(name: &str, tag: u32, fields: Vec<AdtField>) -> AdtConstructor {
    AdtConstructor {
        name: name.to_owned(),
        tag,
        parameters: Vec::new(),
        fields,
    }
}

fn declaration(
    name: &str,
    visibility: AdtVisibility,
    constructors: Vec<AdtConstructor>,
) -> AdtTypeDeclaration {
    AdtTypeDeclaration {
        name: name.to_owned(),
        visibility,
        parameters: Vec::new(),
        constructors,
    }
}

fn declare(builder: &mut AdtPackageBuilder, declaration: AdtTypeDeclaration) {
    builder
        .declare_type(declaration)
        .unwrap_or_else(|error| panic!("declaration: {error}"));
}

fn list_type(visibility: AdtVisibility) -> AdtTypeDeclaration {
    declaration(
        "List",
        visibility,
        vec![
            constructor("Nil", 0, Vec::new()),
            constructor("Cons", 1, vec![field("head", "Int"), field("tail", "List")]),
        ],
    )
}

fn package_with_list() -> AdtPackageModel {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"))
}

fn pattern(constructor: &str, arguments: Vec<AdtPattern>) -> AdtPattern {
    AdtPattern {
        constructor: constructor.to_owned(),
        arguments,
    }
}

fn tree_scalar(value: i64) -> AdtConstantTree {
    AdtConstantTree::Scalar(value)
}

fn tree_node(
    type_name: &str,
    constructor: &str,
    arguments: Vec<AdtConstantTree>,
) -> AdtConstantTree {
    AdtConstantTree::Constructor {
        type_name: type_name.to_owned(),
        constructor: constructor.to_owned(),
        arguments,
    }
}

#[test]
fn section_36_anchors_and_nonclaims_are_published() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"))
        .unwrap_or_else(|error| panic!("SPEC.md: {error}"));
    assert_eq!(ADT_CLAUSES.len(), 13);
    for clause in ADT_CLAUSES {
        assert!(
            spec.contains(&format!("<a id=\"{clause}\"></a>")),
            "{clause} is not published"
        );
        assert!(
            spec.contains(&format!("**[{clause}] ")),
            "{clause} carries no clause text"
        );
    }
    assert_eq!(AdtDiagnosticCode::ALL.len(), 14);
    for code in AdtDiagnosticCode::ALL {
        assert!(
            spec.contains(&format!("`{}`", code.code())),
            "{} is not published",
            code.code()
        );
    }
    let assertions: Vec<AdtNonClaimAssertion> = AdtNonClaimName::ALL
        .iter()
        .map(|name| AdtNonClaimAssertion {
            name: *name,
            claims_as_guarantee: false,
        })
        .collect();
    check_adt_non_claims(&assertions).unwrap_or_else(|error| panic!("non-claims: {error}"));
    let mut overclaiming = assertions.clone();
    overclaiming[0].claims_as_guarantee = true;
    assert_eq!(
        check_adt_non_claims(&overclaiming)
            .refused("an overclaiming assertion")
            .code(),
        AdtDiagnosticCode::NonClaimAsGuarantee
    );
    let mut missing = assertions;
    missing.pop();
    assert_eq!(
        check_adt_non_claims(&missing)
            .refused("a missing non-claim")
            .code(),
        AdtDiagnosticCode::NonClaimAsGuarantee
    );
}

#[test]
fn productive_and_unproductive_recursion_are_distinguished() {
    let model = package_with_list();
    assert_eq!(model.type_names(), vec!["List"]);
    assert!(model.constructor_identity("List", "Cons").is_some());

    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder
        .declare_type(declaration(
            "Infinite",
            AdtVisibility::Public,
            vec![constructor("Step", 0, vec![field("next", "Infinite")])],
        ))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    assert_eq!(
        builder
            .finish()
            .refused("a type with no finite value")
            .code(),
        AdtDiagnosticCode::UnproductiveRecursion
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(
        &mut builder,
        declaration(
            "A",
            AdtVisibility::Package,
            vec![
                constructor("AEnd", 0, Vec::new()),
                constructor("AStep", 1, vec![field("b", "B")]),
            ],
        ),
    );
    declare(
        &mut builder,
        declaration(
            "B",
            AdtVisibility::Package,
            vec![constructor("BStep", 0, vec![field("a", "A")])],
        ),
    );
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("mutual: {error}"));
    assert_eq!(model.type_names(), vec!["A", "B"]);

    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(
        &mut builder,
        declaration(
            "A",
            AdtVisibility::Package,
            vec![constructor("AStep", 0, vec![field("b", "B")])],
        ),
    );
    declare(
        &mut builder,
        declaration(
            "B",
            AdtVisibility::Package,
            vec![constructor("BStep", 0, vec![field("a", "A")])],
        ),
    );
    assert_eq!(
        builder
            .finish()
            .refused("mutual recursion without a finite value")
            .code(),
        AdtDiagnosticCode::UnproductiveRecursion
    );
}

#[test]
fn mutual_recursion_is_order_independent() {
    let mut forward = AdtPackageBuilder::new("gantry.example");
    forward.declare_leaf("Int");
    declare(
        &mut forward,
        declaration(
            "Forest",
            AdtVisibility::Public,
            vec![
                constructor("Empty", 0, Vec::new()),
                constructor(
                    "Trees",
                    1,
                    vec![field("tree", "Tree"), field("rest", "Forest")],
                ),
            ],
        ),
    );
    declare(
        &mut forward,
        declaration(
            "Tree",
            AdtVisibility::Public,
            vec![constructor(
                "Node",
                0,
                vec![field("value", "Int"), field("children", "Forest")],
            )],
        ),
    );
    let forward = forward
        .finish()
        .unwrap_or_else(|error| panic!("forward: {error}"));

    let mut reverse = AdtPackageBuilder::new("gantry.example");
    reverse.declare_leaf("Int");
    declare(
        &mut reverse,
        declaration(
            "Tree",
            AdtVisibility::Public,
            vec![constructor(
                "Node",
                0,
                vec![field("value", "Int"), field("children", "Forest")],
            )],
        ),
    );
    declare(
        &mut reverse,
        declaration(
            "Forest",
            AdtVisibility::Public,
            vec![
                constructor("Empty", 0, Vec::new()),
                constructor(
                    "Trees",
                    1,
                    vec![field("tree", "Tree"), field("rest", "Forest")],
                ),
            ],
        ),
    );
    let reverse = reverse
        .finish()
        .unwrap_or_else(|error| panic!("reverse: {error}"));

    assert_eq!(forward.canonical_schema(), reverse.canonical_schema());
    assert_eq!(forward.identity(), reverse.identity());
    assert_eq!(
        forward.constructor_identity("Forest", "Trees"),
        reverse.constructor_identity("Forest", "Trees")
    );
}

#[test]
fn aliases_resolve_transitively_and_cycles_are_refused() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    declare(&mut builder, list_type(AdtVisibility::Public));
    builder
        .declare_alias(AdtAliasDeclaration {
            name: "Ints".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: Vec::new(),
            target: "List".to_owned(),
        })
        .unwrap_or_else(|error| panic!("alias: {error}"));
    builder
        .declare_alias(AdtAliasDeclaration {
            name: "ManyInts".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: Vec::new(),
            target: "Ints".to_owned(),
        })
        .unwrap_or_else(|error| panic!("alias: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    assert_eq!(model.resolve_type("ManyInts"), Some("List"));
    assert_eq!(
        model.constructor_identity("ManyInts", "Cons"),
        model.constructor_identity("List", "Cons")
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_alias(AdtAliasDeclaration {
            name: "Left".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: Vec::new(),
            target: "Right".to_owned(),
        })
        .unwrap_or_else(|error| panic!("alias: {error}"));
    builder
        .declare_alias(AdtAliasDeclaration {
            name: "Right".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: Vec::new(),
            target: "Left".to_owned(),
        })
        .unwrap_or_else(|error| panic!("alias: {error}"));
    assert_eq!(
        builder.finish().refused("an alias-only cycle").code(),
        AdtDiagnosticCode::AliasCycle
    );
}

#[test]
fn constructors_must_carry_their_type_parameter_list() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(AdtTypeDeclaration {
            name: "Boxed".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: vec!["T".to_owned()],
            constructors: vec![AdtConstructor {
                name: "Box".to_owned(),
                tag: 0,
                parameters: vec!["T".to_owned()],
                fields: vec![field("value", "Int")],
            }],
        })
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    assert_eq!(model.resolve_type("Boxed"), Some("Boxed"));

    let mut mismatch = AdtPackageBuilder::new("gantry.example");
    mismatch.declare_leaf("Int");
    assert_eq!(
        mismatch
            .declare_type(AdtTypeDeclaration {
                name: "Boxed".to_owned(),
                visibility: AdtVisibility::Public,
                parameters: vec!["T".to_owned()],
                constructors: vec![AdtConstructor {
                    name: "Box".to_owned(),
                    tag: 0,
                    parameters: Vec::new(),
                    fields: vec![field("value", "Int")],
                }],
            })
            .refused("a constructor departing from its type's parameter list")
            .code(),
        AdtDiagnosticCode::ConstructorArity
    );
}

#[test]
fn constant_sites_admit_only_open_enough_types() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    declare(
        &mut builder,
        declaration(
            "Hidden",
            AdtVisibility::Private,
            vec![constructor("Hidden", 0, Vec::new())],
        ),
    );
    builder
        .declare_constant(AdtConstantSite {
            name: "EXPOSED".to_owned(),
            visibility: AdtVisibility::Public,
            type_name: "Hidden".to_owned(),
            value: AdtConstantValue::Tree(tree_node("Hidden", "Hidden", Vec::new())),
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    assert_eq!(
        builder
            .finish()
            .refused("a public constant site naming a private type")
            .code(),
        AdtDiagnosticCode::InvisibleReference
    );

    let mut admitted = AdtPackageBuilder::new("gantry.example");
    admitted.declare_leaf("Int");
    declare(
        &mut admitted,
        declaration(
            "Hidden",
            AdtVisibility::Private,
            vec![constructor("Hidden", 0, Vec::new())],
        ),
    );
    admitted
        .declare_constant(AdtConstantSite {
            name: "INTERNAL".to_owned(),
            visibility: AdtVisibility::Private,
            type_name: "Hidden".to_owned(),
            value: AdtConstantValue::Tree(tree_node("Hidden", "Hidden", Vec::new())),
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    admitted
        .finish()
        .unwrap_or_else(|error| panic!("a private constant site may name a private type: {error}"));
}

#[test]
fn projections_refuse_altered_constant_values() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    builder
        .declare_constant(AdtConstantSite {
            name: "ONES".to_owned(),
            visibility: AdtVisibility::Public,
            type_name: "List".to_owned(),
            value: AdtConstantValue::Tree(tree_node(
                "List",
                "Cons",
                vec![tree_scalar(1), tree_node("List", "Nil", Vec::new())],
            )),
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    let projection = model.durable_projection();
    let rebuilt = AdtPackageModel::from_projection(&projection)
        .unwrap_or_else(|error| panic!("round trip: {error}"));
    assert_eq!(rebuilt.identity(), model.identity());

    let mut altered = projection.clone();
    altered.constants[0].value = AdtConstantValue::Tree(tree_node(
        "List",
        "Cons",
        vec![tree_scalar(2), tree_node("List", "Nil", Vec::new())],
    ));
    assert_eq!(
        AdtPackageModel::from_projection(&altered)
            .refused("a projection altering a constant value")
            .code(),
        AdtDiagnosticCode::RoundTripLoss
    );
}

#[test]
fn visibility_admits_only_open_enough_references() {
    assert!(AdtVisibility::Public.admits_reference_from(AdtVisibility::Package));
    assert!(AdtVisibility::Package.admits_reference_from(AdtVisibility::Package));
    assert!(!AdtVisibility::Private.admits_reference_from(AdtVisibility::Public));
    assert!(AdtVisibility::Public.admits_reference_from(AdtVisibility::Private));

    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(
        &mut builder,
        declaration(
            "Hidden",
            AdtVisibility::Private,
            vec![constructor("Hidden", 0, Vec::new())],
        ),
    );
    declare(
        &mut builder,
        declaration(
            "Exposed",
            AdtVisibility::Public,
            vec![constructor("Exposed", 0, vec![field("hidden", "Hidden")])],
        ),
    );
    assert_eq!(
        builder
            .finish()
            .refused("a public declaration exposing a private type")
            .code(),
        AdtDiagnosticCode::InvisibleReference
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(
        &mut builder,
        declaration(
            "Hidden",
            AdtVisibility::Private,
            vec![constructor("Hidden", 0, Vec::new())],
        ),
    );
    declare(
        &mut builder,
        declaration(
            "Envelope",
            AdtVisibility::Private,
            vec![constructor("Envelope", 0, vec![field("hidden", "Hidden")])],
        ),
    );
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("private: {error}"));
    assert!(model.constructor_identity("Envelope", "Envelope").is_some());
}

#[test]
fn duplicate_declarations_and_arity_irregularities_are_refused() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(&mut builder, list_type(AdtVisibility::Public));
    assert_eq!(
        builder
            .declare_type(list_type(AdtVisibility::Package))
            .refused("a duplicated type name")
            .code(),
        AdtDiagnosticCode::DuplicateConstructor
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    assert_eq!(
        builder
            .declare_type(declaration(
                "Pair",
                AdtVisibility::Public,
                vec![
                    constructor("First", 0, Vec::new()),
                    constructor("Second", 0, Vec::new()),
                ],
            ))
            .refused("a duplicated tag")
            .code(),
        AdtDiagnosticCode::DuplicateConstructor
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    declare(
        &mut builder,
        declaration(
            "Box",
            AdtVisibility::Public,
            vec![constructor("Box", 0, vec![field("value", "Int")])],
        ),
    );
    assert_eq!(
        builder.finish().refused("an undeclared field type").code(),
        AdtDiagnosticCode::UnresolvedReference
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    assert_eq!(
        builder
            .declare_type(declaration("Empty", AdtVisibility::Public, Vec::new()))
            .refused("a type with no constructor")
            .code(),
        AdtDiagnosticCode::DuplicateConstructor
    );
}

#[test]
fn patterns_cover_the_declared_constructor_space() {
    let model = package_with_list();
    let complete = vec![
        pattern("Nil", Vec::new()),
        pattern(
            "Cons",
            vec![pattern("Nil", Vec::new()), pattern("Nil", Vec::new())],
        ),
    ];
    let report: AdtMatchReport = model
        .match_coverage("List", &complete)
        .unwrap_or_else(|error| panic!("coverage: {error}"));
    assert_eq!(report.covered, vec!["Nil", "Cons"]);
    assert!(report.checked_paths >= 3);

    assert_eq!(
        model
            .match_coverage("List", &complete[..1])
            .refused("an uncovered constructor")
            .code(),
        AdtDiagnosticCode::IncompleteMatch
    );
    assert_eq!(
        model
            .match_coverage(
                "List",
                &[pattern("Nil", Vec::new()), pattern("Cons", Vec::new()),],
            )
            .refused("a sub-pattern arity mismatch")
            .code(),
        AdtDiagnosticCode::ConstructorArity
    );
    assert_eq!(
        model
            .match_coverage(
                "List",
                &[
                    pattern("Nil", Vec::new()),
                    pattern("Cons", vec![pattern("Nil", Vec::new()); 2]),
                    pattern("Absent", Vec::new()),
                ],
            )
            .refused("an unknown constructor")
            .code(),
        AdtDiagnosticCode::UnknownConstructor
    );

    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder
        .declare_type(declaration(
            "Only",
            AdtVisibility::Public,
            vec![constructor("Only", 0, Vec::new())],
        ))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    let single = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    assert_eq!(
        single
            .match_coverage("Only", &[])
            .refused("a single-constructor type still requires coverage")
            .code(),
        AdtDiagnosticCode::IncompleteMatch
    );
}

#[test]
fn coverage_reports_constructors_in_tag_order() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(declaration(
            "Choice",
            AdtVisibility::Public,
            vec![
                constructor("Later", 7, Vec::new()),
                constructor("Earlier", 2, Vec::new()),
            ],
        ))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    let report: AdtMatchReport = model
        .match_coverage(
            "Choice",
            &[pattern("Later", Vec::new()), pattern("Earlier", Vec::new())],
        )
        .unwrap_or_else(|error| panic!("coverage: {error}"));
    assert_eq!(report.covered, vec!["Earlier", "Later"]);
}

#[test]
fn constant_sites_are_finite_trees_with_charges() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    let tree = tree_node(
        "List",
        "Cons",
        vec![tree_scalar(1), tree_node("List", "Nil", Vec::new())],
    );
    builder
        .declare_constant(AdtConstantSite {
            name: "ONES".to_owned(),
            visibility: AdtVisibility::Public,
            type_name: "List".to_owned(),
            value: AdtConstantValue::Tree(tree),
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));
    let charge = model
        .charge_constant("ONES", &AdtConstantBudget::new(3, 2))
        .unwrap_or_else(|error| panic!("charge: {error}"));
    assert_eq!((charge.nodes, charge.depth), (3, 2));
    assert_eq!(
        model
            .charge_constant("ONES", &AdtConstantBudget::new(2, 2))
            .refused("a node budget")
            .code(),
        AdtDiagnosticCode::ConstantLimit
    );
    assert_eq!(
        model
            .charge_constant("ONES", &AdtConstantBudget::new(3, 1))
            .refused("a depth budget")
            .code(),
        AdtDiagnosticCode::ConstantLimit
    );

    let mut deferred = AdtPackageBuilder::new("gantry.example");
    deferred.declare_leaf("Int");
    deferred
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    deferred
        .declare_constant(AdtConstantSite {
            name: "DEVELOPER".to_owned(),
            visibility: AdtVisibility::Public,
            type_name: "List".to_owned(),
            value: AdtConstantValue::Deferred {
                reason: "host computation".to_owned(),
            },
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    assert_eq!(
        deferred
            .finish()
            .refused("a deferred constant value")
            .code(),
        AdtDiagnosticCode::ConstantForm
    );

    let mut scalar_leaf = AdtPackageBuilder::new("gantry.example");
    scalar_leaf.declare_leaf("Int");
    scalar_leaf
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    scalar_leaf
        .declare_constant(AdtConstantSite {
            name: "EMPTY".to_owned(),
            visibility: AdtVisibility::Public,
            type_name: "List".to_owned(),
            value: AdtConstantValue::Tree(tree_scalar(0)),
        })
        .unwrap_or_else(|error| panic!("constant: {error}"));
    assert_eq!(
        scalar_leaf
            .finish()
            .refused("a scalar standing in for a declared type")
            .code(),
        AdtDiagnosticCode::ConstantForm
    );
}

#[test]
fn declarations_do_not_execute_at_package_load() {
    let model = package_with_list();
    let load = model.package_load();
    assert_eq!(load.declarations, 1);
    assert_eq!(load.executed_statements, 0);
    assert_eq!(load.executed_declarations, 0);
    let builder = AdtPackageBuilder::new("gantry.example");
    assert_eq!(
        builder
            .declare_mutable_global("COUNTER")
            .refused("a mutable package global")
            .code(),
        AdtDiagnosticCode::MutableGlobal
    );
}

#[test]
fn schemas_and_identities_are_boundary_independent() {
    let model = package_with_list();
    let mut labels = AdtBoundaryLabels::new();
    labels.label("List", "Cons", "cons_cell");
    labels.label("List", "Nil", "empty");
    let labeled = model.with_boundary_labels(labels);
    assert_eq!(labeled.canonical_schema(), model.canonical_schema());
    assert_eq!(labeled.identity(), model.identity());
    assert_eq!(
        labeled.constructor_identity("List", "Cons"),
        model.constructor_identity("List", "Cons")
    );
    assert_eq!(
        labeled.boundary_labels().get("List", "Cons"),
        Some("cons_cell")
    );
    model
        .verify_schema(&model.canonical_schema())
        .unwrap_or_else(|error| panic!("canonical schema: {error}"));
    assert_eq!(
        model
            .verify_schema("package gantry.example\ntype List public params[]\n")
            .refused("a divergent schema")
            .code(),
        AdtDiagnosticCode::SchemaDivergence
    );
    assert_ne!(
        model.constructor_identity("List", "Cons"),
        model.constructor_identity("List", "Nil")
    );
}

#[test]
fn durable_projections_rebuild_identity() {
    let mut builder = AdtPackageBuilder::new("gantry.example");
    builder.declare_leaf("Int");
    builder
        .declare_type(list_type(AdtVisibility::Public))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    builder
        .declare_type(declaration(
            "Marker",
            AdtVisibility::Package,
            vec![constructor("Mark", 0, Vec::new())],
        ))
        .unwrap_or_else(|error| panic!("declaration: {error}"));
    builder
        .declare_alias(AdtAliasDeclaration {
            name: "Ints".to_owned(),
            visibility: AdtVisibility::Public,
            parameters: Vec::new(),
            target: "List".to_owned(),
        })
        .unwrap_or_else(|error| panic!("alias: {error}"));
    let model = builder
        .finish()
        .unwrap_or_else(|error| panic!("model: {error}"));

    let projection: AdtDurableProjection = model.durable_projection();
    let rebuilt = AdtPackageModel::from_projection(&projection)
        .unwrap_or_else(|error| panic!("round trip: {error}"));
    assert_eq!(rebuilt.identity(), model.identity());
    assert_eq!(rebuilt.canonical_schema(), model.canonical_schema());

    let mut reordered = projection.clone();
    reordered.types.reverse();
    assert_eq!(
        AdtPackageModel::from_projection(&reordered)
            .refused("a projection that reorders carried declarations")
            .code(),
        AdtDiagnosticCode::RoundTripLoss
    );

    let mut omitted = projection.clone();
    omitted.types.retain(|entry| entry.name != "Marker");
    assert_eq!(
        AdtPackageModel::from_projection(&omitted)
            .refused("a projection omitting a declaration")
            .code(),
        AdtDiagnosticCode::RoundTripLoss
    );

    let mut altered = projection.clone();
    altered.types[0].constructors[1].tag = 7;
    assert_eq!(
        AdtPackageModel::from_projection(&altered)
            .refused("a projection altering a tag")
            .code(),
        AdtDiagnosticCode::RoundTripLoss
    );
}

#[test]
fn diagnostic_codes_are_frozen_and_single_owner() {
    let mut spellings: Vec<&str> = AdtDiagnosticCode::ALL
        .iter()
        .map(|code| code.code())
        .collect();
    spellings.sort_unstable();
    let mut unique = spellings.clone();
    unique.dedup();
    assert_eq!(spellings, unique);
    for code in AdtDiagnosticCode::ALL {
        assert!(
            ADT_CLAUSES.contains(&code.clause()),
            "{} is owned by an unpublished clause",
            code.code()
        );
    }
    for clause in ADT_CLAUSES
        .iter()
        .filter(|clause| **clause != ADT_CLAUSES[0])
    {
        assert!(
            AdtDiagnosticCode::ALL
                .iter()
                .any(|code| code.clause() == *clause),
            "{clause} owns no diagnostic"
        );
    }
    let error: AdtError = AdtError::new(AdtDiagnosticCode::AliasCycle, "cycle");
    assert_eq!(error.code().code(), "adt-alias-cycle");
    assert_eq!(error.detail(), "cycle");
}
