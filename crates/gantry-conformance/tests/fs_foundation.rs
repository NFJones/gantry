//! Conformance for the declared `std.fs` surface.
//!
//! The lane pins the declared filesystem clauses, the closed module-row set, and the exact
//! declaration and admission behavior of `crates/gantry-ir/src/fs.rs` over one standard-library
//! graph. It performs no host I/O and claims no descriptor, open handle, live resource instance,
//! adapter, or runtime behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    FS_CLAUSES, FS_ITEMS, FS_PATH_SEGMENT_BOUND, FS_SURFACE_MODES, FS_SURFACE_TARGETS, FsAction,
    FsDiagnosticCode, FsPath, FsResourceOperation, IoOperation, NameClass, PackageFamily, Prelude,
    ResourceCarrier, ResourceLifetimeState, StabilityTier, StdGraph, StdItem, StdPackage,
    StdlibDiagnosticCode, admit_fs_surface, declare_fs_surface, generated::RecoveryClass,
};
use gantry::ir::{SemanticMode, TargetKind};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the text with every whitespace run collapsed to one space.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns one declared family package of `std.fs` over the library and binary targets.
fn family_package(modes: &[SemanticMode], targets: &[TargetKind]) -> StdPackage {
    StdPackage::new(
        PackageFamily::Fs,
        NameClass::Package,
        StabilityTier::Stable,
        modes,
        targets,
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the family package declaration is admissible: {error:?}"))
}

#[test]
fn fs_contract_clauses_and_scope_are_published() {
    assert_eq!(
        FS_CLAUSES,
        [
            "GNT-47.0-filesystem-foundation-scope",
            "GNT-47.1-filesystem-modules-and-item-rows",
            "GNT-47.2-filesystem-path-values",
            "GNT-47.3-filesystem-action-values",
            "GNT-47.4-filesystem-resource-operations",
            "GNT-47.5-filesystem-resource-state",
        ]
    );
    assert_eq!(FS_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        FS_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    assert!(specification.contains("the capability-backed family `std.fs`"));
    assert!(specification.contains("consumes and never restates or widens"));
    assert!(
        specification.contains(
            "The frozen diagnostics of this section are `fs-path-escape` and `fs-path-invalid`"
        ),
        "the section must publish its frozen diagnostic registry"
    );
}

#[test]
fn fs_module_rows_are_closed_and_canonical() {
    let names = FS_ITEMS.iter().map(|row| row.name).collect::<Vec<_>>();
    assert_eq!(
        names,
        ["std.fs::action", "std.fs::path", "std.fs::resource"]
    );
    assert_eq!(FS_ITEMS.len(), 3);
    for row in FS_ITEMS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        let expected: &[&str] = match row.name {
            "std.fs::action" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.3-filesystem-action-values",
            ],
            "std.fs::path" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.2-filesystem-path-values",
            ],
            "std.fs::resource" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.4-filesystem-resource-operations",
                "GNT-47.5-filesystem-resource-state",
            ],
            other => panic!("the undeclared module row `{other}` must not exist"),
        };
        assert_eq!(row.clauses, expected);
    }
    for clause in FS_CLAUSES {
        assert!(
            FS_ITEMS.iter().any(|row| row.clauses.contains(&clause)),
            "some declared module row must register the clause {clause}"
        );
    }
}

#[test]
fn fs_surface_declaration_requires_the_family_package() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        declare_fs_surface(&mut empty)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    let declared = family_package(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    assert!(graph.declare(declared).is_ok());
    assert!(declare_fs_surface(&mut graph).is_ok());

    let owner = PackageFamily::Fs.package_name();
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), FS_ITEMS.len());
    let declared_order = package.items().keys().cloned().collect::<Vec<_>>();
    let row_order = FS_ITEMS
        .iter()
        .map(|row| row.name.replace("::", "."))
        .collect::<Vec<_>>();
    assert_eq!(
        declared_order, row_order,
        "the rows must follow the package's canonical name order"
    );
    for row in FS_ITEMS {
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("{} is declared", row.name));
        assert_eq!(item.tier(), row.tier);
        assert_eq!(item.modes(), package.modes());
        assert_eq!(item.targets(), package.targets());
    }
    assert_eq!(
        declare_fs_surface(&mut graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::DuplicatePackage),
        "a second declaration of one item is refused by the duplicate rule"
    );
}

#[test]
fn fs_surface_admission_is_closed_and_exact() {
    let mut graph = StdGraph::new(Prelude::canonical());
    assert!(
        graph
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            ))
            .is_ok()
    );
    assert!(declare_fs_surface(&mut graph).is_ok());
    assert!(admit_fs_surface(&graph).is_ok());

    let extra = StdItem::new(
        "std.fs::extra",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    )
    .unwrap_or_else(|error| panic!("the extra item declaration is admissible: {error:?}"));
    assert!(graph.declare_item(extra).is_ok());
    assert_eq!(
        admit_fs_surface(&graph).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a declared name outside the three modules is refused"
    );

    // A partially declared surface is refused rather than completed or repaired.
    let mut partial = StdGraph::new(Prelude::canonical());
    assert!(
        partial
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            ))
            .is_ok()
    );
    let single = StdItem::new(
        "std.fs::action",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    )
    .unwrap_or_else(|error| panic!("the single-row declaration is admissible: {error:?}"));
    assert!(partial.declare_item(single).is_ok());
    assert_eq!(
        admit_fs_surface(&partial).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a partially declared surface is refused"
    );

    let mut mismatched = StdGraph::new(Prelude::canonical());
    assert!(
        mismatched
            .declare(family_package(
                &[SemanticMode::Application],
                &[TargetKind::Binary]
            ))
            .is_ok()
    );
    assert_eq!(
        declare_fs_surface(&mut mismatched)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );
}

#[test]
fn fs_path_values_are_bounded_and_escape_free() {
    assert_eq!(
        FsDiagnosticCode::ALL,
        [FsDiagnosticCode::PathEscape, FsDiagnosticCode::PathInvalid]
    );
    assert_eq!(FsDiagnosticCode::PathEscape.as_str(), "fs-path-escape");
    assert_eq!(FsDiagnosticCode::PathInvalid.as_str(), "fs-path-invalid");
    assert_eq!(FS_PATH_SEGMENT_BOUND, 256);

    let path = FsPath::rooted("workspace", &["logs", "today.txt"])
        .unwrap_or_else(|error| panic!("the declared path is admissible: {error}"));
    assert_eq!(path.root(), "workspace");
    let segments = path
        .segments()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(segments, ["logs", "today.txt"]);
    assert_eq!(path.canonical_spelling(), "workspace/logs/today.txt");
    let joined = path
        .join(&["extra"])
        .unwrap_or_else(|error| panic!("the declared join is admissible: {error}"));
    assert_eq!(
        joined.canonical_spelling(),
        "workspace/logs/today.txt/extra"
    );
    assert_eq!(
        joined.root(),
        "workspace",
        "a join never changes the declared root"
    );

    // Reserved components are refused rather than normalized, collapsed, or resolved.
    for (declared, component, position) in [
        (vec![".."], "..", 0_u32),
        (vec!["logs", ".."], "..", 1),
        (vec!["."], ".", 0),
    ] {
        let error = FsPath::rooted("workspace", &declared)
            .err()
            .unwrap_or_else(|| panic!("the reserved component {component} must be refused"));
        assert_eq!(error.code(), FsDiagnosticCode::PathEscape);
        assert_eq!(error.component(), Some(component));
        assert_eq!(error.position(), position);
    }
    let error = path
        .join(&[".."])
        .err()
        .unwrap_or_else(|| panic!("a reserved component in a join must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathEscape);
    assert_eq!(error.position(), 2, "a join reports the joined position");

    // Malformed declarations are refused instead of being repaired or defaulted.
    for (root, declared) in [
        ("", vec!["a"]),
        ("/absolute", vec!["a"]),
        ("work/space", vec!["a"]),
        ("~home", vec!["a"]),
        ("$HOME", vec!["a"]),
        ("%HOME%", vec!["a"]),
        ("Workspace", vec!["a"]),
        ("has space", vec!["a"]),
        ("unicode\u{e9}", vec!["a"]),
        ("workspace", Vec::new()),
        ("workspace", vec![""]),
        ("workspace", vec!["a/b"]),
        ("workspace", vec!["a\\b"]),
        ("workspace", vec!["a\u{7}b"]),
    ] {
        let error = FsPath::rooted(root, &declared)
            .err()
            .unwrap_or_else(|| panic!("the declared ({root}, {declared:?}) must be refused"));
        assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
        assert_eq!(error.component(), None);
    }
    let error = FsPath::rooted("workspace", &[])
        .err()
        .unwrap_or_else(|| panic!("an empty segment sequence must be refused"));
    assert!(
        error.detail().contains('0') && error.detail().contains("256"),
        "the empty-sequence refusal names the count and its bound: {}",
        error.detail()
    );

    // The declared segment bound is enforced rather than truncated.
    let admitted = vec!["segment"; FS_PATH_SEGMENT_BOUND];
    assert!(FsPath::rooted("workspace", &admitted).is_ok());
    let mut beyond = admitted;
    beyond.push("segment");
    let error = FsPath::rooted("workspace", &beyond)
        .err()
        .unwrap_or_else(|| panic!("a segment count beyond the bound must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
    assert!(
        error.detail().contains("257"),
        "the refusal names the declared count: {}",
        error.detail()
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "a path spelling is never authority",
        "at most `FS_PATH_SEGMENT_BOUND` segments",
        "refused under `fs-path-escape` naming the reserved component and its position",
        "refused under `fs-path-invalid` naming the segment and its position",
        "A declared root is a portable name of ASCII lower-case letters, digits, and `_` whose first scalar is a lower-case letter",
        "the separator scalar `/` or `\\`",
        "`canonical_spelling` renders the declared root followed by each declared segment separated by `/`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_actions_are_closed_and_carry_recovery_classes() {
    assert_eq!(
        FsAction::ALL,
        [
            FsAction::Create,
            FsAction::Read,
            FsAction::Replace,
            FsAction::Remove,
        ]
    );
    let spellings = FsAction::ALL
        .into_iter()
        .map(FsAction::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(spellings, ["create", "read", "replace", "remove"]);
    for action in FsAction::ALL {
        assert_eq!(FsAction::from_wire_name(action.wire_name()), Some(action));
        assert_eq!(action.as_str(), action.wire_name());
        if action == FsAction::Read {
            assert_eq!(
                action.declared_recovery_class(),
                RecoveryClass::ReadOnly,
                "a whole-object read makes no externally visible mutation"
            );
        } else {
            assert_eq!(
                action.declared_recovery_class(),
                RecoveryClass::NonIdempotent,
                "a create, a replace, and a remove may repeat externally"
            );
        }
    }
    assert_eq!(FsAction::from_wire_name("append"), None);
    assert_eq!(
        FsAction::ALL
            .into_iter()
            .map(FsAction::declared_recovery_class)
            .collect::<Vec<_>>(),
        [
            RecoveryClass::NonIdempotent,
            RecoveryClass::ReadOnly,
            RecoveryClass::NonIdempotent,
            RecoveryClass::NonIdempotent,
        ],
        "a read is read_only and a create, a replace, and a remove are non_idempotent"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "The declared actions are exactly four - create, read, replace, and remove, in that canonical order, which is the declared whole-object lifecycle order and not wire-name order",
        "a read is `read_only`",
        "a repeated read observes the same declared object and publishes no second one",
        "a create, a replace, and a remove are `non_idempotent`",
        "no action declares an implicit root, a default directory, or a search path",
        "declares no partial progress, no octet quantity, no request, no handle, and no resource state",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_resource_operations_are_closed_and_consume_io_requests() {
    assert_eq!(
        FsResourceOperation::ALL,
        [
            FsResourceOperation::Open,
            FsResourceOperation::Read,
            FsResourceOperation::Write,
            FsResourceOperation::Seek,
            FsResourceOperation::Flush,
            FsResourceOperation::Sync,
            FsResourceOperation::Truncate,
            FsResourceOperation::Close,
            FsResourceOperation::Lock,
            FsResourceOperation::Watch,
        ]
    );
    assert_eq!(
        FsResourceOperation::ALL
            .into_iter()
            .map(FsResourceOperation::wire_name)
            .collect::<Vec<_>>(),
        [
            "open", "read", "write", "seek", "flush", "sync", "truncate", "close", "lock", "watch",
        ]
    );
    for operation in FsResourceOperation::ALL {
        assert_eq!(
            FsResourceOperation::from_wire_name(operation.wire_name()),
            Some(operation)
        );
        assert_eq!(operation.as_str(), operation.wire_name());
    }
    for undeclared in ["finish", "read_text", "append", "read-text"] {
        assert_eq!(
            FsResourceOperation::from_wire_name(undeclared),
            None,
            "`{undeclared}` is not one of the declared ten"
        );
    }

    // Exactly the three declared std.io kinds are consumed, one each, and every remaining
    // declared operation consumes no request at all.
    let consuming = FsResourceOperation::ALL
        .into_iter()
        .filter_map(|operation| {
            operation
                .declared_request_kind()
                .map(|kind| (operation, kind))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        consuming,
        [
            (FsResourceOperation::Read, IoOperation::Read),
            (FsResourceOperation::Write, IoOperation::Write),
            (FsResourceOperation::Seek, IoOperation::Seek),
        ]
    );
    let mut consumed_kinds = consuming
        .iter()
        .map(|(_, kind)| kind.wire_name())
        .collect::<Vec<_>>();
    consumed_kinds.sort_unstable();
    assert_eq!(
        consumed_kinds,
        IoOperation::ALL.map(IoOperation::wire_name),
        "exactly the three declared std.io kinds are consumed, one each"
    );
    for operation in [
        FsResourceOperation::Open,
        FsResourceOperation::Flush,
        FsResourceOperation::Sync,
        FsResourceOperation::Truncate,
        FsResourceOperation::Close,
        FsResourceOperation::Lock,
        FsResourceOperation::Watch,
    ] {
        assert_eq!(
            operation.declared_request_kind(),
            None,
            "`{}` consumes no admitted request in this clause",
            operation.wire_name()
        );
    }
    let resource = FS_ITEMS
        .iter()
        .find(|row| row.name == "std.fs::resource")
        .unwrap_or_else(|| panic!("the `std.fs::resource` module row must be declared"));
    assert!(
        resource
            .clauses
            .contains(&"GNT-47.4-filesystem-resource-operations"),
        "the resource row must register the clause that declares its vocabulary"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "The declared operations are exactly ten - open, read, write, seek, flush, sync, truncate, close, lock, and watch, in that canonical order",
        "which is the declared resource-operation order - opening, transfer and positioning, settlement, release, exclusion, and observation, in the order those phases are declared - and not wire-name order",
        "it publishes no sequencing, lifetime, precedence, or mutual-exclusion rule between two operations",
        "the model's `FsResourceOperation` and its `FsResourceOperation::ALL` publish them",
        "A spelling outside the declared ten - including a settlement spelling such as `finish` and a text-reading spelling such as `read_text` - is not declared by this clause",
        "no streaming-segment spelling and no implicit native or text conversion",
        "no ambient descriptor, no inherited handle, and no implicit root",
        "a path spelling is never authority here either",
        "a read consumes one read request and a write consumes one write request",
        "a seek consumes one seek request whose declared quantity is the position it moves to",
        "The model accessor `declared_request_kind` publishes exactly that decision",
        "A flush declares no octet quantity and consumes no request",
        "a completed flush publishes exactly `committed-progress` of `GNT-29.2-reader-writer-seek-progress` and publishes no octet count",
        "publishes no progress observation, no channel, and no settlement for them",
        "a truncate declares a length and not a transfer",
        "no second request contract, no second octet bound, and no second progress vocabulary",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_resource_state_vocabulary_consumes_section28_and_read_only_grants_cannot_mutate() {
    // The clause consumes the landed Section 28 lifetime vocabulary instead of declaring a second
    // one, so the state facts pinned here are that model's facts.
    assert!(ResourceLifetimeState::Active.admits_charge());
    for state in [
        ResourceLifetimeState::Finishing,
        ResourceLifetimeState::Finished,
        ResourceLifetimeState::Poisoned,
        ResourceLifetimeState::EmergencyReleased,
        ResourceLifetimeState::Retired,
        ResourceLifetimeState::Deleted,
    ] {
        assert!(
            !state.admits_charge(),
            "only an active resource admits ordinary charges"
        );
    }
    for state in [
        ResourceLifetimeState::Finished,
        ResourceLifetimeState::Poisoned,
        ResourceLifetimeState::EmergencyReleased,
    ] {
        assert!(state.is_settled(), "a settled terminal result is declared");
    }
    for state in [
        ResourceLifetimeState::Active,
        ResourceLifetimeState::Finishing,
        ResourceLifetimeState::Retired,
        ResourceLifetimeState::Deleted,
    ] {
        assert!(!state.is_settled(), "a non-terminal state is not settled");
    }

    let mutating = FsResourceOperation::ALL
        .into_iter()
        .filter(|operation| operation.declares_content_mutation())
        .collect::<Vec<_>>();
    assert_eq!(
        mutating,
        [FsResourceOperation::Write, FsResourceOperation::Truncate],
        "exactly a write and a truncate declare a content mutation"
    );
    for operation in [
        FsResourceOperation::Open,
        FsResourceOperation::Read,
        FsResourceOperation::Seek,
        FsResourceOperation::Flush,
        FsResourceOperation::Sync,
        FsResourceOperation::Close,
        FsResourceOperation::Lock,
        FsResourceOperation::Watch,
    ] {
        assert!(
            !operation.declares_content_mutation(),
            "`{}` declares no content mutation",
            operation.wire_name()
        );
    }
    assert_eq!(ResourceCarrier::ALL.len(), 3, "the carrier set is closed");
    assert!(ResourceCarrier::ALL.contains(&ResourceCarrier::ReconstructionRecord));

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "The whole-resource lifetime state of an instance is exactly the closed vocabulary of `GNT-28.4-resource-lifetime-finish-poison-and-emergency-release`",
        "active, finishing, finished, poisoned, emergency-released, retired, and deleted",
        "this clause declares no second lifetime state, no second transition, no second terminal rule, and no reopening",
        "An admitted instance carries exactly one declared generation of `GNT-20.2-logical-operation-and-resource-generation-identity` and exactly one declared owner",
        "this clause declares exactly `write` and `truncate` as content-mutating",
        "the model accessor `declares_content_mutation` publishes exactly that decision",
        "refused under a read-only grant rather than ignored, downgraded, or partially executed",
        "a grant's read-only status never changes whether an operation declares a content mutation",
        "a durable record carries no live handle, no descriptor, and no admitted instance",
        "reconstruction reads the declared reconstruction record of `GNT-28.7-durable-resource-reconstruction`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}
