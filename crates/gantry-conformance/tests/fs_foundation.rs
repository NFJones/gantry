//! Conformance for the declared `std.fs` surface.
//!
//! The lane pins the declared filesystem clauses, the closed module-row set, and the exact
//! declaration and admission behavior of `crates/gantry-ir/src/fs.rs` over one standard-library
//! graph. It performs no host I/O and claims no descriptor, open handle, live resource instance,
//! adapter, or runtime behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::{
    FS_CLAUSES, FS_ITEMS, FS_PATH_SEGMENT_BOUND, FS_REFUSAL_CONDITIONS, FS_REPLACEMENT_ACTION,
    FS_RESOLUTION_COUNT, FS_SURFACE_MODES, FS_SURFACE_TARGETS, FsAction, FsDiagnosticCode, FsError,
    FsPath, FsRefusalCondition, FsResourceOperation, FsTargetState, IoOperation, NameClass,
    PackageFamily, Prelude, ResourceCarrier, ResourceLifetimeState, StabilityTier, StdGraph,
    StdItem, StdPackage, StdlibDiagnosticCode, admit_fs_surface, declare_fs_surface,
    fs_traversal_order, generated::RecoveryClass,
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
            "GNT-47.6-filesystem-traversal",
            "GNT-47.7-filesystem-action-grants",
            "GNT-47.8-filesystem-link-policy",
            "GNT-47.9-filesystem-replacement",
            "GNT-47.10-filesystem-declared-limits",
            "GNT-47.11-filesystem-case-identity",
            "GNT-47.12-filesystem-operation-refusals",
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
                "GNT-47.7-filesystem-action-grants",
                "GNT-47.8-filesystem-link-policy",
                "GNT-47.9-filesystem-replacement",
                "GNT-47.10-filesystem-declared-limits",
                "GNT-47.12-filesystem-operation-refusals",
            ],
            "std.fs::path" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.2-filesystem-path-values",
                "GNT-47.6-filesystem-traversal",
                "GNT-47.10-filesystem-declared-limits",
                "GNT-47.11-filesystem-case-identity",
            ],
            "std.fs::resource" => &[
                "GNT-47.0-filesystem-foundation-scope",
                "GNT-47.1-filesystem-modules-and-item-rows",
                "GNT-47.4-filesystem-resource-operations",
                "GNT-47.5-filesystem-resource-state",
                "GNT-47.8-filesystem-link-policy",
                "GNT-47.10-filesystem-declared-limits",
                "GNT-47.12-filesystem-operation-refusals",
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
fn fs_link_policy_refuses_links_without_resolution_or_reread() {
    assert_eq!(
        FS_RESOLUTION_COUNT, 1,
        "one operation resolves its path value exactly once"
    );
    assert_eq!(
        FsDiagnosticCode::ALL.len(),
        2,
        "the link policy adds no diagnostic spelling to the frozen registry"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "resolving one operation's path value is exactly one step, and this clause declares exactly one resolution per operation",
        "with no re-resolution, fallback, retry, or second attempt, so a later change to an entry never admits it after a refusal",
        "An entry of one of those three kinds is never followed",
        "without publishing a diagnostic spelling of its own and without sharing a frozen spelling of `GNT-47.2-filesystem-path-values`",
        "whether or not the link target names a location inside the declared root",
        "the refusal is not normalization, substitution, truncation, or a partial execution of the operation's declared effect",
        "and resolves no entry, so a traversal alone publishes no such refusal and a link or a target that changes while a traversal runs does not change the names it publishes",
        "A grant's read-only status neither widens nor narrows this rule",
        "it publishes no diagnostic spelling, no link creation, no link-target reading, no definition of a junction or a reparse point beyond naming it",
        "no race-detection, race-reporting, or race-retry mechanism",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
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
    assert_eq!(
        error.position(),
        0,
        "a refusal the declared count produced names zero: {error:?}"
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
    assert_eq!(
        error.position(),
        0,
        "a refusal the declared count produced names zero: {error:?}"
    );

    // A count refusal names zero whatever value it was produced against, while a segment refusal
    // still names the position of the refused segment within the declared value.
    let joined = FsPath::rooted("workspace", &["a"])
        .unwrap_or_else(|error| panic!("one declared segment is admitted: {error:?}"));
    let error = joined
        .join(&[])
        .err()
        .unwrap_or_else(|| panic!("an empty added sequence must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
    assert_eq!(
        error.position(),
        0,
        "a count refusal names zero on a join too: {error:?}"
    );
    let error = joined
        .join(&["b/c"])
        .err()
        .unwrap_or_else(|| panic!("a separator segment must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
    assert_eq!(
        error.position(),
        1,
        "a refused segment names its own position in the joined value: {error:?}"
    );
    let full = FsPath::rooted("workspace", &vec!["segment"; FS_PATH_SEGMENT_BOUND])
        .unwrap_or_else(|error| panic!("the declared bound is admitted: {error:?}"));
    let error = full
        .join(&["segment"])
        .err()
        .unwrap_or_else(|| panic!("a join beyond the bound must be refused"));
    assert_eq!(error.code(), FsDiagnosticCode::PathInvalid);
    assert!(
        error.detail().contains("257"),
        "the join refusal names the declared count: {}",
        error.detail()
    );
    assert_eq!(
        error.position(),
        0,
        "a join count refusal names zero: {error:?}"
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
        "The position a refusal of this clause names is zero-based within the declared value",
        "a refusal a segment produced names that segment's position, and a refusal the declared count or the declared root produced names zero rather than a segment position",
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
        "which is the declared resource-operation order - opening, transfer and positioning, mutation and settlement, release, exclusion, and observation, in the order those phases are declared - and not wire-name order",
        "it publishes no sequencing, lifetime, precedence, or mutual-exclusion rule between two operations",
        "mutation and settlement, release, exclusion, and observation, in the order those phases are declared",
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
        "An admitted instance carries exactly one declared generation of `GNT-20.2-logical-operation-and-resource-generation-identity` and exactly one declared owner generation of `GNT-20.10-retirement-and-stale-owner-fencing`",
        "a stale owner is never admitted, while a genuinely advanced owner remains admissible as that clause declares",
        "this clause declares exactly `write` and `truncate` as content-mutating",
        "the model accessor `declares_content_mutation` publishes exactly that decision",
        "refused under a read-only grant rather than ignored, downgraded, or partially executed",
        "a grant's read-only status never changes whether an operation declares a content mutation",
        "An admitted instance is never carried in durable state, exactly as the rule of `GNT-3-T-AUTHORITY-INSTANCES` declares of a live instance",
        "a durable record carries no live handle, no descriptor, and no admitted instance",
        "reconstruction reads the declared reconstruction record of `GNT-28.7-durable-resource-reconstruction`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_traversal_publishes_canonical_entry_order_and_refuses_outer_names() {
    assert_eq!(
        fs_traversal_order(&["b", "a", "B", "10", "a1"])
            .unwrap_or_else(|error| panic!("declared names are admissible: {error:?}")),
        ["10", "B", "a", "a1", "b"],
        "the declared order ascends by scalar value and never uses a host order"
    );
    assert_eq!(
        fs_traversal_order(&["\u{e9}", "z"])
            .unwrap_or_else(|error| panic!("non-ASCII names are declared segments: {error:?}")),
        ["z", "\u{e9}"],
        "a scalar-value order places a multi-byte name after a one-byte name"
    );
    assert_eq!(
        fs_traversal_order(&["\u{10000}", "\u{e000}"])
            .unwrap_or_else(|error| panic!("astral names are declared segments: {error:?}")),
        ["\u{e000}", "\u{10000}"],
        "the order is by scalar value, not by UTF-16 code unit, which would invert this pair"
    );
    assert!(
        fs_traversal_order(&[])
            .unwrap_or_else(|error| panic!("an empty object is admitted: {error:?}"))
            .is_empty()
    );
    let many = (0..300)
        .map(|index| format!("entry{index:03}"))
        .collect::<Vec<String>>();
    let many_refs = many.iter().map(String::as_str).collect::<Vec<&str>>();
    let ordered_many = fs_traversal_order(&many_refs)
        .unwrap_or_else(|error| panic!("a traversal carries no entry bound: {error:?}"));
    assert_eq!(ordered_many.len(), 300, "no entry count is refused");
    assert_eq!(ordered_many.first().map(String::as_str), Some("entry000"));
    assert_eq!(ordered_many.last().map(String::as_str), Some("entry299"));

    let empty = match fs_traversal_order(&["a", ""]) {
        Ok(names) => panic!("an empty entry name must be refused, got {names:?}"),
        Err(error) => error,
    };
    assert_eq!(empty.code(), FsDiagnosticCode::PathInvalid);
    assert_eq!(empty.position(), 1, "the refusal names the entry position");

    let separator = match fs_traversal_order(&["a", "b/c"]) {
        Ok(names) => panic!("a separator scalar must be refused, got {names:?}"),
        Err(error) => error,
    };
    assert_eq!(separator.code(), FsDiagnosticCode::PathInvalid);
    assert_eq!(separator.position(), 1);

    let control = match fs_traversal_order(&["\u{7}"]) {
        Ok(names) => panic!("a control scalar must be refused, got {names:?}"),
        Err(error) => error,
    };
    assert_eq!(control.code(), FsDiagnosticCode::PathInvalid);
    assert_eq!(control.position(), 0);

    let parent = match fs_traversal_order(&["a", "b", ".."]) {
        Ok(names) => panic!("the parent component must be refused, got {names:?}"),
        Err(error) => error,
    };
    assert_eq!(parent.code(), FsDiagnosticCode::PathEscape);
    assert_eq!(parent.position(), 2);

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "A traversal publishes the declared names of the entries of the object the path value names, in exactly one canonical order: ascending by Unicode scalar value over the declared name",
        "never by a host collation, a locale, or a UTF-16 code-unit order, never in the host's directory order",
        "Two traversals of the same declared path value over the same declared object state publish the same sequence",
        "the model function `fs_traversal_order` of `crates/gantry-ir/src/fs.rs` publishes the order and the refusal",
        "refused under the diagnostic of that clause rather than normalized, escaped, truncated, renamed, dropped, or silently skipped",
        "the refusal names the zero-based position of that entry within the traversal",
        "no symbolic link, junction, or reparse point is followed by a rule of this clause",
        "no snapshot, atomicity, or isolation guarantee across entries",
        "no admitted request of `GNT-45.1-bounded-one-call-io-contract`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_action_grant_rule_refuses_read_only_mutations_in_both_vocabularies() {
    let mutating = FsAction::ALL
        .into_iter()
        .filter(|action| action.declares_content_mutation())
        .collect::<Vec<_>>();
    assert_eq!(
        mutating,
        [FsAction::Create, FsAction::Replace, FsAction::Remove],
        "exactly a create, a replace, and a remove declare a content mutation"
    );
    // The content-mutation fact of `GNT-47.7` and the recovery class of `GNT-47.3` are independent
    // declarations that coincide for today's four actions; they are pinned separately here and in
    // `fs_actions_are_closed_and_carry_recovery_classes` rather than equated.
    assert!(!FsAction::Read.declares_content_mutation());
    assert!(!FsResourceOperation::Read.declares_content_mutation());
    for operation in FsResourceOperation::ALL {
        assert_eq!(
            operation.declares_content_mutation(),
            matches!(
                operation,
                FsResourceOperation::Write | FsResourceOperation::Truncate
            ),
            "the resource content-mutation fact is exactly a write and a truncate"
        );
    }

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "a read-only grant refuses every action that declares an externally visible mutation of the object's content",
        "this clause declares exactly `create`, `replace`, and `remove` as content-mutating",
        "the model accessor `FsAction::declares_content_mutation` publishes exactly that decision",
        "such an action is refused under a read-only grant rather than ignored, downgraded, renamed, or partially executed",
        "A read declares no content mutation, so this rule never refuses a read",
        "No action becomes a content mutation because a grant is read-only",
        "neither vocabulary admits the other's members even though the `read` spelling is declared by both, and a grant refuses a content mutation in either one",
        "the frozen registry of `GNT-47.0-filesystem-foundation-scope` is unchanged, and this clause adds no third code",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_replacement_publishes_no_staging_or_partial_object() {
    assert_eq!(FS_REPLACEMENT_ACTION, FsAction::Replace);
    assert_eq!(FS_REPLACEMENT_ACTION.wire_name(), "replace");
    assert_eq!(
        FsAction::ALL,
        [
            FsAction::Create,
            FsAction::Read,
            FsAction::Replace,
            FsAction::Remove
        ],
        "the action vocabulary is still closed over exactly its four declared members"
    );
    assert!(FsAction::ALL.contains(&FS_REPLACEMENT_ACTION));
    assert!(FS_REPLACEMENT_ACTION.declares_content_mutation());

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "This clause declares the replacement contract of the `replace` action of `GNT-47.3-filesystem-action-values`",
        "A replacement names exactly one path value of `GNT-47.2-filesystem-path-values` and the grant the caller presents",
        "it has exactly one declared outcome for the object the path value names: the complete declared object replaces the complete named object",
        "This clause publishes no intermediate, partial, spliced, or staged outcome, no mixed old and new content, no partially replaced object, no resume, and no rollback of the replaced object",
        "a replacement that the implementation refuses publishes the declared refusal rather than a partially replaced object",
        "A replacement is one declared operation and never a declared sequence of them",
        "this clause publishes no staging, temporary, backup, sibling, or intermediate path spelling, no renaming step, no multi-step order, and no shell or host convention for one",
        "The read-only grant rule of `GNT-47.7-filesystem-action-grants` refuses a replacement presented under a read-only grant",
        "the single-resolution and link rules of `GNT-47.8-filesystem-link-policy` apply to it unchanged",
        "no durability, commit point, ordering, flush or sync requirement, journal, recovery, reclamation, or crash behavior",
        "no visibility, isolation, or observation rule for another process, another operation, another handle, or a later operation",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_declared_limits_are_exactly_the_segment_bound_request_count_and_resolution_count() {
    assert_eq!(FS_PATH_SEGMENT_BOUND, 256);
    assert_eq!(FS_RESOLUTION_COUNT, 1);

    // Every public constant of the model module is declared here, so any public constant added to
    // or renamed in this module fails this lane regardless of how its value is spelled.
    let model = read_text(&workspace_root().join("crates/gantry-ir/src/fs.rs"));
    let mut constants = Vec::new();
    for line in model.lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else {
            continue;
        };
        if rest.starts_with("fn ") {
            continue;
        }
        constants.push(rest.split(':').next().unwrap_or_default().to_owned());
    }
    constants.sort_unstable();
    assert_eq!(
        constants,
        [
            "ALL",
            "ALL",
            "ALL",
            "FS_CLAUSES",
            "FS_ITEMS",
            "FS_PATH_SEGMENT_BOUND",
            "FS_REFUSAL_CONDITIONS",
            "FS_REPLACEMENT_ACTION",
            "FS_RESOLUTION_COUNT",
            "FS_SURFACE_MODES",
            "FS_SURFACE_TARGETS",
        ]
        .map(str::to_owned)
    );

    // The numeric subset of those constants is exactly the two declared limits.
    let mut declared = Vec::new();
    for line in model.lines() {
        let Some(rest) = line.strip_prefix("pub const FS_") else {
            continue;
        };
        let Some((name, remainder)) = rest.split_once(": ") else {
            continue;
        };
        let Some((_kind, value)) = remainder.split_once(" = ") else {
            continue;
        };
        let Ok(number) = value.trim_end_matches(';').parse::<u64>() else {
            continue;
        };
        declared.push((format!("FS_{name}"), number));
    }
    declared.sort_unstable();
    assert_eq!(
        declared,
        [
            ("FS_PATH_SEGMENT_BOUND".to_owned(), 256),
            ("FS_RESOLUTION_COUNT".to_owned(), 1),
        ],
        "the section declares exactly these two numeric limits"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in FS_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "This clause publishes the quantitative limits this section declares, so that no reader infers a bound this section does not publish",
        "Exactly three quantitative bounds on the values of this section and on the work one operation may do are declared",
        "Identity, uniqueness, and closed-vocabulary counts are not limits in this clause's sense: for example",
        "at most `FS_PATH_SEGMENT_BOUND` segments, the declared bound of `GNT-47.2-filesystem-path-values`, which is `256`",
        "a read, a write, and a seek each consume exactly one admitted request of `GNT-45.1-bounded-one-call-io-contract`, the declared count of `GNT-47.4-filesystem-resource-operations`",
        "whose declared quantity is bounded by that contract's `IO_REQUEST_OCTET_BOUND` alone",
        "an operation resolves an entry exactly once, the declared count `FS_RESOLUTION_COUNT` of `GNT-47.8-filesystem-link-policy`, which is `1`",
        "a refusal a declared limit produced is never published as a refusal an implementation produced",
        "this clause's silence is not a limit",
        "this section declares no limit on traversal entries",
        "a quantity this clause does not declare is unbounded by this section",
        "MUST NOT be presented as one, published as a portable diagnostic, or relied on as a portable fact",
        "no host-enforced bound participates in admitting or refusing a portable program",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_path_value_case_identity_is_exact_and_never_folded() {
    // A declared segment keeps its own case: two path values that differ only in the case of one
    // segment are two declared values, and neither spelling is preferred or merged.
    let upper = FsPath::rooted("root", &["Report"])
        .unwrap_or_else(|error| panic!("an upper-case segment is declared: {error:?}"));
    let lower = FsPath::rooted("root", &["report"])
        .unwrap_or_else(|error| panic!("a lower-case segment is declared: {error:?}"));
    assert_ne!(
        upper, lower,
        "no fold merges two declared segments that differ only in case"
    );
    assert_eq!(upper.canonical_spelling(), "root/Report");
    assert_eq!(lower.canonical_spelling(), "root/report");
    assert_ne!(upper.canonical_spelling(), lower.canonical_spelling());

    // An upper-case root is not the lower-case root: the portable-name domain refuses it rather
    // than folding it into the domain.
    let refused = match FsPath::rooted("Root", &["report"]) {
        Err(error) => error,
        Ok(value) => panic!("an upper-case root must be refused rather than folded: {value:?}"),
    };
    assert!(
        matches!(refused, FsError::PathInvalid { .. }),
        "the root refusal is the declared diagnostic: {refused:?}"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for rule in [
        "the declaration-layer case rule that `GNT-47.2-filesystem-path-values` does not publish",
        "The path-value identity of `GNT-47.2-filesystem-path-values` is decided by scalar-value sequence equality of the declared root and the declared segments",
        "the comparison is exactly case-sensitive, it never folds, and it never consults a locale, a host collation, a display form, or a case-insensitive lookup key",
        "`Report` and `report` are two declared segments and two declared path values that no clause of this section merges, normalizes, folds, renames, or substitutes, and neither spelling is preferred",
        "two directory states that differ only in the case of an entry name publish two different sequences and never one sequence with a preferred spelling",
        "A target's own case behaviour is not a fact of this section",
        "A fold is never identity, never a lookup key, never a merge, never a rename, and never a substitution",
        "what a folding target reports is not a declared outcome of this section, this clause admits no fold as identity, publishes no refusal of its own, and adds no diagnostic to the frozen registry of `GNT-47.0-filesystem-foundation-scope`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn fs_operation_refusals_name_one_target_state_and_add_no_diagnostic_spelling() {
    assert_eq!(
        FS_REFUSAL_CONDITIONS,
        [
            FsRefusalCondition::TargetStateUnadmitted,
            FsRefusalCondition::FoldingTargetCollision,
        ]
    );
    // The frozen registry keeps its two codes: the refusal vocabulary adds no third spelling.
    assert_eq!(
        FsDiagnosticCode::ALL,
        [FsDiagnosticCode::PathEscape, FsDiagnosticCode::PathInvalid]
    );

    // Each whole-object action names exactly one declared target state it does not admit.
    assert_eq!(
        FsAction::Create.unadmitted_target_state(),
        Some(FsTargetState::Present)
    );
    for action in [FsAction::Read, FsAction::Replace, FsAction::Remove] {
        assert_eq!(
            action.unadmitted_target_state(),
            Some(FsTargetState::Absent),
            "{} is refused when no object is named",
            action.as_str()
        );
    }
    for action in FsAction::ALL {
        assert_eq!(
            action.refusal_conditions(),
            [
                FsRefusalCondition::TargetStateUnadmitted,
                FsRefusalCondition::FoldingTargetCollision,
            ],
            "{} resolves the declared path value of its caller",
            action.as_str()
        );
    }

    // Only `open` names an unadmitted target state; the nine instance operations declare no
    // condition of the refusal clause at all.
    assert_eq!(
        FsResourceOperation::Open.unadmitted_target_state(),
        Some(FsTargetState::Absent)
    );
    assert_eq!(
        FsResourceOperation::Open.refusal_conditions(),
        [
            FsRefusalCondition::TargetStateUnadmitted,
            FsRefusalCondition::FoldingTargetCollision,
        ]
    );
    for operation in FsResourceOperation::ALL {
        if operation == FsResourceOperation::Open {
            continue;
        }
        assert_eq!(
            operation.unadmitted_target_state(),
            None,
            "{}",
            operation.as_str()
        );
        assert!(
            operation.refusal_conditions().is_empty(),
            "{} applies to an admitted instance and declares no refusal condition",
            operation.as_str()
        );
    }

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for rule in [
        "This clause declares the refusal vocabulary of an operation of this section whose declared target state does not admit it",
        "Exactly two refusal conditions are declared, and the model's `FsRefusalCondition` and its `FS_REFUSAL_CONDITIONS` publish them",
        "the frozen registry of `GNT-47.0-filesystem-foundation-scope` keeps exactly `fs-path-escape` and `fs-path-invalid`, both owned by `GNT-47.2-filesystem-path-values`, and this clause adds no third code, no refusal position, count, or bound, and no spelling of its own",
        "either absent - no object is named by the declared path value - or present - one object is named by it",
        "`create` is refused when the declared target state is present, because an object that is already named does not admit creation, and `read`, `replace`, and `remove` are refused when the declared target state is absent",
        "`FsResourceOperation::unadmitted_target_state` publishes that decision",
        "the other nine declared operations apply to one admitted instance of `GNT-47.5-filesystem-resource-state`, declare no condition of this clause, and are neither admitted nor refused by it",
        "is refused when the target reports a collision under the target's own case behaviour",
        "the model accessors `FsAction::refusal_conditions` and `FsResourceOperation::refusal_conditions` publish exactly that condition set for the two vocabularies",
        "it publishes no folded spelling, no preferred spelling, no lookup key, and no identity of a fold",
        "an operation refused because the declared target state does not admit it is never published as refused for a collision",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}
