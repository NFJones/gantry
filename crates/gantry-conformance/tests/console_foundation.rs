//! Conformance for the declared `std.console` surface.
//!
//! The lane pins the declared console clauses, the closed module-row set, the declared operation
//! settlement facts, and the exact declaration and admission behavior of
//! `crates/gantry-ir/src/console.rs` over one standard-library graph. It performs no host I/O and
//! claims no terminal, adapter, or runtime behavior.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::RecoveryClass;
use gantry::ir::{
    CONSOLE_CLAUSES, CONSOLE_DIMENSION_BOUND, CONSOLE_ITEMS, CONSOLE_OPERATION_FACTS,
    CONSOLE_SURFACE_MODES, CONSOLE_SURFACE_TARGETS, ConsoleDetection, ConsoleDiagnosticCode,
    ConsoleDimensions, ConsoleEnvelopeRule, ConsoleOperation, ConsoleTerminalReport, IoOperation,
    IoOutcome, IoRequest, NameClass, PackageFamily, Prelude, ProgressObservation, StabilityTier,
    StdGraph, StdItem, StdPackage, StdlibDiagnosticCode, admit_console_surface,
    declare_console_surface,
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

#[test]
fn console_contract_clauses_and_scope_are_published() {
    assert_eq!(
        CONSOLE_CLAUSES,
        [
            "GNT-46.0-console-foundation-scope",
            "GNT-46.1-console-modules-and-item-rows",
            "GNT-46.2-console-bounded-operations",
            "GNT-46.3-console-operation-recovery-and-accepted-input",
            "GNT-46.4-console-encoding-and-shutdown-settlement",
            "GNT-46.5-console-terminal-observations",
        ]
    );
    assert_eq!(CONSOLE_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        CONSOLE_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in CONSOLE_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    assert!(specification.contains("the capability-backed family `std.console`"));
    assert!(specification.contains("consumes and never restates or widens"));
}

#[test]
fn console_module_rows_are_closed_and_canonical() {
    let names = CONSOLE_ITEMS.iter().map(|row| row.name).collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "std.console::control",
            "std.console::input",
            "std.console::output",
            "std.console::terminal",
        ]
    );
    assert_eq!(CONSOLE_ITEMS.len(), 4);
    for row in CONSOLE_ITEMS {
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        let expected: &[&str] = match row.name {
            "std.console::input" | "std.console::output" => &[
                "GNT-46.0-console-foundation-scope",
                "GNT-46.1-console-modules-and-item-rows",
                "GNT-46.2-console-bounded-operations",
                "GNT-46.3-console-operation-recovery-and-accepted-input",
                "GNT-46.4-console-encoding-and-shutdown-settlement",
            ],
            "std.console::terminal" => &[
                "GNT-46.0-console-foundation-scope",
                "GNT-46.1-console-modules-and-item-rows",
                "GNT-46.5-console-terminal-observations",
            ],
            _ => &[
                "GNT-46.0-console-foundation-scope",
                "GNT-46.1-console-modules-and-item-rows",
            ],
        };
        assert_eq!(row.clauses, expected);
    }
}

#[test]
fn console_surface_declaration_requires_the_family_package() {
    let mut empty = StdGraph::new(Prelude::canonical());
    assert_eq!(
        declare_console_surface(&mut empty)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnknownEdge)
    );

    let mut graph = StdGraph::new(Prelude::canonical());
    let declared = StdPackage::new(
        PackageFamily::Console,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the family package declaration is admissible: {error:?}"));
    assert!(graph.declare(declared).is_ok());
    assert!(declare_console_surface(&mut graph).is_ok());

    let owner = PackageFamily::Console.package_name();
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), CONSOLE_ITEMS.len());
    let declared_order = package.items().keys().cloned().collect::<Vec<_>>();
    let row_order = CONSOLE_ITEMS
        .iter()
        .map(|row| row.name.replace("::", "."))
        .collect::<Vec<_>>();
    assert_eq!(
        declared_order, row_order,
        "the rows must follow the package's canonical name order"
    );
    for row in CONSOLE_ITEMS {
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("{} is declared", row.name));
        assert_eq!(item.tier(), row.tier);
        assert_eq!(item.modes(), package.modes());
        assert_eq!(item.targets(), package.targets());
    }
    assert_eq!(
        declare_console_surface(&mut graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::DuplicatePackage),
        "a second declaration of one item is refused by the duplicate rule"
    );
}

#[test]
fn console_surface_admission_is_closed_and_exact() {
    let mut graph = StdGraph::new(Prelude::canonical());
    let declared = StdPackage::new(
        PackageFamily::Console,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the family package declaration is admissible: {error:?}"));
    assert!(graph.declare(declared).is_ok());
    assert!(declare_console_surface(&mut graph).is_ok());
    assert!(admit_console_surface(&graph).is_ok());

    let extra = StdItem::new(
        "std.console::extra",
        NameClass::Module,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    )
    .unwrap_or_else(|error| panic!("the extra item declaration is admissible: {error:?}"));
    assert!(graph.declare_item(extra).is_ok());
    assert_eq!(
        admit_console_surface(&graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a declared name outside the four modules is refused"
    );

    let mut mismatched = StdGraph::new(Prelude::canonical());
    let wrong = StdPackage::new(
        PackageFamily::Console,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Binary],
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the package declaration is admissible: {error:?}"));
    assert!(mismatched.declare(wrong).is_ok());
    assert_eq!(
        declare_console_surface(&mut mismatched)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );
}

#[test]
fn console_operations_are_closed_and_consume_io_requests() {
    assert_eq!(
        ConsoleOperation::ALL,
        [
            ConsoleOperation::Read,
            ConsoleOperation::Write,
            ConsoleOperation::Flush,
        ]
    );
    let spellings = ConsoleOperation::ALL
        .into_iter()
        .map(ConsoleOperation::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(spellings, ["read", "write", "flush"]);
    for operation in ConsoleOperation::ALL {
        assert_eq!(
            ConsoleOperation::from_wire_name(operation.wire_name()),
            Some(operation)
        );
    }
    assert_eq!(ConsoleOperation::from_wire_name("flush-all"), None);

    assert_eq!(ConsoleOperation::Read.module_name(), "std.console::input");
    assert_eq!(ConsoleOperation::Write.module_name(), "std.console::output");
    assert_eq!(ConsoleOperation::Flush.module_name(), "std.console::output");

    assert_eq!(
        ConsoleOperation::Read.io_operation(),
        Some(IoOperation::Read)
    );
    assert_eq!(
        ConsoleOperation::Write.io_operation(),
        Some(IoOperation::Write)
    );
    assert_eq!(ConsoleOperation::Flush.io_operation(), None);
    assert_eq!(ConsoleOperation::Read.completed_observation(), None);
    assert_eq!(ConsoleOperation::Write.completed_observation(), None);
    assert_eq!(
        ConsoleOperation::Flush.completed_observation(),
        Some(ProgressObservation::CommittedProgress)
    );

    // A console read consumes the admitted `std.io` request contract unchanged.
    let request =
        IoRequest::read(8).unwrap_or_else(|_| panic!("an eight-octet read is admissible"));
    assert_eq!(
        request.derive_progress(&IoOutcome::Read {
            requested: 8,
            advanced: 3,
            ended: false,
        }),
        Ok(ProgressObservation::ShortRead)
    );
}

#[test]
fn console_operation_recovery_and_accepted_input_are_declared() {
    let operations = CONSOLE_OPERATION_FACTS
        .iter()
        .map(|facts| facts.operation)
        .collect::<Vec<_>>();
    assert_eq!(
        operations,
        [
            ConsoleOperation::Read,
            ConsoleOperation::Write,
            ConsoleOperation::Flush,
        ]
    );
    let classes = CONSOLE_OPERATION_FACTS
        .iter()
        .map(|facts| facts.recovery)
        .collect::<Vec<_>>();
    assert_eq!(
        classes,
        [
            RecoveryClass::NonIdempotent,
            RecoveryClass::NonIdempotent,
            RecoveryClass::Idempotent,
        ],
        "a read consumes a cursor and a write may duplicate output; a repeated flush adds nothing"
    );
    for facts in CONSOLE_OPERATION_FACTS {
        assert_ne!(
            facts.recovery,
            RecoveryClass::ReadOnly,
            "no console operation is read_only, because a console read consumes an input cursor"
        );
        assert_eq!(facts.recovery, facts.operation.declared_recovery_class());
        assert_eq!(
            facts.consumes_input_cursor,
            facts.operation.consumes_input_cursor()
        );
        assert_eq!(
            facts.consumes_input_cursor,
            facts.operation.returns_octets()
        );
    }
    // A read and a write may be duplicated, so suppressing a duplicate is an adapter obligation; a
    // repeated flush delivers no additional octet and needs none.
    assert_eq!(
        CONSOLE_OPERATION_FACTS
            .iter()
            .map(|facts| facts.deduplication_is_adapter_owned)
            .collect::<Vec<_>>(),
        [true, true, false]
    );
    assert!(ConsoleOperation::Write.accepts_octets());
    assert!(!ConsoleOperation::Flush.accepts_octets());
    assert!(!ConsoleOperation::Write.returns_octets());

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in CONSOLE_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "a flush is `idempotent` because repeating it delivers no additional octet",
        "An accepted console read is nontransactional and is never implicitly retried, replayed, repaired",
        "is a new request of a new stable operation identity that consumes the cursor again",
        "a read may be retried only inside an adapter declaration of `GNT-29.11-adapter-declaration-obligations`",
        "The `interrupted` category of `GNT-29.4-console-contract` stays a category of the console family's portable envelope and is never a progress observation",
        "the effect certainty of a console call is the certainty",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn console_envelope_rules_are_closed_and_canonical() {
    assert_eq!(
        ConsoleEnvelopeRule::ALL,
        [
            ConsoleEnvelopeRule::OctetsOnlyPayload,
            ConsoleEnvelopeRule::EncodingIsTextFamilyOwned,
            ConsoleEnvelopeRule::ProtectedValueIsNotAnOctetSource,
            ConsoleEnvelopeRule::AccessIsRequesterArranged,
        ]
    );
    let spellings = ConsoleEnvelopeRule::ALL
        .into_iter()
        .map(ConsoleEnvelopeRule::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(
        spellings,
        [
            "octets-only-payload",
            "encoding-is-text-family-owned",
            "protected-value-is-not-an-octet-source",
            "access-is-requester-arranged",
        ]
    );
    for rule in ConsoleEnvelopeRule::ALL {
        assert_eq!(
            ConsoleEnvelopeRule::from_wire_name(rule.wire_name()),
            Some(rule)
        );
        assert_eq!(rule.as_str(), rule.wire_name());
    }
    assert_eq!(ConsoleEnvelopeRule::from_wire_name("octets-only"), None);

    assert_eq!(
        ConsoleOperation::ALL
            .into_iter()
            .filter(|operation| operation.completed_observation().is_some())
            .collect::<Vec<_>>(),
        [ConsoleOperation::Flush],
        "only a flush publishes a completion observation without an octet count"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for rule in [
        "The declared console envelope rules are exactly four",
        "spelled `octets-only-payload`, `encoding-is-text-family-owned`, `protected-value-is-not-an-octet-source`, and `access-is-requester-arranged`",
        "A protected value, protected envelope, credential, or key is not an octet source for a console operation",
        "Terminal detection, terminal dimensions, and terminal control remain outside this section",
        "no console write, read, or flush grants terminal-control authority, terminal control stays separately authorized",
        "not a second shutdown facility, and shutdown ownership rests with the owner that granted the access",
        "whose completed observation is exactly the `committed-progress` of `GNT-29.2-reader-writer-seek-progress`",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}

#[test]
fn console_terminal_observations_and_control_boundary_are_declared() {
    assert_eq!(
        ConsoleDetection::ALL,
        [ConsoleDetection::Attached, ConsoleDetection::NotAttached]
    );
    let spellings = ConsoleDetection::ALL
        .into_iter()
        .map(ConsoleDetection::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(spellings, ["terminal-attached", "terminal-not-attached"]);
    for detection in ConsoleDetection::ALL {
        assert_eq!(
            ConsoleDetection::from_wire_name(detection.wire_name()),
            Some(detection)
        );
        assert_eq!(detection.as_str(), detection.wire_name());
    }
    assert_eq!(ConsoleDetection::from_wire_name("terminal-unknown"), None);

    assert_eq!(CONSOLE_DIMENSION_BOUND, 4096);
    assert_eq!(
        ConsoleDiagnosticCode::ALL,
        [ConsoleDiagnosticCode::ObservationInconsistent]
    );
    assert_eq!(
        ConsoleDiagnosticCode::ObservationInconsistent.as_str(),
        "console-observation-inconsistent"
    );

    let admitted = ConsoleDimensions::new(80, 24)
        .unwrap_or_else(|error| panic!("an 80 by 24 observation is admissible: {error}"));
    assert_eq!(admitted.columns(), 80);
    assert_eq!(admitted.rows(), 24);
    // A count outside the declared bound is refused with its fact, observed value, and bound.
    for (columns, rows) in [
        (0, 24),
        (80, 0),
        (CONSOLE_DIMENSION_BOUND + 1, 24),
        (80, CONSOLE_DIMENSION_BOUND + 1),
    ] {
        let error = ConsoleDimensions::new(columns, rows)
            .err()
            .unwrap_or_else(|| panic!("the {columns} by {rows} observation must be refused"));
        assert_eq!(error.code(), ConsoleDiagnosticCode::ObservationInconsistent);
        assert_eq!(error.observed(), if columns == 80 { rows } else { columns });
        assert_eq!(error.maximum(), CONSOLE_DIMENSION_BOUND);
        assert!(matches!(error.fact(), "column" | "row"));
    }

    let attached = ConsoleTerminalReport::Attached(admitted);
    assert_eq!(attached.detection(), ConsoleDetection::Attached);
    assert_eq!(attached.dimensions(), Some(admitted));
    assert_eq!(
        ConsoleTerminalReport::NotAttached.detection(),
        ConsoleDetection::NotAttached
    );
    assert_eq!(
        ConsoleTerminalReport::NotAttached.dimensions(),
        None,
        "a not-attached console publishes no dimension observation"
    );

    let specification = flatten(&read_text(&workspace_root().join("SPEC.md")));
    for anchor in CONSOLE_CLAUSES {
        assert!(
            specification.contains(anchor),
            "the specification must declare {anchor}"
        );
    }
    for rule in [
        "spelled `terminal-attached` and `terminal-not-attached`",
        "a count outside that range is refused under the frozen console diagnostic `console-observation-inconsistent`",
        "consumes no admitted `std.io` request",
        "that module row stays a declared name without a published contract until",
    ] {
        assert!(
            specification.contains(rule),
            "the specification must pin: {rule}"
        );
    }
}
