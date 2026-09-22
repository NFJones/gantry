//! Conformance for the declared `std.console` capability surface.
//!
//! The lane reads the published note and requires it to name the declared package family with its
//! wire spelling, the declared host-domain family with its application-only applicability and
//! closed categories, the declared operations with their recovery classes and the requirement shape
//! they admit, and only specification anchors that the model's clause vocabularies declare.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::{HostDomainFamily, HostTarget, RecoveryClass};
use gantry::ir::{
    CONSOLE_CLAUSES, CONSOLE_OPERATION_FACTS, ConsoleOperation, HOST_DOMAIN_CLAUSES, PackageFamily,
    STDLIB_CLAUSES,
};

/// Every anchor the note cites, each of which a declared clause vocabulary must publish.
const REQUIRED_ANCHORS: [&str; 11] = [
    "GNT-29.4",
    "GNT-29.10",
    "GNT-29.11",
    "GNT-29.15",
    "GNT-34.1",
    "GNT-46.0",
    "GNT-46.1",
    "GNT-46.2",
    "GNT-46.3",
    "GNT-46.4",
    "GNT-46.5",
];

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

/// Returns the note paragraph that names `declaration`.
fn declaration_paragraph<'a>(note: &'a str, declaration: &str) -> &'a str {
    note.split("\n\n")
        .find(|paragraph| paragraph.contains(declaration))
        .unwrap_or_else(|| panic!("the note must name {declaration}"))
}

/// Returns whether some declared clause vocabulary carries exactly `token` or an anchor introduced
/// by `token-`, so a prefix-imprecise citation such as `GNT-29.1` never matches `GNT-29.10`.
fn declared_anchor(token: &str) -> bool {
    let introduced = format!("{token}-");
    CONSOLE_CLAUSES
        .iter()
        .chain(STDLIB_CLAUSES.iter())
        .chain(HOST_DOMAIN_CLAUSES.iter())
        .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
}

#[test]
fn console_capability_note_names_the_declared_family_and_applicability() {
    let note = read_text(&workspace_root().join("docs/console-capability.md"));

    let package = PackageFamily::Console.package_name();
    assert!(
        note.contains(&package),
        "the note must name the declared package {package}"
    );
    let wire = PackageFamily::Console.wire_name();
    assert!(
        declaration_paragraph(&note, "PackageFamily::Console")
            .contains(&format!("wire spelling `{wire}`")),
        "the identity paragraph must publish the declared wire spelling `{wire}`"
    );

    let host_wire = HostDomainFamily::Console.wire_name();
    assert!(
        declaration_paragraph(&note, "HostDomainFamily::Console")
            .contains(&format!("wire spelling `{host_wire}`")),
        "the host-domain paragraph must publish the declared wire spelling `{host_wire}`"
    );
    assert!(HostDomainFamily::Console.applies_to(HostTarget::Application));
    assert!(!HostDomainFamily::Console.applies_to(HostTarget::Portable));
    assert!(!HostDomainFamily::Console.applies_to(HostTarget::Durable));
    assert!(
        flatten(&note).contains("applies to the application target only"),
        "the note must state the declared application-only applicability"
    );
    for category in HostDomainFamily::Console.categories() {
        assert!(
            HostDomainFamily::Console.admits(*category),
            "the declared family must admit its own category"
        );
        assert!(
            note.contains(category.wire_name()),
            "the note must name the declared category `{}`",
            category.wire_name()
        );
    }
}

#[test]
fn console_capability_note_cites_only_declared_anchors() {
    let note = read_text(&workspace_root().join("docs/console-capability.md"));
    for token in REQUIRED_ANCHORS {
        assert!(note.contains(token), "the note must cite {token}");
        assert!(
            declared_anchor(token),
            "the note cites an anchor no declared vocabulary publishes: {token}"
        );
    }
    assert_eq!(CONSOLE_CLAUSES.len(), 6);
    for clause in CONSOLE_CLAUSES {
        assert!(
            note.contains(clause),
            "the note must cite the declared console clause {clause}"
        );
    }
}

#[test]
fn console_capability_note_agrees_with_the_declared_operations() {
    let note = read_text(&workspace_root().join("docs/console-capability.md"));
    let flattened = flatten(&note);
    assert_eq!(ConsoleOperation::ALL.len(), 3);
    for operation in ConsoleOperation::ALL {
        assert!(
            note.contains(operation.wire_name()),
            "the note must name the declared operation `{}`",
            operation.wire_name()
        );
        let recovery = operation.declared_recovery_class();
        assert_ne!(
            recovery,
            RecoveryClass::ReadOnly,
            "no console operation is read_only"
        );
        assert!(
            note.contains(recovery.wire_name()),
            "the note must publish the declared class `{}`",
            recovery.wire_name()
        );
    }
    assert!(
        flattened.contains("no console operation is `read_only`"),
        "the note must publish that no console operation is read_only"
    );
    for facts in CONSOLE_OPERATION_FACTS {
        assert_eq!(facts.recovery, facts.operation.declared_recovery_class());
        if facts.recovery == RecoveryClass::Idempotent {
            assert!(
                !facts.deduplication_is_adapter_owned,
                "an idempotent console operation needs no duplicate suppression"
            );
        }
    }
    assert!(
        flattened.contains(
            "A console capability requirement therefore names the declared family spelling `console` together with one of the three recovery classes"
        ),
        "the note must publish the shape a console capability requirement may name"
    );
}

#[test]
fn console_capability_note_publishes_its_non_claims() {
    let note = read_text(&workspace_root().join("docs/console-capability.md"));
    let flattened = flatten(&note);
    for statement in [
        "declares no right spelling",
        "grants no terminal-control capability",
        "provides no adapter, no deterministic or raw adapter, no cross-target mapping",
        "claims no runtime availability",
        "no console read, write, flush, detection, or dimension observation carries terminal-control authority",
    ] {
        assert!(
            flattened.contains(statement),
            "the note must publish the non-claim: {statement}"
        );
    }
}
