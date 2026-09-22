//! Conformance for the declared `std.io` common I/O surface.
//!
//! The lane reads the published note and requires it to name the declared capability family, to
//! mirror the declared Reader/Writer/Seek progress mapping exactly, to cite only specification
//! anchors the model's clause vocabularies declare, and to state the unlanded contract without
//! claiming it.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::ir::generated::HostDomainFamily;
use gantry::ir::{
    CONSTANT_CLAUSES, HOST_DOMAIN_CLAUSES, HostProgress, IO_CLAUSES, IO_CONTRACT_VERSION, IO_ITEMS,
    IO_REQUEST_OCTET_BOUND, IO_SURFACE_MODES, IO_SURFACE_TARGETS, IoDiagnosticCode, IoError,
    IoOperation, IoOutcome, IoRequest, NameClass, PackageFamily, Prelude, ProgressObservation,
    STDLIB_CLAUSES, SemanticMode, StabilityTier, StdGraph, StdItem, StdName, StdPackage,
    StdlibDiagnosticCode, TargetKind, admit_io_progress, admit_io_surface, declare_io_surface,
};

const REQUIRED_ANCHORS: [&str; 10] = [
    "GNT-29.1",
    "GNT-29.2",
    "GNT-29.3",
    "GNT-29.14",
    "GNT-29.15",
    "GNT-34.1",
    "GNT-45.0",
    "GNT-45.1",
    "GNT-45.2",
    "GNT-45.3",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Returns the note with every whitespace run collapsed to one space, so a published sentence
/// can be pinned without depending on its line wrapping.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns whether some declared clause vocabulary carries exactly `token` or an anchor
/// introduced by `token-`, so a prefix-imprecise citation such as `GNT-29.9` never matches the
/// declared `GNT-29.9-codec-contract` anchor's siblings by accident of spelling.
fn declared_anchor(token: &str) -> bool {
    let introduced = format!("{token}-");
    STDLIB_CLAUSES
        .iter()
        .chain(HOST_DOMAIN_CLAUSES.iter())
        .chain(CONSTANT_CLAUSES.iter())
        .chain(IO_CLAUSES.iter())
        .any(|anchor| *anchor == token || anchor.starts_with(&introduced))
}

#[test]
fn io_contract_clauses_and_scope_are_published() {
    assert_eq!(
        IO_CLAUSES,
        [
            "GNT-45.0-common-io-foundation-scope",
            "GNT-45.1-bounded-one-call-io-contract",
            "GNT-45.2-standard-io-modules-and-item-rows",
            "GNT-45.3-io-progress-derivation",
        ]
    );
    assert_eq!(IO_CONTRACT_VERSION, 1);
    const {
        assert!(IO_REQUEST_OCTET_BOUND > 0);
    }

    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);
    assert!(
        flat.contains("## The declared one-call contract"),
        "the note must publish the landed one-call contract"
    );
    for anchor in ["GNT-45.0-common-io-foundation-scope", "GNT-45.1"] {
        assert!(flat.contains(anchor), "the note must cite {anchor}");
    }
}

#[test]
fn io_operation_vocabulary_is_closed_and_canonical() {
    assert_eq!(
        IoOperation::ALL,
        [IoOperation::Read, IoOperation::Seek, IoOperation::Write]
    );
    let spellings = IoOperation::ALL
        .into_iter()
        .map(IoOperation::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(spellings, ["read", "seek", "write"]);
    for operation in IoOperation::ALL {
        assert_eq!(
            IoOperation::from_wire_name(operation.wire_name()),
            Some(operation)
        );
    }
    assert_eq!(IoOperation::from_wire_name("seek-to"), None);
    let refusal = IoRequest::admit_wire("seek-to", 1)
        .err()
        .unwrap_or_else(|| panic!("an undeclared spelling must be refused"));
    assert_eq!(
        refusal,
        IoError::RequestKind {
            observed: "seek-to".to_owned(),
        }
    );
    assert_eq!(refusal.code(), IoDiagnosticCode::RequestKind);
}

#[test]
fn io_request_bound_is_inclusive_and_refuses_zero_and_one_more() {
    let bound = IO_REQUEST_OCTET_BOUND;
    let admitted = IoRequest::read(bound).unwrap_or_else(|_| panic!("the bound is inclusive"));
    assert_eq!(admitted.operation(), IoOperation::Read);
    assert_eq!(admitted.quantity(), bound);
    assert!(IoRequest::read(1).is_ok());
    assert!(IoRequest::write(bound).is_ok());
    assert_eq!(
        IoRequest::read(0).err(),
        Some(IoError::RequestBound {
            operation: IoOperation::Read,
            observed: 0,
            maximum: bound,
        })
    );
    assert_eq!(
        IoRequest::read(bound + 1).err(),
        Some(IoError::RequestBound {
            operation: IoOperation::Read,
            observed: bound + 1,
            maximum: bound,
        })
    );
    assert_eq!(
        IoRequest::write(0).err(),
        Some(IoError::RequestBound {
            operation: IoOperation::Write,
            observed: 0,
            maximum: bound,
        })
    );
    assert!(IoRequest::write(bound + 1).is_err());
    let at_zero = IoRequest::seek(0);
    assert_eq!(at_zero.quantity(), 0);
    assert_eq!(IoRequest::seek(u64::MAX).quantity(), u64::MAX);
    assert_eq!(
        IoRequest::admit_wire("read", 0)
            .err()
            .map(|error| error.code()),
        Some(IoDiagnosticCode::RequestBound)
    );
    assert!(IoRequest::admit_wire("seek", u64::MAX).is_ok());
}

#[test]
fn io_progress_sets_are_closed_per_kind() {
    let declared: [(IoOperation, [ProgressObservation; 4], usize); 3] = [
        (
            IoOperation::Read,
            [
                ProgressObservation::CommittedProgress,
                ProgressObservation::Eof,
                ProgressObservation::NotStarted,
                ProgressObservation::ShortRead,
            ],
            4,
        ),
        (
            IoOperation::Seek,
            [
                ProgressObservation::CommittedProgress,
                ProgressObservation::NotStarted,
                ProgressObservation::PartialAdvance,
                ProgressObservation::PartialAdvance,
            ],
            2,
        ),
        (
            IoOperation::Write,
            [
                ProgressObservation::CommittedProgress,
                ProgressObservation::NotStarted,
                ProgressObservation::ShortWrite,
                ProgressObservation::PartialAdvance,
            ],
            3,
        ),
    ];
    for (operation, expected, length) in declared {
        assert_eq!(operation.admissible_progress(), &expected[..length]);
        for observation in ProgressObservation::ALL {
            let expected_admitted = expected[..length].contains(&observation);
            let outcome = admit_io_progress(operation, observation);
            if expected_admitted {
                assert_eq!(outcome, Ok(()));
            } else {
                assert_eq!(
                    outcome.err(),
                    Some(IoError::ProgressInapplicable {
                        operation,
                        observation,
                    })
                );
            }
        }
    }
    for (operation, observation) in [
        (IoOperation::Read, ProgressObservation::ShortWrite),
        (IoOperation::Read, ProgressObservation::PartialAdvance),
        (IoOperation::Write, ProgressObservation::Eof),
        (IoOperation::Write, ProgressObservation::ShortRead),
        (IoOperation::Seek, ProgressObservation::Eof),
        (IoOperation::Seek, ProgressObservation::PartialAdvance),
    ] {
        let error = admit_io_progress(operation, observation)
            .err()
            .unwrap_or_else(|| panic!("{operation:?} must refuse {observation:?}"));
        assert_eq!(error.code(), IoDiagnosticCode::ProgressInapplicable);
    }
    let codes = IoDiagnosticCode::ALL
        .into_iter()
        .map(IoDiagnosticCode::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        [
            "io-observation-inconsistent",
            "io-progress-inapplicable",
            "io-request-bound",
            "io-request-kind"
        ]
    );
    for code in IoDiagnosticCode::ALL {
        assert_eq!(
            IoDiagnosticCode::from_wire_name(code.wire_name()),
            Some(code)
        );
    }
}

#[test]
fn io_progress_precedence_and_derivation_scope_are_published() {
    let root = workspace_root();
    let specification = flatten(&read_text(&root.join("SPEC.md")));
    let note = flatten(&read_text(&root.join("docs/io-foundation.md")));

    for needle in [
        "an observation that observes the end of a stream is `eof` even when it advances no octet",
        "`not-started` is published only when no advance and no end of stream are observed",
        "it publishes no derivation of an observation from a presented quantity or end-of-stream fact",
    ] {
        assert!(
            specification.contains(needle),
            "the clause must state: {needle}"
        );
    }
    for needle in [
        "`eof` takes precedence over `not-started`",
        "the derivation of `GNT-45.3-io-progress-derivation`",
    ] {
        assert!(note.contains(needle), "the note must state: {needle}");
    }
}

#[test]
fn io_item_rows_are_closed_and_owned() {
    assert_eq!(IO_ITEMS.len(), IoOperation::ALL.len());
    let names = IO_ITEMS.iter().map(|row| row.name).collect::<Vec<_>>();
    assert_eq!(names, ["std.io::reader", "std.io::seek", "std.io::writer"]);
    let unique = names.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), names.len());
    for (row, operation) in IO_ITEMS.iter().zip(IoOperation::ALL) {
        assert_eq!(row.operation, operation);
        assert_eq!(row.name, operation.module_name());
        assert_eq!(row.class, NameClass::Module);
        assert_eq!(row.tier, StabilityTier::Stable);
        assert_eq!(
            row.clauses.to_vec(),
            [
                "GNT-45.0-common-io-foundation-scope",
                "GNT-45.1-bounded-one-call-io-contract",
                "GNT-45.2-standard-io-modules-and-item-rows",
            ]
        );
    }
}

#[test]
fn io_surface_declaration_requires_the_family_package() {
    let mut empty = StdGraph::new(Prelude::canonical());
    let refusal = declare_io_surface(&mut empty)
        .err()
        .unwrap_or_else(|| panic!("an undeclared family package must be refused"));
    assert_eq!(refusal.code(), StdlibDiagnosticCode::UnknownEdge);

    let mut graph = StdGraph::new(Prelude::canonical());
    let declared = StdPackage::new(
        PackageFamily::Io,
        NameClass::Package,
        StabilityTier::Stable,
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
        &[],
        &[],
    )
    .unwrap_or_else(|error| panic!("the family package declaration is admissible: {error:?}"));
    assert!(graph.declare(declared).is_ok());
    assert!(declare_io_surface(&mut graph).is_ok());
    let owner = PackageFamily::Io.package_name();
    let package = graph
        .package(&owner)
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(package.items().len(), IO_ITEMS.len());
    for row in IO_ITEMS {
        let item = package
            .item(row.name)
            .unwrap_or_else(|| panic!("{} is declared", row.name));
        assert_eq!(item.tier(), row.tier);
        assert_eq!(item.modes(), package.modes());
        assert_eq!(item.targets(), package.targets());
    }
    assert_eq!(IO_SURFACE_MODES, [SemanticMode::Application]);
    assert_eq!(
        IO_SURFACE_TARGETS,
        [TargetKind::Library, TargetKind::Binary]
    );
    assert_eq!(
        declare_io_surface(&mut graph)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::DuplicatePackage),
        "a second declaration of one item is refused by the duplicate rule"
    );
}

#[test]
fn io_surface_admission_is_closed_and_exact() {
    let fixture = |modes: &[SemanticMode], targets: &[TargetKind]| {
        let mut graph = StdGraph::new(Prelude::canonical());
        let declared = StdPackage::new(
            PackageFamily::Io,
            NameClass::Package,
            StabilityTier::Stable,
            modes,
            targets,
            &[],
            &[],
        )
        .unwrap_or_else(|error| panic!("the fixture package declaration is admissible: {error:?}"));
        graph
            .declare(declared)
            .unwrap_or_else(|error| panic!("the fixture package is admissible: {error:?}"));
        graph
    };
    let owner = PackageFamily::Io.package_name();

    let mut portable = fixture(
        &[SemanticMode::Portable],
        &[TargetKind::Library, TargetKind::Binary],
    );
    assert_eq!(
        declare_io_surface(&mut portable)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );

    let mut library_only = fixture(&[SemanticMode::Application], &[TargetKind::Library]);
    assert_eq!(
        declare_io_surface(&mut library_only)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability)
    );

    let mut graph = fixture(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    assert!(declare_io_surface(&mut graph).is_ok());
    assert!(
        admit_io_surface(&graph).is_ok(),
        "{:?}",
        admit_io_surface(&graph).err()
    );
    graph
        .declare_item(
            StdItem::new(
                "std.io::invented",
                NameClass::Module,
                StabilityTier::Stable,
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            )
            .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}"));
    assert_eq!(
        admit_io_surface(&graph).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "an item outside the declared set is refused"
    );

    let mut partial = fixture(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    let row = IO_ITEMS[0];
    partial
        .declare_item(
            StdItem::new(
                row.name,
                row.class,
                row.tier,
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            )
            .unwrap_or_else(|error| panic!("the declared row is admissible: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("the declared row is admissible: {error:?}"));
    assert_eq!(
        declare_io_surface(&mut partial)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a partially declared surface is refused before mutating"
    );
    let after = partial
        .package(&owner)
        .unwrap_or_else(|| panic!("the family package is declared"));
    assert_eq!(after.items().len(), 1, "the refusal mutates nothing");

    let mut named = fixture(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    assert!(declare_io_surface(&mut named).is_ok());
    named
        .declare_name(
            StdName::new("std.io::invented", NameClass::Module, "std.io")
                .unwrap_or_else(|error| panic!("the fixture name is admissible: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("the fixture name is admissible: {error:?}"));
    assert_eq!(
        admit_io_surface(&named).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a graph name outside the declared modules is refused"
    );
    assert_eq!(
        declare_io_surface(&mut named)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "the preflight refuses a graph name outside the declared modules"
    );

    let mut mistiered = fixture(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    for row in IO_ITEMS {
        let tier = if row.operation == IoOperation::Read {
            StabilityTier::Experimental
        } else {
            row.tier
        };
        mistiered
            .declare_item(
                StdItem::new(
                    row.name,
                    row.class,
                    tier,
                    &[SemanticMode::Application],
                    &[TargetKind::Library, TargetKind::Binary],
                )
                .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}")),
            )
            .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}"));
    }
    assert_eq!(
        admit_io_surface(&mistiered).err().map(|error| error.code()),
        Some(StdlibDiagnosticCode::InvalidNameClassification),
        "a row with another tier is refused"
    );

    let mut misapplicable = fixture(
        &[SemanticMode::Application],
        &[TargetKind::Library, TargetKind::Binary],
    );
    let row = IO_ITEMS[0];
    for item_name in [row.name, IO_ITEMS[1].name, IO_ITEMS[2].name] {
        let modes: &[SemanticMode] = if item_name == row.name {
            &[SemanticMode::Application, SemanticMode::Portable]
        } else {
            &[SemanticMode::Application]
        };
        misapplicable
            .declare_item(
                StdItem::new(
                    item_name,
                    NameClass::Module,
                    StabilityTier::Stable,
                    modes,
                    &[TargetKind::Library, TargetKind::Binary],
                )
                .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}")),
            )
            .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}"));
    }
    assert_eq!(
        admit_io_surface(&misapplicable)
            .err()
            .map(|error| error.code()),
        Some(StdlibDiagnosticCode::UnsupportedApplicability),
        "a row with another applicability is refused"
    );
}

#[test]
fn io_surface_identity_covers_exactly_the_declared_rows() {
    let canonical = |tier: StabilityTier| {
        let mut graph = StdGraph::new(Prelude::canonical());
        let declared = StdPackage::new(
            PackageFamily::Io,
            NameClass::Package,
            StabilityTier::Stable,
            &[SemanticMode::Application],
            &[TargetKind::Library, TargetKind::Binary],
            &[],
            &[],
        )
        .unwrap_or_else(|error| panic!("the fixture package declaration is admissible: {error:?}"));
        graph
            .declare(declared)
            .unwrap_or_else(|error| panic!("the fixture package is admissible: {error:?}"));
        for row in IO_ITEMS {
            let row_tier = if row.operation == IoOperation::Seek {
                tier
            } else {
                row.tier
            };
            graph
                .declare_item(
                    StdItem::new(
                        row.name,
                        row.class,
                        row_tier,
                        &[SemanticMode::Application],
                        &[TargetKind::Library, TargetKind::Binary],
                    )
                    .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}")),
                )
                .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}"));
        }
        graph
    };
    let identity = |graph: &StdGraph| {
        graph
            .package(&PackageFamily::Io.package_name())
            .unwrap_or_else(|| panic!("the family package is declared"))
            .identity()
            .as_str()
            .to_owned()
    };

    let baseline = identity(&canonical(StabilityTier::Stable));
    assert_ne!(
        identity(&canonical(StabilityTier::Experimental)),
        baseline,
        "a changed row tier changes the interface identity"
    );
    let mut with_extra = canonical(StabilityTier::Stable);
    with_extra
        .declare_item(
            StdItem::new(
                "std.io::invented",
                NameClass::Module,
                StabilityTier::Stable,
                &[SemanticMode::Application],
                &[TargetKind::Library, TargetKind::Binary],
            )
            .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("the fixture item is admissible: {error:?}"));
    assert_ne!(
        identity(&with_extra),
        baseline,
        "an extra item changes the interface identity"
    );
}

#[test]
fn io_progress_derivation_is_total_and_precedence_preserving() {
    let bound = IO_REQUEST_OCTET_BOUND;
    let cases = [
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 0,
                ended: true,
            },
            ProgressObservation::Eof,
        ),
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 8,
                ended: true,
            },
            ProgressObservation::Eof,
        ),
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 0,
                ended: false,
            },
            ProgressObservation::NotStarted,
        ),
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 8,
                ended: false,
            },
            ProgressObservation::CommittedProgress,
        ),
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 3,
                ended: false,
            },
            ProgressObservation::ShortRead,
        ),
        (
            IoOutcome::Read {
                requested: bound,
                advanced: bound,
                ended: false,
            },
            ProgressObservation::CommittedProgress,
        ),
        (
            IoOutcome::Write {
                provided: 8,
                accepted: 8,
            },
            ProgressObservation::CommittedProgress,
        ),
        (
            IoOutcome::Write {
                provided: 8,
                accepted: 0,
            },
            ProgressObservation::NotStarted,
        ),
        (
            IoOutcome::Write {
                provided: 8,
                accepted: 3,
            },
            ProgressObservation::ShortWrite,
        ),
        (
            IoOutcome::Seek {
                target: 4,
                from: 4,
                to: 4,
            },
            ProgressObservation::NotStarted,
        ),
        (
            IoOutcome::Seek {
                target: 4,
                from: 1,
                to: 4,
            },
            ProgressObservation::CommittedProgress,
        ),
    ];
    for (outcome, expected) in cases {
        assert_eq!(outcome.derive_progress(), Ok(expected));
    }
}

#[test]
fn io_observation_facts_outside_their_ranges_are_refused() {
    let bound = IO_REQUEST_OCTET_BOUND;
    let cases = [
        (
            IoOutcome::Read {
                requested: 8,
                advanced: 9,
                ended: false,
            },
            "advanced",
            9,
            8,
        ),
        (
            IoOutcome::Read {
                requested: 0,
                advanced: 0,
                ended: false,
            },
            "requested",
            0,
            bound,
        ),
        (
            IoOutcome::Read {
                requested: bound + 1,
                advanced: 0,
                ended: false,
            },
            "requested",
            bound + 1,
            bound,
        ),
        (
            IoOutcome::Write {
                provided: 8,
                accepted: 9,
            },
            "accepted",
            9,
            8,
        ),
        (
            IoOutcome::Write {
                provided: 0,
                accepted: 0,
            },
            "provided",
            0,
            bound,
        ),
        (
            IoOutcome::Write {
                provided: bound + 1,
                accepted: 0,
            },
            "provided",
            bound + 1,
            bound,
        ),
        (
            IoOutcome::Seek {
                target: 4,
                from: 1,
                to: 9,
            },
            "to",
            9,
            4,
        ),
    ];
    for (outcome, fact, observed, maximum) in cases {
        let error = outcome
            .derive_progress()
            .err()
            .unwrap_or_else(|| panic!("{outcome:?} must be refused"));
        assert_eq!(
            error,
            IoError::ObservationInconsistent {
                operation: outcome.operation(),
                fact,
                observed,
                maximum,
            }
        );
        assert_eq!(error.code(), IoDiagnosticCode::ObservationInconsistent);
    }
}

#[test]
fn io_note_names_the_declared_capability_family() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    assert!(PackageFamily::ALL.contains(&PackageFamily::Io));
    assert_eq!(PackageFamily::ALL.len(), 20);
    assert!(!PackageFamily::Io.is_pure());
    let package = PackageFamily::Io.package_name();
    assert!(
        flat.contains("capability-backed family `PackageFamily::Io`"),
        "the note must name the declared family `PackageFamily::Io` as capability-backed"
    );
    assert!(
        flat.contains(&format!("logical package name `{package}`")),
        "the note must name the declared package {package}"
    );
    assert!(
        flat.contains(&format!(
            "wire spelling `{}`",
            PackageFamily::Io.wire_name()
        )),
        "the note must name the declared wire spelling"
    );
    assert!(
        flat.contains("one of the twenty entries of `PackageFamily::ALL`"),
        "the note must state the declared family count it claims"
    );
}

#[test]
fn io_note_mirrors_the_declared_progress_mapping() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    assert_eq!(HostProgress::ALL.len(), 5);
    let mut reached = Vec::new();
    for progress in HostProgress::ALL {
        let observation = progress.observation();
        assert!(
            !reached.contains(&observation),
            "each declared progress member maps to its own observation"
        );
        reached.push(observation);
        let phrase = format!(
            "`HostProgress::{progress:?}` maps to `{}`",
            observation.wire_name()
        );
        assert_eq!(
            flat.matches(&phrase).count(),
            1,
            "the note must state `{phrase}` exactly once"
        );
    }
    for observation in ProgressObservation::ALL {
        if observation == ProgressObservation::PartialAdvance {
            assert!(
                !reached.contains(&observation),
                "the Section 20-only partial-advance observation is not reachable from the io progress vocabulary"
            );
        } else {
            assert!(
                reached.contains(&observation),
                "every other declared observation must be reachable: {}",
                observation.wire_name()
            );
        }
    }
}

#[test]
fn io_surface_declares_no_host_domain_family() {
    let declared = HostDomainFamily::ALL
        .into_iter()
        .map(HostDomainFamily::wire_name)
        .collect::<Vec<_>>();
    assert_eq!(declared.len(), 12);
    assert!(!declared.contains(&"io"));

    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);
    let listed = flat
        .split_once("declares twelve families in canonical order: ")
        .unwrap_or_else(|| panic!("the note must list the declared host-domain families"))
        .1
        .split_once(". Those are exactly the entries of")
        .unwrap_or_else(|| panic!("the note's family list must name its source"))
        .0
        .split(", ")
        .map(|token| {
            token
                .trim_start_matches("and ")
                .trim_matches('`')
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        listed, declared,
        "the note's family list must equal the declared vocabulary exactly"
    );
    assert!(
        flat.contains("carries no `io` row"),
        "the note must state that no io host-domain row is declared"
    );
}

#[test]
fn io_note_cites_only_declared_anchors_and_the_required_bounds() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    for anchor in REQUIRED_ANCHORS {
        assert!(
            flat.contains(anchor),
            "the note must cite the declared bound {anchor}"
        );
    }
    for token in note.split('`').filter(|token| token.starts_with("GNT-")) {
        assert!(
            declared_anchor(token),
            "the note must not cite an undeclared anchor {token}"
        );
    }
}

#[test]
fn io_note_records_the_unlanded_contract_without_claiming_it() {
    let note = read_text(&workspace_root().join("docs/io-foundation.md"));
    let flat = flatten(&note);

    for needle in [
        "It admits no streaming, incremental, chunked, or resumable contract and no buffering, queueing, or wait behavior beyond the progress observation a single call publishes.",
        "It declares no interface digest of its own; the declared module rows of `GNT-45.2-standard-io-modules-and-item-rows`",
        "It grants no adapter, no host trait, no runtime availability, and no capability: adapters remain leaves",
    ] {
        assert!(
            flat.contains(needle),
            "the note must record the unlanded contract: {needle}"
        );
    }
}
