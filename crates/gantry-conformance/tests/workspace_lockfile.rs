//! Machine-checked conformance for the workspace, solving, and lockfile model.
//!
//! The tests use declared manifests, requirements, releases, and lockfile text
//! only. They neither resolve a real registry nor read a host path, load package
//! source, or rewrite a lockfile implicitly; every identity they check is
//! recomputed from the declared facts.

use gantry::ir::{
    ContentDigest, DependencyRequirement, DependencySource, GeneratorInput, GeneratorInputRole,
    GeneratorInputs, LockPolicy, MemberManifest, PackageName, PackageRelease, PackageVersion,
    SelectedFeatureSet, SourceLocator, SourceRevision, TargetFactSet, TargetFacts, TargetKind,
    WorkspaceDiagnosticCode, WorkspaceError, WorkspaceLockfile, WorkspaceManifest, solve,
    solve_with_policy, sync_lockfile,
};

const REGISTRY: &str = "registry.example";

fn name(value: &str) -> PackageName {
    PackageName::new(value).unwrap_or_else(|_| panic!("declared package name"))
}

fn version(value: &str) -> PackageVersion {
    PackageVersion::new(value).unwrap_or_else(|_| panic!("declared version"))
}

fn digest(marker: char) -> ContentDigest {
    ContentDigest::new(&marker.to_string().repeat(64)).unwrap_or_else(|_| panic!("declared digest"))
}

fn locator(value: &str) -> SourceLocator {
    SourceLocator::new(value).unwrap_or_else(|_| panic!("declared locator"))
}

fn revision(marker: char) -> SourceRevision {
    SourceRevision::new(&marker.to_string().repeat(40)).unwrap_or_else(|_| panic!("declared revision"))
}

fn library() -> TargetFactSet {
    let facts = TargetFacts::new(TargetKind::Library, None).unwrap_or_else(|_| panic!("library target facts"));
    TargetFactSet::new(&[facts])
}

fn features(names: &[&str]) -> SelectedFeatureSet {
    SelectedFeatureSet::new(names).unwrap_or_else(|_| panic!("declared feature selection"))
}

fn requirement(
    alias: &str,
    source: DependencySource,
    selection: SelectedFeatureSet,
) -> DependencyRequirement {
    DependencyRequirement::new(name(alias), source, selection)
}

fn path_source(root: &str) -> DependencySource {
    DependencySource::Path {
        root: locator(root),
    }
}

fn registry_source(version_text: &str) -> DependencySource {
    DependencySource::Registry {
        registry: locator(REGISTRY),
        version: version(version_text),
    }
}

fn member(
    member_name: &str,
    root: &str,
    interface: char,
    requirements: &[DependencyRequirement],
) -> MemberManifest {
    MemberManifest::new(
        name(member_name),
        version("1.0.0"),
        locator(root),
        library(),
        digest(interface),
        requirements,
    )
    .unwrap_or_else(|_| panic!("declared member"))
}

fn release(
    release_name: &str,
    version_text: &str,
    source: DependencySource,
    interface: char,
    generators: GeneratorInputs,
    dependencies: &[&str],
) -> PackageRelease {
    PackageRelease::new(
        name(release_name),
        version(version_text),
        source,
        library(),
        digest(interface),
        generators,
        dependencies.iter().map(|entry| name(entry)).collect(),
    )
}

fn refuse<T>(outcome: Result<T, WorkspaceError>, context: &str) -> WorkspaceError {
    match outcome {
        Ok(_) => panic!("{context}: the decision must be refused"),
        Err(error) => error,
    }
}

/// One workspace whose single member requires the vendored release.
fn vendored_workspace(requirement_digest: char) -> WorkspaceManifest {
    let requirement = requirement(
        "demo-util",
        DependencySource::Vendored {
            root: locator("vendor/util"),
            digest: digest(requirement_digest),
        },
        SelectedFeatureSet::empty(),
    );
    let core = member("demo-core", "ws/core", 'a', &[requirement]);
    WorkspaceManifest::new(name("demo"), locator("ws"), &[core]).unwrap_or_else(|_| panic!("declared workspace"))
}

#[test]
fn permutations_resolve_to_identical_identities() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            path_source("ws/util"),
            SelectedFeatureSet::empty(),
        )],
    );
    let tool = member("demo-tool", "ws/tool", 'b', &[]);
    let forward =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[core.clone(), tool.clone()])
            .unwrap_or_else(|_| panic!("declared workspace"));
    let reversed = WorkspaceManifest::new(name("demo"), locator("ws"), &[tool, core])
        .unwrap_or_else(|_| panic!("declared workspace"));
    let util = release(
        "demo-util",
        "1.0.0",
        path_source("ws/util"),
        'c',
        GeneratorInputs::empty(),
        &[],
    );
    let other = release(
        "demo-other",
        "1.0.0",
        path_source("ws/other"),
        'd',
        GeneratorInputs::empty(),
        &[],
    );
    let first = solve(&forward, &[util.clone(), other.clone()]).unwrap_or_else(|_| panic!("resolved workspace"));
    let second = solve(&reversed, &[other, util]).unwrap_or_else(|_| panic!("resolved workspace"));
    let partial = [release(
        "demo-util",
        "1.0.0",
        path_source("ws/util"),
        'c',
        GeneratorInputs::empty(),
        &[],
    )];
    let narrowed = solve(&forward, &partial).unwrap_or_else(|_| panic!("unused releases are not required"));
    assert_eq!(
        WorkspaceLockfile::from_resolved(&narrowed).canonical_text(),
        WorkspaceLockfile::from_resolved(&first).canonical_text(),
    );
    let locked = WorkspaceLockfile::from_resolved(&first).canonical_text();
    let locked_again = WorkspaceLockfile::from_resolved(&second).canonical_text();
    assert_eq!(locked, locked_again);
    assert_eq!(first.len(), 3, "core, tool, and util instances");
    assert_eq!(first.instance_of("demo-util", "1.0.0", &features(&[])), {
        first
            .instances()
            .iter()
            .find(|instance| instance.name().as_str() == "demo-util")
    });
}

#[test]
fn simultaneous_versions_stay_distinct_instances() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            registry_source("1.0.0"),
            SelectedFeatureSet::empty(),
        )],
    );
    let other = member(
        "demo-other",
        "ws/other",
        'b',
        &[requirement(
            "demo-util",
            registry_source("2.0.0"),
            SelectedFeatureSet::empty(),
        )],
    );
    let workspace = WorkspaceManifest::new(name("demo"), locator("ws"), &[core, other])
        .unwrap_or_else(|_| panic!("declared workspace"));
    let releases = [
        release(
            "demo-util",
            "1.0.0",
            registry_source("1.0.0"),
            'c',
            GeneratorInputs::empty(),
            &[],
        ),
        release(
            "demo-util",
            "2.0.0",
            registry_source("2.0.0"),
            'd',
            GeneratorInputs::empty(),
            &[],
        ),
    ];
    let resolved = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    assert_eq!(resolved.len(), 4);
    let first = resolved
        .instance_of("demo-util", "1.0.0", &features(&[]))
        .unwrap_or_else(|| panic!("first instance"));
    let second = resolved
        .instance_of("demo-util", "2.0.0", &features(&[]))
        .unwrap_or_else(|| panic!("second instance"));
    assert_ne!(first.identity_hex(), second.identity_hex());
}

#[test]
fn feature_selections_stay_distinct_instances() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            registry_source("1.0.0"),
            features(&["fast"]),
        )],
    );
    let other = member(
        "demo-other",
        "ws/other",
        'b',
        &[requirement(
            "demo-util",
            registry_source("1.0.0"),
            features(&["small"]),
        )],
    );
    let workspace = WorkspaceManifest::new(name("demo"), locator("ws"), &[core, other])
        .unwrap_or_else(|_| panic!("declared workspace"));
    let releases = [release(
        "demo-util",
        "1.0.0",
        registry_source("1.0.0"),
        'c',
        GeneratorInputs::empty(),
        &[],
    )];
    let resolved = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    assert_eq!(resolved.len(), 4);
    let fast = resolved
        .instance_of("demo-util", "1.0.0", &features(&["fast"]))
        .unwrap_or_else(|| panic!("fast instance"));
    let small = resolved
        .instance_of("demo-util", "1.0.0", &features(&["small"]))
        .unwrap_or_else(|| panic!("small instance"));
    assert_ne!(fast.identity_hex(), small.identity_hex());
}

#[test]
fn duplicate_members_and_alias_collisions_are_refused() {
    let first = member("demo-core", "ws/core", 'a', &[]);
    let second = member("demo-core", "ws/core-two", 'b', &[]);
    let duplicate = refuse(
        WorkspaceManifest::new(name("demo"), locator("ws"), &[first, second]),
        "duplicate member name",
    );
    assert_eq!(duplicate.code_str(), "workspace-member-duplicate");

    let colliding = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            path_source("ws/util"),
            SelectedFeatureSet::empty(),
        )],
    );
    let util = member("demo-util", "ws/util", 'b', &[]);
    let collision = refuse(
        WorkspaceManifest::new(name("demo"), locator("ws"), &[colliding, util]),
        "alias colliding with a member name",
    );
    assert_eq!(collision.code_str(), "workspace-alias-collision");
}

#[test]
fn member_outside_the_workspace_root_is_refused() {
    let outside = member("demo-core", "elsewhere/core", 'a', &[]);
    let error = refuse(
        WorkspaceManifest::new(name("demo"), locator("ws"), &[outside]),
        "member outside the workspace root",
    );
    assert_eq!(error.code_str(), "workspace-member-not-contained");
}

#[test]
fn movable_sources_are_refused() {
    let branch = refuse(
        SourceRevision::new("main"),
        "a branch name is not an immutable revision",
    );
    assert_eq!(branch.code_str(), "workspace-source-refused");
    let escaped = refuse(
        SourceLocator::new("ws/../elsewhere"),
        "a traversal segment is not a canonical locator",
    );
    assert_eq!(escaped.code_str(), "workspace-source-refused");
    assert_eq!(revision('b').as_str().len(), 40);
}

#[test]
fn offline_policy_refuses_authenticated_acquisition() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            registry_source("1.0.0"),
            SelectedFeatureSet::empty(),
        )],
    );
    let workspace =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[core]).unwrap_or_else(|_| panic!("declared workspace"));
    let releases = [release(
        "demo-util",
        "1.0.0",
        registry_source("1.0.0"),
        'c',
        GeneratorInputs::empty(),
        &[],
    )];
    let error = refuse(
        solve_with_policy(&workspace, &releases, &LockPolicy::frozen_offline()),
        "offline registry requirement",
    );
    assert_eq!(error.code_str(), "workspace-offline-source-unavailable");
    assert!(solve(&workspace, &releases).is_ok());
}

#[test]
fn vendored_digest_mismatch_is_refused() {
    let workspace = vendored_workspace('a');
    let releases = [PackageRelease::new(
        name("demo-util"),
        version("1.0.0"),
        DependencySource::Vendored {
            root: locator("vendor/util"),
            digest: digest('b'),
        },
        library(),
        digest('c'),
        GeneratorInputs::empty(),
        Vec::new(),
    )];
    let error = refuse(solve(&workspace, &releases), "vendored digest mismatch");
    assert_eq!(error.code_str(), "workspace-vendored-source-mismatch");
}

#[test]
fn unresolved_and_ambiguous_releases_are_refused() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            path_source("ws/util"),
            SelectedFeatureSet::empty(),
        )],
    );
    let workspace =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[core]).unwrap_or_else(|_| panic!("declared workspace"));
    let missing = refuse(solve(&workspace, &[]), "unresolved release");
    assert_eq!(missing.code_str(), "workspace-solve-conflict");
    let ambiguous = refuse(
        solve(
            &workspace,
            &[
                release(
                    "demo-util",
                    "1.0.0",
                    path_source("ws/util"),
                    'c',
                    GeneratorInputs::empty(),
                    &[],
                ),
                release(
                    "demo-util",
                    "1.0.0",
                    path_source("ws/util"),
                    'd',
                    GeneratorInputs::empty(),
                    &[],
                ),
            ],
        ),
        "ambiguous release",
    );
    assert_eq!(ambiguous.code_str(), "workspace-solve-conflict");
}

#[test]
fn lockfile_round_trips_canonically() {
    let workspace = vendored_workspace('a');
    let releases = [PackageRelease::new(
        name("demo-util"),
        version("1.0.0"),
        DependencySource::Vendored {
            root: locator("vendor/util"),
            digest: digest('a'),
        },
        library(),
        digest('c'),
        GeneratorInputs::empty(),
        Vec::new(),
    )];
    let resolved = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let lockfile = WorkspaceLockfile::from_resolved(&resolved);
    let text = lockfile.canonical_text();
    let parsed = WorkspaceLockfile::parse(&text).unwrap_or_else(|_| panic!("canonical lockfile text"));
    assert_eq!(parsed, lockfile);
    assert_eq!(parsed.canonical_text(), text);
    assert_eq!(parsed.text_digest(), lockfile.text_digest());
    assert!(lockfile.verify(&resolved).is_ok());
}

#[test]
fn tampered_and_stale_lockfiles_are_refused() {
    let workspace = vendored_workspace('a');
    let releases = [PackageRelease::new(
        name("demo-util"),
        version("1.0.0"),
        DependencySource::Vendored {
            root: locator("vendor/util"),
            digest: digest('a'),
        },
        library(),
        digest('c'),
        GeneratorInputs::empty(),
        Vec::new(),
    )];
    let resolved = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let lockfile = WorkspaceLockfile::from_resolved(&resolved);
    let text = lockfile.canonical_text().replacen("1.0.0", "1.0.1", 1);
    let tampered = refuse(WorkspaceLockfile::parse(&text), "edited lockfile entry");
    assert_eq!(tampered.code_str(), "workspace-lockfile-tampered");

    let unsupported = refuse(
        WorkspaceLockfile::parse("gantry-workspace-lockfile 9\n"),
        "unsupported lockfile version",
    );
    assert_eq!(
        unsupported.code_str(),
        "workspace-lockfile-version-unsupported"
    );

    let other = member(
        "demo-other",
        "ws/other",
        'b',
        &[requirement(
            "demo-util",
            DependencySource::Vendored {
                root: locator("vendor/util"),
                digest: digest('a'),
            },
            SelectedFeatureSet::empty(),
        )],
    );
    let spare = member("demo-spare", "ws/spare", 'd', &[]);
    let wider = WorkspaceManifest::new(name("demo"), locator("ws"), &[other, spare])
        .unwrap_or_else(|_| panic!("declared workspace"));
    let wider_resolved = solve(&wider, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let stale = refuse(lockfile.verify(&wider_resolved), "different instance set");
    assert_eq!(stale.code_str(), "workspace-lockfile-stale");
}

#[test]
fn rewrites_require_an_explicit_update_policy() {
    let workspace = vendored_workspace('a');
    let releases = [PackageRelease::new(
        name("demo-util"),
        version("1.0.0"),
        DependencySource::Vendored {
            root: locator("vendor/util"),
            digest: digest('a'),
        },
        library(),
        digest('c'),
        GeneratorInputs::empty(),
        Vec::new(),
    )];
    let narrow = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let lockfile = WorkspaceLockfile::from_resolved(&narrow);
    assert_eq!(
        sync_lockfile(&lockfile, &narrow, &LockPolicy::online_frozen())
            .unwrap_or_else(|_| panic!("matching lockfile is returned unchanged"))
            .canonical_text(),
        lockfile.canonical_text()
    );

    let other = member("demo-other", "ws/other", 'b', &[]);
    let wider =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[other]).unwrap_or_else(|_| panic!("declared workspace"));
    let wider_resolved = solve(&wider, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let refused = refuse(
        sync_lockfile(&lockfile, &wider_resolved, &LockPolicy::online_frozen()),
        "frozen policy cannot rewrite a lockfile",
    );
    assert_eq!(refused.code_str(), "workspace-lockfile-rewrite-refused");
    let updated = sync_lockfile(
        &lockfile,
        &wider_resolved,
        &LockPolicy::online_reviewable_update(),
    )
    .unwrap_or_else(|_| panic!("explicit update policy permits a rewrite"));
    assert_eq!(
        updated.canonical_text(),
        WorkspaceLockfile::from_resolved(&wider_resolved).canonical_text()
    );
}

#[test]
fn generator_input_binding_is_verified() {
    let workspace = vendored_workspace('a');
    let release_with = |marker: char| {
        let input =
            GeneratorInput::new("schema", GeneratorInputRole::Input, digest(marker).as_str())
                .unwrap_or_else(|_| panic!("declared generator input"));
        PackageRelease::new(
            name("demo-util"),
            version("1.0.0"),
            DependencySource::Vendored {
                root: locator("vendor/util"),
                digest: digest('a'),
            },
            library(),
            digest('c'),
            GeneratorInputs::new(&[input]).unwrap_or_else(|_| panic!("declared generator inputs")),
            Vec::new(),
        )
    };
    let bound = [release_with('e')];
    let resolved = solve(&workspace, &bound).unwrap_or_else(|_| panic!("resolved workspace"));
    let lockfile = WorkspaceLockfile::from_resolved(&resolved);
    assert!(lockfile.verify_releases(&bound).is_ok());
    let mismatch = refuse(
        lockfile.verify_releases(&[release_with('f')]),
        "generator input differs from the bound release",
    );
    assert_eq!(mismatch.code_str(), "workspace-generator-input-mismatch");
}

#[test]
fn undeclared_transitives_are_not_reachable() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            path_source("ws/util"),
            SelectedFeatureSet::empty(),
        )],
    );
    let workspace =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[core]).unwrap_or_else(|_| panic!("declared workspace"));
    let releases = [
        release(
            "demo-util",
            "1.0.0",
            path_source("ws/util"),
            'c',
            GeneratorInputs::empty(),
            &["demo-deep"],
        ),
        release(
            "demo-deep",
            "1.0.0",
            path_source("ws/deep"),
            'd',
            GeneratorInputs::empty(),
            &[],
        ),
    ];
    let resolved = solve(&workspace, &releases).unwrap_or_else(|_| panic!("resolved workspace"));
    let core_instance = resolved
        .instances()
        .iter()
        .find(|instance| instance.name().as_str() == "demo-core")
        .unwrap_or_else(|| panic!("core instance"));
    let core_edges: Vec<&str> = core_instance
        .dependencies()
        .iter()
        .map(PackageName::as_str)
        .collect();
    assert_eq!(core_edges, ["demo-util"]);
    let util_instance = resolved
        .instances()
        .iter()
        .find(|instance| instance.name().as_str() == "demo-util")
        .unwrap_or_else(|| panic!("util instance"));
    let util_edges: Vec<&str> = util_instance
        .dependencies()
        .iter()
        .map(PackageName::as_str)
        .collect();
    assert_eq!(util_edges, ["demo-deep"]);
    assert!(!core_edges.contains(&"demo-deep"));
}

#[test]
fn an_instance_without_a_shipping_target_is_refused() {
    let core = member(
        "demo-core",
        "ws/core",
        'a',
        &[requirement(
            "demo-util",
            path_source("ws/util"),
            SelectedFeatureSet::empty(),
        )],
    );
    let workspace =
        WorkspaceManifest::new(name("demo"), locator("ws"), &[core]).unwrap_or_else(|_| panic!("declared workspace"));
    let releases = [PackageRelease::new(
        name("demo-util"),
        version("1.0.0"),
        path_source("ws/util"),
        TargetFactSet::empty(),
        digest('c'),
        GeneratorInputs::empty(),
        Vec::new(),
    )];
    let error = refuse(solve(&workspace, &releases), "no shipping target");
    assert_eq!(error.code_str(), "workspace-instance-not-shipping");
}

#[test]
fn the_diagnostic_registry_is_frozen() {
    let codes = WorkspaceDiagnosticCode::ALL;
    assert_eq!(codes.len(), 13);
    let mut spellings: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
    spellings.sort_unstable();
    let unique: std::collections::BTreeSet<&str> = spellings.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "no spelling is shared twice");
    for code in codes {
        assert!(code.as_str().starts_with("workspace-"));
        assert!(!code.meaning().is_empty());
    }
    let represented: std::collections::BTreeSet<&str> = [
        refuse(solve(&vendored_workspace('a'), &[]), "unresolved").code_str(),
        refuse(SourceRevision::new("main"), "movable revision").code_str(),
    ]
    .into_iter()
    .collect();
    assert!(represented.contains("workspace-solve-conflict"));
    assert!(represented.contains("workspace-source-refused"));
}
