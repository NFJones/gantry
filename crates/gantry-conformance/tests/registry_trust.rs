//! Machine-checked conformance for the authenticated package-acquisition and registry-trust
//! model of `SPEC.md` Section 27, clauses `GNT-27.1` .. `GNT-27.14`.
//!
//! These tests exercise the public `gantry::ir::registry` surface that Section 27 publishes, one
//! test per clause:
//! `GNT-27.1-immutable-source-identity-and-source-kind-vocabulary`,
//! `GNT-27.2-canonical-publication-names-and-external-name-mapping`,
//! `GNT-27.3-authenticated-metadata-snapshot-and-client-verification`,
//! `GNT-27.4-trust-roots-and-delegated-authority`,
//! `GNT-27.5-key-rotation-and-compromise-recovery`,
//! `GNT-27.6-expiry-freshness-and-offline-mode`,
//! `GNT-27.7-rollback-and-freeze-resistance`,
//! `GNT-27.8-publication-immutability`,
//! `GNT-27.9-yank-semantics`,
//! `GNT-27.10-security-revocation`,
//! `GNT-27.11-vcs-path-and-vendor-source-verification`,
//! `GNT-27.12-lockfile-evidence-binding`,
//! `GNT-27.13-trust-failure-attribution`, and
//! `GNT-27.14-registry-non-claims`.
//!
//! Every test is a pure function of its own arguments: no test reads a clock, a host path, an
//! environment variable, a network answer, or a registry response, and no test waits on a handle.
//! Epochs, checkouts, vendored directories, mirror bindings, and signature values are declared
//! inputs, and every digest is derived here from a declared seed, so every verdict below is
//! reproducible from its own inputs.
//!
//! Each test states one admissible path and at least one falsifiable refusal: an unauthorized
//! publisher, changed bytes, stale or expired metadata, a refused key rotation, a rollback or
//! freeze, a yank, a revocation, a pinned checkout, a modified path, a vendored directory, a
//! mirror substitution, and stale lockfile evidence are each decided here.

use std::fs;

use gantry::ir::TargetKind;
use gantry::ir::registry::{
    AcquisitionRouteKind, AdvisoryBoundary, AdvisoryScope, AdvisorySetProof, AdvisoryStore,
    AliasBinding, AliasBindings, AuthorityScope, AuthorizationDefect, CommitId, Compromise,
    ConfigurationAlias, DeclaredSignature, Delegation, DelegationTiming, DeliveredRelease,
    EntryAuthority, EpochObservation, EvidenceDefect, ExternalAliasMap, ExternalName,
    FreshnessMode, KeyId, KeyRecord, LockedDependency, Lockfile, LockfileInputs, LockfileRecord,
    MetadataSnapshot, MirrorBinding, MirrorDefect, NameDefect, PathPin, PinDefect, PinnedTree,
    PublicationDefect, PublicationLedger, PublicationNameSet, PublicationState, PublisherIdentity,
    REGISTRY_CLAUSES, REGISTRY_NAME_SCALAR_LIMIT, REGISTRY_NON_CLAIM_ORDER, REGISTRY_NON_CLAIMS,
    RegistryDiagnosticCode, RegistryError, RegistryName, RegistryNameKind, RegistryNonClaim,
    RegistryNonClaimAssertion, RegistryRefusal, RetainedState, RootId, RootSelectionPolicy,
    RotationContext, RotationDefect, RotationEvidence, RotationSignatures, RotationTiming,
    RunRequest, SecurityAdvisory, Severity, SnapshotDependency, SnapshotEntry, SourceAlias,
    SourceDeclaration, SourceIdentity, SourceKind, TargetArtifact, TrustFailureReason, TrustRoot,
    TrustStore, VcsPin, VendorDefect, VendorDirectory, VendorEntry, VerificationInput,
    VerifiedSnapshot, check_registry_non_claims, collision, declared_signature,
    resolve_new_release, resolve_source, verify_mirror, verify_path_tree, verify_pinned_tree,
    verify_vendor,
};
use sha2::{Digest, Sha256};

/// Returns one declared digest derived from one declared seed.
fn digest(seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.finalize().into()
}

/// Returns the repository root that owns the committed documentation note.
fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap_or_else(|| unreachable!("conformance crate is nested below the workspace"))
        .to_path_buf()
}

/// Returns the admitted value of one trust decision.
fn admit<T>(outcome: Result<T, RegistryRefusal>, context: &str) -> T {
    match outcome {
        Ok(value) => value,
        Err(refusal) => panic!("{context}: {refusal}"),
    }
}

/// Returns the refusal that prevented one trust decision.
fn refuse<T>(outcome: Result<T, RegistryRefusal>, context: &str) -> RegistryRefusal {
    match outcome {
        Ok(_) => panic!("{context}: the decision was admitted"),
        Err(refusal) => refusal,
    }
}

/// Keeps single-record fixtures explicit about the sealed admission boundary they exercise.
#[allow(clippy::result_large_err)]
trait RotationTestExt {
    /// Admits one one-member sealed rotation set.
    fn rotate(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: RotationEvidence,
        keys: &[KeyRecord],
    ) -> Result<(), RegistryRefusal>;

    /// Admits one one-member sealed rotation set under the selected root policy.
    fn rotate_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: RotationEvidence,
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal>;
}

impl RotationTestExt for TrustStore {
    fn rotate(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: RotationEvidence,
        keys: &[KeyRecord],
    ) -> Result<(), RegistryRefusal> {
        self.rotate_batch(declaration, std::slice::from_ref(&evidence), keys)
    }

    fn rotate_with_root_selection(
        &mut self,
        declaration: &SourceDeclaration,
        evidence: RotationEvidence,
        keys: &[KeyRecord],
        root_policy: &RootSelectionPolicy,
    ) -> Result<(), RegistryRefusal> {
        self.rotate_batch_with_root_selection(
            declaration,
            std::slice::from_ref(&evidence),
            keys,
            root_policy,
        )
    }
}

/// Returns the admitted value of one declaration decision.
fn accept<T>(outcome: Result<T, RegistryError>, context: &str) -> T {
    match outcome {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

/// Returns the typed condition that refused one declaration.
fn reject<T>(outcome: Result<T, RegistryError>, context: &str) -> RegistryError {
    match outcome {
        Ok(_) => panic!("{context}: the declaration was admitted"),
        Err(error) => error,
    }
}

/// Returns one validated name of one kind.
fn name(kind: RegistryNameKind, spelling: &str) -> RegistryName {
    accept(
        RegistryName::new(kind, spelling),
        "the declared name is valid",
    )
}

/// Returns one registry service identity for the namespace that publishes a package.
fn registry_source(namespace: &str, package: &str) -> SourceIdentity {
    let _ = package;
    accept(
        SourceIdentity::registry(&format!("{namespace}-registry")),
        "the declared registry source identity is valid",
    )
}

/// Returns one source declaration with an explicit package subject.
fn source_declaration(
    index: usize,
    alias: &str,
    package: &str,
    identity: SourceIdentity,
) -> SourceDeclaration {
    accept(
        SourceDeclaration::new(
            index,
            &format!("manifest:dependency:{index}"),
            alias,
            package,
            identity,
        ),
        "the declared source declaration is valid",
    )
}

/// Returns one source declaration with an explicit package subject.
#[allow(clippy::result_large_err)]
fn source_declaration_for(
    index: usize,
    alias: &str,
    package: &str,
    identity: SourceIdentity,
) -> Result<SourceDeclaration, RegistryError> {
    SourceDeclaration::new(
        index,
        &format!("manifest:dependency:{index}"),
        alias,
        package,
        identity,
    )
}

/// Returns one publisher identity.
fn publisher(name: &str, key: &str) -> PublisherIdentity {
    accept(
        PublisherIdentity::of(name, key),
        "the declared publisher identity is valid",
    )
}

/// Returns one key record whose declared material derives from its identity.
fn key(spelling: &str) -> KeyRecord {
    let identity = accept(KeyId::new(spelling), "the declared key identity is valid");
    accept(
        KeyRecord::new(identity, digest(spelling)),
        "the declared key record is valid",
    )
}

/// Returns one pinned commit identity.
fn commit(spelling: &str) -> CommitId {
    accept(
        CommitId::new(spelling),
        "the declared commit identity is valid",
    )
}

/// Returns one published snapshot entry.
fn entry(
    namespace: &str,
    package: &str,
    version: &str,
    publisher: &PublisherIdentity,
    manifest: &str,
    artifact: &str,
) -> SnapshotEntry {
    accept(
        SnapshotEntry::new(
            registry_source(namespace, package),
            namespace,
            package,
            version,
            publisher.clone(),
        ),
        "the declared snapshot entry is valid",
    )
    .with_manifest(digest(manifest))
    .with_artifact(digest(artifact))
    .with_target_artifact(accept(
        TargetArtifact::new(TargetKind::Library, digest(artifact)),
        "the declared target artifact is valid",
    ))
    .with_source_content(digest(&format!("source:{manifest}")))
    .with_generated(digest(&format!("generated:{artifact}")))
    .with_interface(digest(&format!("interface:{manifest}")))
}

/// Returns one published snapshot entry bound to an explicit non-registry source.
#[allow(clippy::too_many_arguments)]
fn entry_for_source(
    source: SourceIdentity,
    namespace: &str,
    package: &str,
    version: &str,
    publisher: &PublisherIdentity,
    manifest: &str,
    artifact: &str,
    source_content: [u8; 32],
) -> SnapshotEntry {
    entry(namespace, package, version, publisher, manifest, artifact)
        .with_source(source)
        .with_source_content(source_content)
}

/// Returns one metadata snapshot over one declared epoch window.
fn snapshot_of(
    sequence: u64,
    issue_epoch: u64,
    expiry_epoch: u64,
    entries: &[SnapshotEntry],
) -> MetadataSnapshot {
    accept(
        MetadataSnapshot::new(
            MetadataSnapshot::VERSION,
            entries[0].source().clone(),
            sequence,
            issue_epoch,
            expiry_epoch,
            entries,
        ),
        "the declared metadata snapshot is valid",
    )
}

/// Returns an authenticated snapshot fixture and its retained rollback evidence.
fn authenticated_fixture(
    _declaration: &SourceDeclaration,
    snapshot: &MetadataSnapshot,
) -> (TrustStore, RetainedState, Vec<DeclaredSignature>) {
    let entry = &snapshot.entries()[0];
    let record = key(entry.publisher().key().as_str());
    let trust = store_of(
        std::slice::from_ref(&root(
            "fixture-root",
            snapshot.source().clone(),
            entry.publisher().clone(),
            scope_of_namespace(entry.namespace().spelling()),
        )),
        std::slice::from_ref(&record),
        &[],
    );
    let retained = RetainedState::for_source(snapshot.source().clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = vec![declared_signature(&record, snapshot.content_digest())];
    (trust, retained, signatures)
}

/// Builds verification input with a signed proof for the authenticated empty advisory set.
fn verification_input<'a>(
    declarations: &'a [SourceDeclaration],
    snapshot: &'a MetadataSnapshot,
    signatures: &'a [DeclaredSignature],
    retained: &'a [RetainedState],
    publications: &'a PublicationLedger,
    observation: EpochObservation,
    freshness: FreshnessMode,
) -> VerificationInput<'a> {
    verification_input_with_advisories(
        declarations,
        snapshot,
        signatures,
        retained,
        publications,
        observation,
        freshness,
        AdvisoryStore::new(),
    )
}

/// Builds verification input with a signed proof for the supplied advisory set.
#[allow(clippy::too_many_arguments)]
fn verification_input_with_advisories<'a>(
    declarations: &'a [SourceDeclaration],
    snapshot: &'a MetadataSnapshot,
    signatures: &'a [DeclaredSignature],
    retained: &'a [RetainedState],
    publications: &'a PublicationLedger,
    observation: EpochObservation,
    freshness: FreshnessMode,
    advisories: AdvisoryStore,
) -> VerificationInput<'a> {
    verification_input_with_advisories_and_policy(
        declarations,
        snapshot,
        signatures,
        retained,
        publications,
        observation,
        freshness,
        advisories,
        RootSelectionPolicy::Unspecified,
    )
}

/// Builds verification input with a signed proof for the supplied advisory set and root policy.
#[allow(clippy::too_many_arguments)]
fn verification_input_with_advisories_and_policy<'a>(
    declarations: &'a [SourceDeclaration],
    snapshot: &'a MetadataSnapshot,
    signatures: &'a [DeclaredSignature],
    retained: &'a [RetainedState],
    publications: &'a PublicationLedger,
    observation: EpochObservation,
    freshness: FreshnessMode,
    advisories: AdvisoryStore,
    root_policy: RootSelectionPolicy,
) -> VerificationInput<'a> {
    let signer = key(snapshot.entries()[0].publisher().key().as_str());
    let proof = AdvisorySetProof::authenticated(
        snapshot,
        &advisories,
        root_policy.clone(),
        snapshot.entries()[0].publisher().clone(),
        &signer,
    );
    VerificationInput::new(
        declarations,
        snapshot,
        signatures,
        retained,
        publications,
        observation,
        freshness,
    )
    .with_root_selection(root_policy)
    .with_advisory_proof(advisories, proof)
}

/// Returns one ledger whose occupancy entered only through snapshot verification.
fn ledger_of(declaration: &SourceDeclaration, snapshot: &MetadataSnapshot) -> PublicationLedger {
    let (trust, retained, signatures) = authenticated_fixture(declaration, snapshot);
    let declarations = snapshot
        .entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            accept(
                source_declaration_for(
                    index,
                    &format!("fixture_{index}"),
                    entry.package().spelling(),
                    entry.source().clone(),
                ),
                "the fixture declaration owns the entry package subject",
            )
        })
        .collect::<Vec<_>>();
    let empty = PublicationLedger::new();
    let input = verification_input(
        &declarations,
        snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &empty,
        EpochObservation::at(snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&trust, &input);
    let mut ledger = PublicationLedger::new();
    admit(
        ledger.admit_verified(&verified, &declarations),
        "the verified snapshot occupies the publication ledger",
    );
    ledger
}

/// Returns a historical lockfile record bound to prior authenticated evidence.
fn record_of(
    entry: &SnapshotEntry,
    snapshot: &MetadataSnapshot,
    declaration: &SourceDeclaration,
) -> LockfileRecord {
    record_with_inputs(
        entry,
        snapshot,
        declaration,
        LockfileInputs {
            targets: entry
                .target_artifacts()
                .iter()
                .map(TargetArtifact::target)
                .collect(),
            target_artifacts: entry.target_artifacts().to_vec(),
            ..LockfileInputs::default()
        },
    )
}

/// Returns a historical lockfile record with every caller-supplied bound input.
fn record_with_inputs(
    entry: &SnapshotEntry,
    snapshot: &MetadataSnapshot,
    declaration: &SourceDeclaration,
    inputs: LockfileInputs,
) -> LockfileRecord {
    let (trust, retained, signatures) = authenticated_fixture(declaration, snapshot);
    let declarations = snapshot
        .entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            accept(
                source_declaration_for(
                    index,
                    &format!("record_{index}"),
                    entry.package().spelling(),
                    entry.source().clone(),
                ),
                "the record fixture declaration owns the entry package subject",
            )
        })
        .collect::<Vec<_>>();
    let empty = PublicationLedger::new();
    let input = verification_input(
        &declarations,
        snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &empty,
        EpochObservation::at(snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&trust, &input);
    admit(
        LockfileRecord::historical(entry, &verified, &retained, declaration, inputs),
        "the declared lockfile record is valid",
    )
}

/// Returns one lockfile.
fn lockfile_of(records: &[LockfileRecord]) -> Lockfile {
    accept(Lockfile::new(records), "the declared lockfile is valid")
}

/// Returns one package scope.
fn scope_of_package(namespace: &str, package: &str) -> AuthorityScope {
    accept(
        AuthorityScope::of_package(namespace, package),
        "the declared package scope is valid",
    )
}

/// Returns one whole-namespace scope.
fn scope_of_namespace(namespace: &str) -> AuthorityScope {
    accept(
        AuthorityScope::of_namespace(namespace),
        "the declared namespace scope is valid",
    )
}

/// Returns one source-scoped trust root.
fn root(
    id: &str,
    source: SourceIdentity,
    publisher: PublisherIdentity,
    scope: AuthorityScope,
) -> TrustRoot {
    accept(
        TrustRoot::new(id, source, publisher, scope),
        "the declared trust root is valid",
    )
}

/// Returns one trust store.
fn store_of(roots: &[TrustRoot], keys: &[KeyRecord], delegations: &[Delegation]) -> TrustStore {
    accept(
        TrustStore::new(roots, keys, delegations),
        "the declared trust store is valid",
    )
}

/// Returns authenticated delegation evidence over one source-scoped grant.
fn delegation(
    source: SourceIdentity,
    delegator: PublisherIdentity,
    delegate: PublisherIdentity,
    scope: AuthorityScope,
    effective_sequence: u64,
    key: &KeyRecord,
) -> Delegation {
    let timing = accept(
        DelegationTiming::new(0, u64::MAX, effective_sequence),
        "the declared delegation timing is valid",
    );
    let payload = Delegation::payload(
        &source,
        &delegator,
        &delegate,
        &scope,
        timing.not_before_epoch(),
        timing.expiry_epoch(),
        timing.effective_sequence(),
    );
    accept(
        Delegation::authenticated(
            source,
            delegator,
            delegate,
            scope,
            timing,
            declared_signature(key, payload),
        ),
        "the declared delegation is valid",
    )
}

/// Returns canonical dual-signed rotation evidence for one source-scoped authority.
fn rotation(
    source: SourceIdentity,
    scope: AuthorityScope,
    old: &KeyRecord,
    next: &KeyRecord,
    effective_sequence: u64,
    old_signature: DeclaredSignature,
    new_signature: DeclaredSignature,
) -> RotationEvidence {
    let timing = accept(
        RotationTiming::new(
            effective_sequence,
            effective_sequence,
            effective_sequence.saturating_add(1),
        ),
        "the declared rotation timing is valid",
    );
    let context = accept(
        RotationContext::new(
            source,
            scope,
            publisher("acme", old.key().as_str()),
            old.key().clone(),
            next.key().clone(),
            timing,
        ),
        "the declared rotation context is valid",
    );
    accept(
        RotationEvidence::authenticated(
            context,
            RotationSignatures::new(old_signature, new_signature),
        ),
        "the declared rotation evidence is valid",
    )
}

/// Returns the verified snapshot of one trust decision.
fn admit_snapshot<'a>(
    store: &'a TrustStore,
    input: &'a VerificationInput<'a>,
) -> VerifiedSnapshot<'a> {
    match store.verify(input) {
        Ok(verified) => verified,
        Err(refusal) => panic!("the declared snapshot verifies: {refusal}"),
    }
}

/// Returns the refusal that prevented one snapshot verification.
fn refuse_snapshot<'a>(store: &'a TrustStore, input: &'a VerificationInput<'a>) -> RegistryRefusal {
    match store.verify(input) {
        Ok(_) => panic!("the declared snapshot was expected to be refused"),
        Err(refusal) => refusal,
    }
}

/// `GNT-27.1-immutable-source-identity-and-source-kind-vocabulary` requires one canonical source identity per declaration, no fallback
/// between kinds, and configuration aliases that bind identity without becoming one.
#[test]
fn gnt_27_1_a_declaration_binds_one_canonical_source_identity() {
    assert!(
        REGISTRY_CLAUSES.contains(&"GNT-27.1-immutable-source-identity-and-source-kind-vocabulary")
    );

    let registry = registry_source("acme", "widget");
    assert_eq!(registry, registry_source("acme", "gadget"));
    let spelling = "a".repeat(40);
    let checkout = accept(
        SourceIdentity::vcs("acme.widget", &commit(&spelling)),
        "the declared version-control identity is valid",
    );
    assert!(
        SourceIdentity::vcs("https://example.invalid/acme/widget", &commit(&spelling)).is_err()
    );
    assert!(SourceIdentity::path("/home/neil/widget").is_err());
    assert!(SourceIdentity::vendored("../widget").is_err());
    let declarations = vec![
        source_declaration(0, "widget", "widget", registry.clone()),
        source_declaration(1, "widget_vcs", "widget_vcs", checkout.clone()),
    ];

    // An admissible path: the declared identity resolves to exactly its own declaration.
    let bound = admit(
        resolve_source(&declarations, &declarations[0], &registry),
        "the declared registry source resolves",
    );
    assert_eq!(bound.index(), 0);
    assert_eq!(bound.identity(), &registry);
    assert_eq!(bound.identity().kind(), SourceKind::Registry);
    assert_eq!(bound.identity().canonical_text(), "registry:acme-registry");
    assert_eq!(bound.identity().digest_hex().len(), 64);
    assert_eq!(bound.alias().spelling(), "widget");
    assert_eq!(
        admit(
            resolve_source(&declarations, &declarations[1], &checkout),
            "the declared version-control source resolves"
        )
        .index(),
        1
    );

    // A configuration alias binds an authenticated identity and is never itself an identity.
    let binding = accept(
        AliasBinding::new("local_widget", registry.clone()),
        "the declared alias binding is valid",
    );
    let aliases = accept(
        AliasBindings::new(std::slice::from_ref(&binding)),
        "the declared alias bindings are valid",
    );
    let alias = accept(
        ConfigurationAlias::new("local_widget"),
        "the declared alias spelling is valid",
    );
    assert_eq!(aliases.bound_identity(&alias), Some(&registry));
    assert_eq!(aliases.len(), 1);
    let refusal = refuse(
        aliases.semantic_identity(&declarations[0], &alias),
        "an alias is not a semantic identity",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::ConfigAliasNotIdentity)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary"
    );
    assert_eq!(refusal.declaration_identity(), &registry);

    // A same-named source of another kind never substitutes for the declared one.
    let same_text = accept(
        SourceIdentity::path(registry.canonical_text()),
        "the declared identity text is valid",
    );
    let refusal = refuse(
        resolve_source(&declarations, &declarations[0], &same_text),
        "resolution never falls back between kinds",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SourceKindFallback)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary"
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.declaration_index(), 0);
    assert_eq!(refusal.declaration_identity(), &registry);

    let undeclared = registry_source("other", "widget");
    let refusal = refuse(
        resolve_source(&declarations, &declarations[0], &undeclared),
        "an undeclared source never resolves",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SourceNotDeclared)
    );
    assert_eq!(refusal.causing_entry(), None);
}

/// `GNT-27.2-canonical-publication-names-and-external-name-mapping` requires one canonical byte representation per name, refuses
/// noncanonical publication names and canonical collisions, and maps external names to explicit
/// collision-free source aliases.
#[test]
fn gnt_27_2_canonical_names_admit_one_byte_representation() {
    let canonical = name(RegistryNameKind::Package, "widget");
    assert_eq!(canonical.spelling(), "widget");
    assert_eq!(canonical.canonical_bytes(), b"widget");
    assert_eq!(canonical.kind(), RegistryNameKind::Package);
    assert_eq!(canonical, name(RegistryNameKind::Package, "widget"));
    assert_eq!(canonical.digest_hex().len(), 64);

    // A noncanonical publication name is refused instead of normalized silently.
    let decomposed = reject(
        RegistryName::namespace("cafe\u{301}"),
        "a noncanonical name is refused",
    );
    assert_eq!(
        decomposed.code(),
        Some(RegistryDiagnosticCode::NameNoncanonical)
    );
    assert_eq!(
        decomposed.clause(),
        "GNT-27.2-canonical-publication-names-and-external-name-mapping"
    );
    let malformed = reject(
        RegistryName::package("widget/sub"),
        "a malformed name is refused",
    );
    assert_eq!(malformed.code(), None);
    assert_eq!(
        malformed.clause(),
        "GNT-27.2-canonical-publication-names-and-external-name-mapping"
    );

    // A canonical collision is refused rather than resolved by preference.
    let mut admitted = PublicationNameSet::new();
    accept(
        admitted.admit(name(RegistryNameKind::Publisher, "Acme")),
        "the declared publisher name is admitted",
    );
    assert_eq!(admitted.len(), 1);
    accept(
        admitted.admit(name(RegistryNameKind::Publisher, "Acme")),
        "the same publication name admits once",
    );
    assert!(admitted.contains(&name(RegistryNameKind::Publisher, "Acme")));
    let collision_error = reject(
        admitted.admit(name(RegistryNameKind::Publisher, "acme")),
        "a case-folded collision is refused",
    );
    assert_eq!(
        collision_error.code(),
        Some(RegistryDiagnosticCode::NameCollision)
    );
    assert!(
        collision(
            &name(RegistryNameKind::Package, "widget"),
            &name(RegistryNameKind::Namespace, "widget")
        )
        .is_none()
    );

    // Two external names sharing one alias skeleton are refused.
    let mut aliases = ExternalAliasMap::new();
    let first = accept(
        ExternalName::new(RegistryNameKind::Package, "widget"),
        "the declared external name is valid",
    );
    let second = accept(
        ExternalName::new(RegistryNameKind::Package, "WIDGET"),
        "the declared external name is valid",
    );
    let alias = accept(
        aliases.insert(first.clone()),
        "the declared external name is mapped",
    );
    assert_eq!(alias.as_str(), "ext_package_widget");
    assert_eq!(
        aliases.alias(&first).map(SourceAlias::as_str),
        Some("ext_package_widget")
    );
    let collision_error = reject(
        aliases.insert(second),
        "two external names sharing one skeleton are refused",
    );
    assert_eq!(
        collision_error.code(),
        Some(RegistryDiagnosticCode::ExternalAliasCollision)
    );
    let other = accept(
        ExternalName::new(RegistryNameKind::Package, "gadget"),
        "the declared external name is valid",
    );
    let other_alias = accept(aliases.insert(other.clone()), "a second name maps too");
    assert_ne!(other_alias.as_str(), alias.as_str());
    assert_eq!(aliases.external(&alias), Some(&first));
    assert_eq!(aliases.len(), 2);
}

/// `GNT-27.3-authenticated-metadata-snapshot-and-client-verification` requires a versioned snapshot over a monotone sequence whose
/// verification returns either a verified snapshot or a typed refusal naming the causing entry.
#[test]
fn gnt_27_3_a_snapshot_verifies_or_refuses_with_its_causing_entry() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let gadget = entry("acme", "gadget", "1.0.0", &acme, "manifest-b", "artifact-b");
    let acme_root = root(
        "acme-root",
        widget.source().clone(),
        acme.clone(),
        scope_of_namespace("acme"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let snapshot = snapshot_of(4, 100, 200, &[widget.clone(), gadget.clone()]);
    assert_eq!(snapshot.version(), MetadataSnapshot::VERSION);
    assert_eq!(snapshot.sequence(), 4);
    assert_eq!(snapshot.entries().len(), 2);
    assert_eq!(snapshot.expiry_epoch(), 200);
    let declarations = vec![
        source_declaration(0, "widget", "widget", widget.source().clone()),
        source_declaration(1, "gadget", "gadget", gadget.source().clone()),
    ];
    let ledger = ledger_of(&declarations[0], &snapshot);
    let retained = [RetainedState::for_source(widget.source().clone(), 1)];
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        &retained,
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );

    // An admissible path: the snapshot verifies with one authority per entry.
    let verified = admit_snapshot(&store, &input);
    assert_eq!(verified.snapshot().sequence(), 4);
    assert_eq!(verified.identity(), snapshot.identity());
    assert_eq!(verified.entries().len(), 2);
    assert_eq!(verified.authorities().len(), 2);
    assert_eq!(verified.entries()[0].package().spelling(), "gadget");
    assert_eq!(
        verified.authority(0).map(EntryAuthority::declaration),
        Some(1)
    );
    assert_eq!(
        verified.authority(1).map(EntryAuthority::declaration),
        Some(0)
    );
    assert_eq!(
        verified
            .authority(0)
            .and_then(|authority| declarations
                .iter()
                .find(|declaration| declaration.index() == authority.declaration()))
            .map(|declaration| declaration.coordinate().as_str()),
        Some("manifest:dependency:1")
    );
    assert_eq!(
        verified
            .authority(1)
            .map(|authority| authority.grant().root().as_str()),
        Some("acme-root")
    );
    assert!(verified.freshness().is_online());
    assert_eq!(verified.freshness().age(), 50);

    // A declared signature that does not verify is refused.
    let forged = vec![DeclaredSignature::declared(
        acme_key.key().clone(),
        digest("forged-signature"),
    )];
    let forged_input = verification_input(
        &declarations,
        &snapshot,
        &forged,
        &retained,
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(1);
    let refusal = refuse_snapshot(&store, &forged_input);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SignatureUnverified)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.4-trust-roots-and-delegated-authority"
    );
    assert_eq!(refusal.declaration_index(), 1);
    assert_eq!(refusal.declaration_identity(), declarations[1].identity());

    // An entry that no declaration binds is refused before any other check reads it.
    let foreign = registry_source("other", "widget");
    let unbound = snapshot_of(
        5,
        100,
        200,
        std::slice::from_ref(&widget.clone().with_source(foreign.clone())),
    );
    let unbound_signatures = vec![declared_signature(&acme_key, unbound.content_digest())];
    let unbound_input = verification_input(
        &declarations,
        &unbound,
        &unbound_signatures,
        &retained,
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &unbound_input);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AttributionMissing)
    );
    assert_eq!(refusal.clause(), "GNT-27.13-trust-failure-attribution");
    assert!(!refusal.is_bound());
    assert_eq!(refusal.causing_entry(), Some(0));
    assert_eq!(refusal.declaration_identity(), &foreign);

    // An unsupported snapshot format version is refused before a snapshot value exists.
    let mut unsupported = MetadataSnapshot::VERSION;
    unsupported.major = 9;
    let error = reject(
        MetadataSnapshot::new(
            unsupported,
            widget.source().clone(),
            4,
            100,
            200,
            std::slice::from_ref(&widget),
        ),
        "an unsupported snapshot version is refused",
    );
    assert_eq!(
        error.code(),
        Some(RegistryDiagnosticCode::SnapshotVersionUnsupported)
    );
    assert_eq!(
        error.clause(),
        "GNT-27.3-authenticated-metadata-snapshot-and-client-verification"
    );
}

/// `GNT-27.4-trust-roots-and-delegated-authority` requires explicit roots, scope narrowing only, and no
/// ambient or fallback trust.
#[test]
fn gnt_27_4_explicit_roots_and_narrowing_delegations_decide_authority() {
    let root_key = key("root-key");
    let delegate_key = key("delegate-key");
    let acme = publisher("acme", "root-key");
    let acme_tools = publisher("acme-tools", "delegate-key");
    let keys = vec![root_key, delegate_key];
    let narrow_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );

    // A delegation that would widen its delegator's authority is refused.
    let widening = delegation(
        registry_source("acme", "widget"),
        acme.clone(),
        acme_tools.clone(),
        scope_of_namespace("acme"),
        1,
        &keys[0],
    );
    let error = reject(
        TrustStore::new(
            std::slice::from_ref(&narrow_root),
            &keys,
            std::slice::from_ref(&widening),
        ),
        "a widening delegation is refused",
    );
    assert_eq!(
        error.code(),
        Some(RegistryDiagnosticCode::DelegationOutOfScope)
    );
    assert_eq!(
        error.clause(),
        "GNT-27.4-trust-roots-and-delegated-authority"
    );

    // An admissible path: a narrowing delegation admits the delegate inside one package.
    let narrowing = delegation(
        registry_source("acme", "widget"),
        acme.clone(),
        acme_tools.clone(),
        scope_of_package("acme", "widget"),
        1,
        &keys[0],
    );
    let store = store_of(
        std::slice::from_ref(&narrow_root),
        &keys,
        std::slice::from_ref(&narrowing),
    );
    assert_eq!(store.roots().len(), 1);
    assert_eq!(store.delegations().len(), 1);
    assert_eq!(store.delegations()[0].root().as_str(), "acme-root");
    assert_eq!(store.delegations()[0].ancestors().len(), 1);
    let inside = entry(
        "acme",
        "widget",
        "1.0.0",
        &acme_tools,
        "manifest-a",
        "artifact-a",
    );
    let inside_declaration = source_declaration(0, "widget", "widget", inside.source().clone());
    let grant = admit(
        store.authorize(&inside_declaration, &inside, 2),
        "the narrowed delegate is authorized inside its scope",
    );
    assert!(grant.is_delegated());
    assert!(!grant.is_inherited());
    assert_eq!(grant.authorized_by().as_str(), "delegate-key");
    assert_eq!(grant.root_key().as_str(), "root-key");
    assert_eq!(
        grant.scope().package().map(RegistryName::spelling),
        Some("widget")
    );
    let rooted = entry("acme", "widget", "0.9.0", &acme, "manifest-c", "artifact-c");
    let rooted_declaration =
        source_declaration(1, "widget_root", "widget_root", rooted.source().clone());
    let grant = admit(
        store.authorize(&rooted_declaration, &rooted, 2),
        "the root itself is authorized across its scope",
    );
    assert!(!grant.is_delegated());
    assert_eq!(grant.authorized_by().as_str(), "root-key");

    // An entry outside the delegated scope is refused with the authority that was found.
    let outside = entry(
        "acme",
        "gadget",
        "1.0.0",
        &acme_tools,
        "manifest-b",
        "artifact-b",
    );
    let outside_declaration = source_declaration(1, "gadget", "gadget", outside.source().clone());
    let refusal = refuse(
        store.authorize(&outside_declaration, &outside, 2),
        "an out-of-scope entry is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::DelegationOutOfScope)
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.declaration_index(), 1);
    assert!(matches!(
        refusal.condition(),
        RegistryError::DelegationOutOfScope { .. }
    ));

    // No ambient trust: a publisher no root and no delegation names holds no authority.
    let stranger = entry(
        "acme",
        "widget",
        "1.0.0",
        &publisher("stranger", "stranger-key"),
        "manifest-d",
        "artifact-d",
    );
    let stranger_declaration =
        source_declaration(2, "stranger", "stranger", stranger.source().clone());
    let refusal = refuse(
        store.authorize(&stranger_declaration, &stranger, 2),
        "an unnamed publisher holds no authority",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::PublisherUnauthorized)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::PublisherUnauthorized {
            defect: AuthorizationDefect::UnknownPublisher,
            ..
        }
    ));
    let empty_store = store_of(&[], &keys, &[]);
    let refusal = refuse(
        empty_store.authorize(&stranger_declaration, &stranger, 2),
        "an empty store authorizes nothing",
    );
    assert_eq!(refusal.code(), None);
    assert_eq!(refusal.reason(), TrustFailureReason::AbsentTrustRoot);
    assert_eq!(
        refusal.requirement_anchor(),
        "GNT-27.4-trust-roots-and-delegated-authority"
    );
}

/// `GNT-27.5-key-rotation-and-compromise-recovery` requires rotation evidence under both keys, a
/// successor that inherits the retired key's authority, and a compromise that revokes it.
#[test]
fn gnt_27_5_rotation_and_compromise_decide_the_signing_key() {
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let mut store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&old),
        &[],
    );
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);

    // A rotation whose evidence is valid under one key only is refused.
    let one_sided = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        DeclaredSignature::declared(next.key().clone(), digest("forged-rotation")),
    );
    let refusal = refuse(
        store.rotate(
            &source_declaration(0, "widget", "widget", registry_source("acme", "widget")),
            one_sided,
            std::slice::from_ref(&next),
        ),
        "rotation evidence under one key is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::RotationEvidenceInvalid)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.5-signing-key-rotation-and-compromise-recovery"
    );
    // An admissible path: evidence under both keys rotates the key.
    let evidence = rotation(
        source,
        scope,
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        declared_signature(&next, payload),
    );
    let rotation_declaration =
        source_declaration(0, "widget", "widget", registry_source("acme", "widget"));
    admit(
        store.rotate(&rotation_declaration, evidence, std::slice::from_ref(&next)),
        "evidence under both keys rotates the key",
    );
    assert_eq!(store.rotations().len(), 1);
    assert_eq!(store.rotations()[0].old_key().as_str(), "acme-key");
    assert_eq!(store.rotations()[0].new_key().as_str(), "next-key");

    // Metadata signed by the successor inherits the retired key's authority.
    let upgraded = entry(
        "acme",
        "widget",
        "2.0.0",
        &publisher("acme", "next-key"),
        "manifest-b",
        "artifact-b",
    );
    let upgraded_declaration = source_declaration(0, "widget", "widget", upgraded.source().clone());
    let upgraded_grant = admit(
        store.authorize(&upgraded_declaration, &upgraded, 5),
        "the rotated key holds the retired key's authority",
    );
    assert!(upgraded_grant.is_inherited());
    assert_eq!(
        upgraded_grant.inherited_from().map(KeyId::as_str),
        Some("acme-key")
    );
    assert_eq!(upgraded_grant.authorized_by().as_str(), "next-key");
    assert_eq!(upgraded_grant.root().as_str(), "acme-root");
    assert!(!upgraded_grant.is_delegated());

    // Metadata signed only by the retired key after the rotation is refused.
    let retired = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let retired_declaration = source_declaration(
        1,
        "widget_retired",
        "widget_retired",
        retired.source().clone(),
    );
    let refusal = refuse(
        store.authorize(&retired_declaration, &retired, 5),
        "a superseded key signs nothing after its rotation",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::KeySuperseded));
    assert_eq!(
        refusal.clause(),
        "GNT-27.5-signing-key-rotation-and-compromise-recovery"
    );
    assert_eq!(refusal.declaration_index(), 1);
    admit(
        store.authorize(&retired_declaration, &retired, 3),
        "metadata that precedes the rotation stays authorized",
    );

    // A source-scoped compromise is authorized by the successor after the retiring key's
    // overlap closes, then revokes the retired key and its inherited authority.
    let compromise_scope = scope_of_package("acme", "widget");
    let recovered = publisher("acme", "next-key");
    let compromise_payload = Compromise::payload(
        retired.source(),
        &compromise_scope,
        &recovered,
        old.key(),
        6,
        6,
    );
    let compromise = accept(
        Compromise::authenticated(
            retired.source().clone(),
            compromise_scope,
            recovered,
            old.key().clone(),
            6,
            6,
            declared_signature(&next, compromise_payload),
        ),
        "the declared compromise evidence is valid",
    );
    admit(
        store.compromise(&retired_declaration, compromise),
        "the signed source-scoped compromise is admitted",
    );
    let refusal = refuse(
        store.authorize(&retired_declaration, &retired, 6),
        "a compromised key holds no authority",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::KeyCompromised));
    let refusal = refuse(
        store.authorize(&upgraded_declaration, &upgraded, 6),
        "a successor descended from a compromised key is refused",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::KeyCompromised));
    assert_eq!(refusal.declaration_index(), upgraded_declaration.index());
    assert_eq!(
        refusal.requirement_anchor(),
        "GNT-27.5-signing-key-rotation-and-compromise-recovery"
    );
    assert_eq!(
        refusal
            .attribution()
            .coordinate()
            .map(|coordinate| coordinate.as_str()),
        Some("manifest:dependency:0")
    );
}

/// `GNT-27.6-expiry-freshness-and-offline-mode` requires expired metadata to fail closed and an explicit
/// offline pinned path that reports its age and is distinguished from an online check.
#[test]
fn gnt_27_6_expiry_fails_closed_and_a_pinned_path_reports_its_age() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", widget.source().clone());
    let declarations = vec![declaration.clone()];
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(widget.source().clone(), 1);
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    assert_eq!(snapshot.issue_epoch(), 100);

    // An admissible path: an online observation inside the declared window verifies.
    let online = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &online);
    assert!(verified.freshness().is_online());
    assert_eq!(verified.freshness().age(), 50);
    assert_eq!(verified.freshness().observed_epoch(), 150);
    assert!(!verified.freshness().snapshot_expired());
    assert_eq!(verified.freshness().mode(), FreshnessMode::Online);
    let offline_witness = accept(
        verified.offline_witness(declaration.identity(), 199),
        "the verified snapshot mints an offline witness",
    );
    assert!(
        verified
            .offline_witness(declaration.identity(), 200)
            .is_ok()
    );

    // An observation past the declared expiry fails closed.
    let expired = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(200),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&store, &expired);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SnapshotExpired)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.6-expiry-freshness-and-offline-mode"
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.causing_entry(), None);
    let early = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(99),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    assert_eq!(
        refuse_snapshot(&store, &early).code(),
        Some(RegistryDiagnosticCode::SnapshotEpochInconsistent)
    );

    // An explicit offline witness admits only the same snapshot during its own validity window.
    let offline = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(199),
        FreshnessMode::offline(offline_witness.clone()),
    );
    let verified = admit_snapshot(&store, &offline);
    assert!(!verified.freshness().is_online());
    assert!(!verified.freshness().snapshot_expired());
    assert_eq!(verified.freshness().age(), 99);
    assert_eq!(verified.freshness().expiry_epoch(), 200);
    assert_ne!(verified.freshness().mode(), FreshnessMode::Online);

    // A witness cannot extend the snapshot's declared expiry.
    let beyond = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(200),
        FreshnessMode::offline(offline_witness),
    )
    .with_snapshot_declaration(declaration.index());
    assert_eq!(
        refuse_snapshot(&store, &beyond).code(),
        Some(RegistryDiagnosticCode::SnapshotExpired)
    );
    let unresolvable = reject(
        verified.offline_witness(declaration.identity(), 99),
        "a witness whose bound precedes snapshot issuance is refused",
    );
    assert_eq!(
        unresolvable.code(),
        Some(RegistryDiagnosticCode::SnapshotEpochInconsistent)
    );
}

/// `GNT-27.7-rollback-and-freeze-resistance` requires a retained minimum trusted sequence and
/// monotone evidence, and refuses a rollback and an unchanged sequence with changed content.
#[test]
fn gnt_27_7_a_rollback_or_a_freeze_is_refused_against_retained_state() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", widget.source().clone());
    let declarations = vec![declaration.clone()];
    let ledger = ledger_of(&declaration, &snapshot);
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];

    // An admissible path: the retained sequence itself carries the same content.
    let monotone = RetainedState::for_source(widget.source().clone(), 4)
        .with_content(4, snapshot.content_digest());
    let accepted = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&monotone),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &accepted);
    assert_eq!(verified.identity(), snapshot.identity());
    assert_eq!(monotone.minimum_sequence(), 4);
    assert_eq!(monotone.sequences().count(), 1);
    assert_eq!(
        monotone.retained_content(4),
        Some(snapshot.content_digest())
    );

    let duplicate = RetainedState::for_source(widget.source().clone(), 4)
        .with_content(4, snapshot.content_digest());
    for retained_states in [
        &[monotone.clone(), duplicate.clone()][..],
        &[duplicate, monotone][..],
    ] {
        let refusal = refuse_snapshot(
            &store,
            &verification_input(
                &declarations,
                &snapshot,
                &signatures,
                retained_states,
                &ledger,
                EpochObservation::at(150),
                FreshnessMode::online(),
            ),
        );
        assert!(matches!(
            refusal.condition(),
            RegistryError::RetainedStateAmbiguous { supplied: 2, .. }
        ));
        assert_eq!(refusal.reason(), TrustFailureReason::RetainedStateAmbiguous);
        assert_eq!(refusal.requirement_anchor(), refusal.reason().anchor());
    }

    // A snapshot older than the retained minimum is a rollback.
    let advanced = RetainedState::for_source(widget.source().clone(), 5);
    let rollback = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&advanced),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &rollback);
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::Rollback));
    assert_eq!(refusal.clause(), "GNT-27.7-rollback-and-freeze-resistance");
    assert!(refusal.is_bound());
    assert_eq!(refusal.declaration_index(), 0);
    assert!(matches!(
        refusal.condition(),
        RegistryError::Rollback {
            declared: 4,
            retained_minimum: 5,
        }
    ));

    // One retained sequence that now carries another content is a freeze or equivocation.
    let equivocated = RetainedState::for_source(widget.source().clone(), 1)
        .with_content(4, digest("other-content"));
    let frozen = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&equivocated),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &frozen);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::FreezeEquivocation)
    );
    assert_eq!(refusal.clause(), "GNT-27.7-rollback-and-freeze-resistance");
    assert!(matches!(
        refusal.condition(),
        RegistryError::FreezeEquivocation { sequence: 4, .. }
    ));
    // A declared source staleness bound detects a freeze even when the sequence is unchanged.
    let stale_source = RetainedState::for_source(widget.source().clone(), 4)
        .with_content(4, snapshot.content_digest())
        .with_maximum_staleness(25)
        .with_expiry_epoch(100);
    let frozen = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&stale_source),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &frozen);
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::FreezeDetected));
    assert!(matches!(
        refusal.condition(),
        RegistryError::FreezeDetected {
            sequence: 4,
            maximum_staleness: 25,
            observed_epoch: 150,
        }
    ));
    let mut progressing = RetainedState::for_source(widget.source().clone(), 4)
        .with_content(4, snapshot.content_digest());
    progressing.advance(9, digest("later-content"));
    assert_eq!(progressing.minimum_sequence(), 9);
    assert_eq!(progressing.sequences().count(), 2);
}

/// `GNT-27.8-publication-immutability` requires one authenticated tuple to name one set of
/// manifest, source, and artifact bytes forever.
#[test]
fn gnt_27_8_a_publication_tuple_never_names_two_byte_sets() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let published = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let _replay = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let declaration = source_declaration(0, "widget", "widget", published.source().clone());

    // An authenticated snapshot, not a raw publication record, occupies the ledger.
    let published_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&published));
    let mut ledger = ledger_of(&declaration, &published_snapshot);
    assert_eq!(ledger.len(), 1);
    let (replay_trust, replay_retained, replay_signatures) =
        authenticated_fixture(&declaration, &published_snapshot);
    let replay_declarations = [declaration.clone()];
    let replay_empty = PublicationLedger::new();
    let replay_input = verification_input(
        &replay_declarations,
        &published_snapshot,
        &replay_signatures,
        std::slice::from_ref(&replay_retained),
        &replay_empty,
        EpochObservation::at(100),
        FreshnessMode::online(),
    );
    let replay_verified = admit_snapshot(&replay_trust, &replay_input);
    admit(
        ledger.admit_verified(&replay_verified, &replay_declarations),
        "an identical verified snapshot retains no second publication",
    );
    assert_eq!(ledger.len(), 1);

    // A differing publication of the same tuple is refused before it can occupy the ledger.
    let changed = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-z")
        .with_generated(digest("generated:artifact-a"));
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&changed));
    let declarations = vec![declaration.clone()];
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let retained = RetainedState::for_source(changed.source().clone(), 1);
    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &input);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::PublicationImmutable)
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.causing_entry(), Some(0));
    assert!(matches!(
        refusal.condition(),
        RegistryError::PublicationImmutable {
            defect: PublicationDefect::ChangedArtifact,
            recorded,
            observed,
            ..
        } if *recorded == digest("artifact-a") && *observed == digest("artifact-z")
    ));

    // A correction requires a new version and a separately verified snapshot admission.
    let corrected = entry("acme", "widget", "2.0.0", &acme, "manifest-b", "artifact-b");
    let corrected_snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&corrected));
    let corrected_signatures = vec![declared_signature(
        &acme_key,
        corrected_snapshot.content_digest(),
    )];
    let verification_ledger = ledger.clone();
    let corrected_input = verification_input(
        &declarations,
        &corrected_snapshot,
        &corrected_signatures,
        std::slice::from_ref(&retained),
        &verification_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let corrected_verified = admit_snapshot(&store, &corrected_input);
    admit(
        ledger.admit_verified(&corrected_verified, &declarations),
        "a correction under a new version is recorded after verification",
    );
    assert_eq!(ledger.len(), 2);
}

/// `GNT-27.9-yank-semantics` requires a yank to remove a release from ordinary new resolution
/// without ever rewriting a lockfile.
#[test]
fn gnt_27_9_a_yank_stops_new_resolution_without_rewriting_a_lockfile() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let published = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let yanked = published.clone().with_publication(PublicationState::Yanked);
    let published_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&published));
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&yanked));
    let declaration = source_declaration(0, "widget", "widget", yanked.source().clone());
    let declarations = vec![declaration.clone()];
    let acme_root = root(
        "acme-root",
        declaration.identity().clone(),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let published_ledger = ledger_of(&declaration, &published_snapshot);
    let published_retained = RetainedState::for_source(declaration.identity().clone(), 3)
        .with_content(3, published_snapshot.content_digest());
    let published_signatures = vec![declared_signature(
        &acme_key,
        published_snapshot.content_digest(),
    )];
    let published_input = verification_input(
        &declarations,
        &published_snapshot,
        &published_signatures,
        std::slice::from_ref(&published_retained),
        &published_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let published_verified = admit_snapshot(&store, &published_input);
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(declaration.identity().clone(), 4)
        .with_content(4, snapshot.content_digest());
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &input);
    assert!(published.is_resolvable());
    assert_eq!(yanked.publication(), PublicationState::Yanked);

    // An admissible path: a published release resolves and a yanked one is refused.
    let resolved = admit(
        resolve_new_release(
            &declaration,
            &published_verified,
            &published_retained,
            &published,
        ),
        "a published release resolves",
    );
    assert_eq!(resolved.version().as_str(), "1.0.0");
    let refusal = refuse(
        resolve_new_release(&declaration, &verified, &retained, &yanked),
        "a yanked release is not resolved anew",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::ReleaseYanked));
    assert_eq!(refusal.clause(), "GNT-27.9-yank-semantics");
    assert!(matches!(
        refusal.condition(),
        RegistryError::ReleaseYanked { package, version, source, sequence }
            if package.as_ref() == "widget" && version.as_ref() == "1.0.0" && source == declaration.identity() && *sequence == 4
    ));

    // An existing verified lockfile stays reproducible.
    let record = record_of(&published, &published_snapshot, &declaration);
    let lockfile = lockfile_of(std::slice::from_ref(&record));
    assert_eq!(lockfile.replay().len(), 1);
    assert_eq!(
        lockfile.replay()[0].publication(),
        PublicationState::Published
    );
    assert_eq!(lockfile.replay()[0].version().as_str(), "1.0.0");
    assert_eq!(lockfile.records()[0].evidence(), record.attest());
    assert_eq!(
        lockfile.records()[0].snapshot(),
        published_snapshot.identity()
    );
    assert!(!lockfile.canonical_bytes().is_empty());
    assert_eq!(lockfile.digest_hex().len(), 64);

    // A silent rewrite of the locked yanked release is refused.
    let refusal = refuse(
        lockfile.rewrite_kept(&declaration, &[], &verified, &retained),
        "a rewrite dropping a yanked release is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::LockfileRewriteRefused)
    );
    assert_eq!(refusal.clause(), "GNT-27.9-yank-semantics");
    let kept = admit(
        lockfile.rewrite_kept(&declaration, &[0], &verified, &retained),
        "a rewrite that keeps every record is admitted",
    );
    assert_eq!(kept.replay().len(), 1);
}

/// `GNT-27.10-security-revocation` requires an authenticated advisory with explicit scope and
/// severity that may refuse a build or run but never substitutes code or rewrites a lockfile.
#[test]
fn gnt_27_10_a_revocation_refuses_a_build_without_substituting_code() {
    let acme_key = key("acme-key");
    let stranger_key = key("stranger-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        &[acme_key.clone(), stranger_key.clone()],
        &[],
    );
    let declaration = source_declaration(0, "widget", "widget", registry_source("acme", "widget"));
    let scope = accept(
        AdvisoryScope::new(
            registry_source("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            &[accept(
                TargetArtifact::new(TargetKind::Library, digest("artifact-a")),
                "the declared advisory target artifact is valid",
            )],
        ),
        "the declared advisory scope is valid",
    );
    let advisory = accept(
        SecurityAdvisory::new("GNT-27.10-1", scope, Severity::RefuseAllExecution),
        "the declared advisory is valid",
    );
    assert_eq!(advisory.severity(), Severity::RefuseAllExecution);
    assert_eq!(
        advisory.scope().artifacts()[0].target(),
        TargetKind::Library
    );
    assert_eq!(
        advisory.scope().artifacts()[0].digest(),
        digest("artifact-a")
    );
    assert_eq!(
        Severity::from_wire_name("refuse-all-execution"),
        Some(Severity::RefuseAllExecution)
    );
    assert_eq!(Severity::ALL.len(), 4);
    assert_eq!(Severity::from_wire_name("critical"), None);
    for severity in Severity::ALL {
        assert_eq!(
            severity.refuses(AdvisoryBoundary::NewResolution),
            severity == Severity::RefuseNewResolution
        );
        assert_eq!(
            severity.refuses(AdvisoryBoundary::NewBuild),
            severity == Severity::RefuseNewBuild
        );
        assert_eq!(
            severity.refuses(AdvisoryBoundary::Execution),
            severity == Severity::RefuseAllExecution
        );
    }

    // An admissible path: an authenticated advisory enters the store.
    let signature = declared_signature(&acme_key, advisory.digest());
    let mut advisories = AdvisoryStore::new();
    assert!(advisories.is_empty());
    admit(
        advisories.admit(
            &declaration,
            advisory.clone(),
            signature.clone(),
            acme.clone(),
            &store,
            5,
        ),
        "an authenticated advisory is admitted",
    );
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories.advisories()[0].id().as_str(), "GNT-27.10-1");
    let clean = accept(
        RunRequest::new(
            registry_source("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            TargetKind::Library,
            digest("artifact-b"),
        ),
        "the declared request is valid",
    );
    let admitted = admit(
        advisories.admit_run(&declaration, &clean),
        "an unaffected artifact is admitted",
    );
    assert_eq!(admitted.artifact(), digest("artifact-b"));
    assert!(!admitted.is_durable());

    let same_digest_other_target = accept(
        RunRequest::new(
            registry_source("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            TargetKind::Binary,
            digest("artifact-a"),
        ),
        "the declared request is valid",
    );
    admit(
        advisories.admit_run(&declaration, &same_digest_other_target),
        "an advisory does not widen from one target artifact to another",
    );

    // The covered artifact is refused under its advisory and severity.
    let covered = accept(
        RunRequest::new(
            registry_source("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            TargetKind::Library,
            digest("artifact-a"),
        ),
        "the declared request is valid",
    )
    .durable();
    assert!(covered.is_durable());
    admit(
        advisories.admit_new_resolution(&declaration, &covered),
        "an execution-only advisory does not refuse new resolution",
    );
    admit(
        advisories.admit_new_build(&declaration, &covered),
        "an execution-only advisory does not refuse a new build",
    );
    let refusal = refuse(
        advisories.admit_run(&declaration, &covered),
        "a covered artifact is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AdvisoryRefusesBuild)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.10-security-revocation-and-durable-execution-policy"
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AdvisoryRefusesBuild {
            severity: Severity::RefuseAllExecution,
            ..
        }
    ));

    // A declared substitute is refused: no revocation substitutes code or rewrites a lockfile.
    let substitute = covered
        .clone()
        .with_substitute(registry_source("other", "widget"));
    assert!(substitute.substitute().is_some());
    let refusal = refuse(
        advisories.admit_run(&declaration, &substitute),
        "a declared substitute is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AdvisorySubstitutionRefused)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.10-security-revocation-and-durable-execution-policy"
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AdvisorySubstitutionRefused { .. }
    ));

    // An unverified or unauthorized advisory never enters the store.
    let mut foreign = AdvisoryStore::new();
    let forged = DeclaredSignature::declared(acme_key.key().clone(), digest("forged-advisory"));
    let refusal = refuse(
        foreign.admit(
            &declaration,
            advisory.clone(),
            forged,
            acme.clone(),
            &store,
            5,
        ),
        "an unverified advisory is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SignatureUnverified)
    );
    let stranger_signature = declared_signature(&stranger_key, advisory.digest());
    let refusal = refuse(
        foreign.admit(
            &declaration,
            advisory,
            stranger_signature,
            publisher("stranger", "stranger-key"),
            &store,
            5,
        ),
        "an unauthorized advisory publisher is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::PublisherUnauthorized)
    );
    assert!(foreign.is_empty());
}

/// `GNT-27.11-vcs-path-and-vendor-source-verification` requires pinned commit and content verification,
/// modified-path detection, vendoring, and mirror substitution that presents one snapshot identity.
#[test]
fn gnt_27_11_pinned_checkouts_vendored_trees_and_mirrors_present_one_universe() {
    let acme = publisher("acme", "acme-key");
    let spelling = "a".repeat(40);
    let pinned_commit = commit(&spelling);
    let vcs = accept(
        SourceIdentity::vcs("acme.widget", &pinned_commit),
        "the declared version-control identity is valid",
    );
    let pin = accept(
        VcsPin::new(vcs.clone(), &spelling, digest("content-a")),
        "the declared version-control pin is valid",
    );
    let declaration = source_declaration(0, "widget", "widget", vcs.clone());

    // An admissible path: a clean checkout at the pinned commit and content verifies.
    let clean = PinnedTree::observed(
        vcs.clone(),
        Some(pinned_commit.clone()),
        digest("content-a"),
    );
    assert!(clean.is_clean());
    let checkout = admit(
        verify_pinned_tree(&declaration, &pin, &clean),
        "a clean pinned checkout verifies",
    );
    assert_eq!(checkout.content().digest(), digest("content-a"));
    assert_eq!(checkout.content().hex(), {
        let mut text = String::new();
        for byte in digest("content-a") {
            text.push_str(&format!("{byte:02x}"));
        }
        text
    });
    assert_eq!(checkout.commit().as_str(), spelling);
    assert_eq!(pin.source(), &vcs);
    assert_eq!(pin.content(), digest("content-a"));

    // A modified path is refused, and so is changed content or an unpinned checkout.
    let modified = clean.clone().modified("crate::main").modified("crate::lib");
    assert_eq!(modified.modified_paths().len(), 2);
    let refusal = refuse(
        verify_pinned_tree(&declaration, &pin, &modified),
        "a modified path is refused",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::ModifiedPath));
    assert_eq!(
        refusal.clause(),
        "GNT-27.11-vcs-path-and-vendor-source-verification"
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::ModifiedPath { path } if path.as_ref() == "crate::lib"
    ));
    let changed = PinnedTree::observed(
        vcs.clone(),
        Some(pinned_commit.clone()),
        digest("content-z"),
    );
    let refusal = refuse(
        verify_pinned_tree(&declaration, &pin, &changed),
        "changed content is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::ContentMismatch)
    );
    let unpinned = PinnedTree::observed(vcs.clone(), None, digest("content-a"));
    let refusal = refuse(
        verify_pinned_tree(&declaration, &pin, &unpinned),
        "an unpinned checkout is refused",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::VcsPinMismatch));
    assert!(matches!(
        refusal.condition(),
        RegistryError::PinMismatch {
            defect: PinDefect::Commit,
            ..
        }
    ));

    // A path source is verified through its own content pin.
    let path = accept(
        SourceIdentity::path("crate::vendor::widget"),
        "the declared path identity is valid",
    );
    let path_pin = accept(
        PathPin::new(path.clone(), digest("content-a")),
        "the declared path pin is valid",
    );
    let path_declaration = source_declaration(1, "widget_path", "widget_path", path.clone());
    let path_tree = PinnedTree::observed(path.clone(), None, digest("content-a"));
    assert_eq!(
        admit(
            verify_path_tree(&path_declaration, &path_pin, &path_tree),
            "a clean path tree verifies"
        )
        .digest(),
        digest("content-a")
    );
    let dirty_path = path_tree.clone().modified("crate::lib");
    assert_eq!(
        refuse(
            verify_path_tree(&path_declaration, &path_pin, &dirty_path),
            "a modified path tree is refused"
        )
        .code(),
        Some(RegistryDiagnosticCode::ModifiedPath)
    );

    // A vendored directory proves the declared source and authenticated snapshot identity only.
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let original_source = widget.source().clone();
    let vendor_declaration = accept(
        source_declaration_for(2, "widget_vendored", "widget", original_source.clone()),
        "the vendored declaration owns the widget package subject",
    );
    let vendor_root = root(
        "acme-vendor-root",
        original_source.clone(),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let vendor_store = store_of(
        std::slice::from_ref(&vendor_root),
        std::slice::from_ref(&key("acme-key")),
        &[],
    );
    let vendor_declarations = vec![vendor_declaration.clone()];
    let vendor_ledger = ledger_of(&vendor_declaration, &snapshot);
    let vendor_retained = RetainedState::for_source(original_source.clone(), 4)
        .with_content(4, snapshot.content_digest());
    let vendor_signatures = vec![declared_signature(
        &key("acme-key"),
        snapshot.content_digest(),
    )];
    let vendor_input = verification_input(
        &vendor_declarations,
        &snapshot,
        &vendor_signatures,
        std::slice::from_ref(&vendor_retained),
        &vendor_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified_vendor_snapshot = admit_snapshot(&vendor_store, &vendor_input);
    let vendor_entries = [accept(
        VendorEntry::new(
            "acme",
            "widget",
            "1.0.0",
            digest("manifest-a"),
            digest("source:manifest-a"),
            digest("generated:artifact-a"),
            digest("interface:manifest-a"),
            digest("artifact-a"),
        ),
        "the declared vendored entry is valid",
    )
    .with_target_artifact(accept(
        TargetArtifact::new(TargetKind::Library, digest("artifact-a")),
        "the declared vendored target artifact is valid",
    ))];
    let vendor = accept(
        VendorDirectory::new(
            original_source.clone(),
            snapshot.identity(),
            &vendor_entries,
        ),
        "the declared vendored directory is valid",
    );
    let report = admit(
        verify_vendor(&vendor_declaration, &vendor, &verified_vendor_snapshot),
        "a vendored directory of the authenticated snapshot verifies",
    );
    assert_eq!(report.source(), &original_source);
    assert_eq!(report.identity(), snapshot.identity());
    assert_eq!(report.entries(), 1);
    assert_eq!(vendor.source(), &original_source);
    let vendor_record = record_of(&widget, &snapshot, &vendor_declaration);
    let vendor_lockfile = lockfile_of(std::slice::from_ref(&vendor_record));
    let vendor_gate = admit(
        verified_vendor_snapshot.bind_lockfile(&vendor_lockfile, &vendor_declarations),
        "vendor acquisition binds the verified source snapshot before delivery",
    );
    let vendor_admission = admit(
        vendor_gate.admit_acquisition(
            vendor_declaration.index(),
            TargetKind::Library,
            &DeliveredRelease::vendor(&widget, &report),
            &AdvisoryStore::new(),
        ),
        "a final vendor acquisition requires its source-bound verification proof",
    );
    assert_eq!(vendor_admission.source(), vendor_declaration.identity());
    assert_eq!(vendor_admission.snapshot(), snapshot.identity());
    assert_eq!(vendor_admission.target(), TargetKind::Library);
    assert_eq!(
        vendor_admission.route().kind(),
        AcquisitionRouteKind::Vendor
    );
    assert_eq!(vendor_admission.route().mirror(), None);
    assert_eq!(
        vendor_admission.route().source(),
        Some(vendor_declaration.identity())
    );
    assert_eq!(
        vendor_admission.route().snapshot(),
        Some(snapshot.identity())
    );
    let other_universe = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let other_retained = RetainedState::for_source(original_source.clone(), 5)
        .with_content(5, other_universe.content_digest());
    let other_signatures = vec![declared_signature(
        &key("acme-key"),
        other_universe.content_digest(),
    )];
    let other_input = verification_input(
        &vendor_declarations,
        &other_universe,
        &other_signatures,
        std::slice::from_ref(&other_retained),
        &vendor_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified_other_universe = admit_snapshot(&vendor_store, &other_input);
    let refusal = refuse(
        verify_vendor(&vendor_declaration, &vendor, &verified_other_universe),
        "another nominal universe is refused",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::VendorMismatch));
    assert!(matches!(
        refusal.condition(),
        RegistryError::VendorMismatch {
            defect: VendorDefect::SnapshotIdentity,
            ..
        }
    ));
    let changed_entries = [accept(
        VendorEntry::new(
            "acme",
            "widget",
            "1.0.0",
            digest("manifest-a"),
            digest("source:manifest-a"),
            digest("generated:artifact-a"),
            digest("interface:manifest-a"),
            digest("artifact-z"),
        ),
        "the declared vendored entry is valid",
    )
    .with_target_artifact(accept(
        TargetArtifact::new(TargetKind::Library, digest("artifact-z")),
        "the declared vendored target artifact is valid",
    ))];
    let changed_vendor = accept(
        VendorDirectory::new(original_source, snapshot.identity(), &changed_entries),
        "the declared vendored directory is valid",
    );
    let refusal = refuse(
        verify_vendor(
            &vendor_declaration,
            &changed_vendor,
            &verified_vendor_snapshot,
        ),
        "a changed vendored artifact is refused",
    );
    assert_eq!(refusal.code(), Some(RegistryDiagnosticCode::VendorMismatch));
    assert!(matches!(
        refusal.condition(),
        RegistryError::VendorMismatch {
            defect: VendorDefect::ChangedArtifact,
            ..
        }
    ));

    // A mirror is admitted only when it presents the same authenticated snapshot identity.
    let mirror_source = registry_source("acme", "widget");
    let mirror_declaration = accept(
        source_declaration_for(3, "widget_mirror", "widget", mirror_source.clone()),
        "the mirror declaration owns the widget package subject",
    );
    let mirror = accept(
        MirrorBinding::new(
            "mirror.example.invalid",
            mirror_source.clone(),
            snapshot.identity(),
        ),
        "the declared mirror binding is valid",
    );
    let accepted = admit(
        verify_mirror(&mirror_declaration, &mirror, &verified_vendor_snapshot),
        "a mirror of the authenticated snapshot verifies",
    );
    assert_eq!(accepted.identity(), snapshot.identity());
    assert_eq!(accepted.mirror(), "mirror.example.invalid");
    let substituted = accept(
        MirrorBinding::new(
            "substitute.example.invalid",
            mirror_source,
            other_universe.identity(),
        ),
        "the declared mirror binding is valid",
    );
    let refusal = refuse(
        verify_mirror(&mirror_declaration, &substituted, &verified_vendor_snapshot),
        "a mirror substitution is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::MirrorIdentityMismatch)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::MirrorIdentityMismatch {
            defect: MirrorDefect::SnapshotIdentity,
            ..
        }
    ));
}

/// `GNT-27.12-lockfile-evidence-binding` requires one canonical record per declaration and refuses to
/// parse any source before every declaration's evidence is bound.
#[test]
fn gnt_27_12_lockfile_evidence_binds_every_declaration_before_parsing() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let gadget = entry("acme", "gadget", "1.0.0", &acme, "manifest-b", "artifact-b");
    let acme_root = root(
        "acme-root",
        widget.source().clone(),
        acme.clone(),
        scope_of_namespace("acme"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let snapshot = snapshot_of(4, 100, 200, &[widget.clone(), gadget.clone()]);
    let declarations = vec![
        source_declaration(0, "widget", "widget", widget.source().clone()),
        source_declaration(1, "gadget", "gadget", gadget.source().clone()),
    ];
    let widget_record = record_of(&widget, &snapshot, &declarations[0]);
    let gadget_record = record_of(&gadget, &snapshot, &declarations[1]);
    assert_eq!(widget_record.attest(), widget_record.evidence());
    assert_eq!(widget_record.declaration(), 0);
    assert_eq!(widget_record.namespace().spelling(), "acme");
    assert_eq!(widget_record.package().spelling(), "widget");
    assert!(widget_record.features().is_empty());
    assert_eq!(widget_record.targets(), &[TargetKind::Library]);
    assert_eq!(widget_record.target_artifacts(), widget.target_artifacts());
    assert!(widget_record.interfaces().is_empty());
    assert!(widget_record.generator_inputs().is_empty());
    let lockfile = lockfile_of(&[widget_record.clone(), gadget_record.clone()]);
    assert_eq!(lockfile.records().len(), 2);
    assert_eq!(lockfile.record(1).map(LockfileRecord::declaration), Some(1));

    // An admissible path: every declaration's evidence is bound before any source is parsed.
    let ledger = ledger_of(&declarations[0], &snapshot);
    let retained = [RetainedState::for_source(widget.source().clone(), 4)
        .with_content(4, snapshot.content_digest())];
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let verification = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        &retained,
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &verification);
    let gate = admit(
        verified.bind_lockfile(&lockfile, &declarations),
        "every declared evidence is bound",
    );
    assert_eq!(gate.bound(), 2);
    assert_eq!(gate.snapshot(), snapshot.identity());
    assert_eq!(gate.lockfile().digest(), lockfile.digest());
    let admitted = admit(
        gate.admit_acquisition(
            1,
            TargetKind::Library,
            &DeliveredRelease::direct(&gadget, snapshot.identity()),
            &AdvisoryStore::new(),
        ),
        "only a final acquisition admission can pass the complete parse gate",
    );
    assert_eq!(admitted.source(), declarations[1].identity());
    assert_eq!(admitted.route().kind(), AcquisitionRouteKind::Direct);
    assert_eq!(admitted.route().source(), Some(declarations[1].identity()));
    assert_eq!(admitted.route().snapshot(), Some(snapshot.identity()));

    // A declaration with no record is refused, and no source is parsed under it.
    let incomplete = vec![
        declarations[0].clone(),
        declarations[1].clone(),
        source_declaration(2, "extra", "extra", registry_source("acme", "extra")),
    ];
    let refusal = refuse(
        verified.bind_lockfile(&lockfile, &incomplete),
        "a declaration without evidence is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::LockfileEvidenceUnbound)
    );
    assert_eq!(refusal.clause(), "GNT-27.12-lockfile-evidence-binding");
    assert_eq!(refusal.declaration_index(), 2);

    // Tampered evidence is detected by recomputation.
    let tampered = admit(
        LockfileRecord::restore(
            &widget,
            &verified,
            &retained[0],
            &declarations[0],
            LockfileInputs {
                targets: widget
                    .target_artifacts()
                    .iter()
                    .map(TargetArtifact::target)
                    .collect(),
                target_artifacts: widget.target_artifacts().to_vec(),
                ..LockfileInputs::default()
            },
            digest("tampered-evidence"),
        ),
        "the restored record is valid",
    );
    let tampered_lockfile = lockfile_of(std::slice::from_ref(&tampered));
    let refusal = refuse(
        verified.bind_lockfile(&tampered_lockfile, std::slice::from_ref(&declarations[0])),
        "tampered evidence is refused",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::LockfileEvidenceStale)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::TamperedEvidence,
            ..
        }
    ));

    // Evidence bound to another snapshot is stale.
    let other = snapshot_of(5, 100, 200, &[widget.clone(), gadget]);
    let other_ledger = ledger_of(&declarations[0], &other);
    let other_signatures = vec![declared_signature(&acme_key, other.content_digest())];
    let other_verification = verification_input(
        &declarations,
        &other,
        &other_signatures,
        &retained,
        &other_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let other_verified = admit_snapshot(&store, &other_verification);
    let refusal = refuse(
        other_verified.bind_lockfile(&lockfile, &declarations),
        "evidence bound to another snapshot is stale",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::LockfileEvidenceStale)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::ChangedSnapshot,
            ..
        }
    ));

    // Evidence bound to another source identity is stale as well.
    let other_source = accept(
        SourceIdentity::path(widget.source().canonical_text()),
        "the declared identity text is valid",
    );
    let foreign_declaration = source_declaration(0, "widget", "widget", other_source);
    let refusal = refuse(
        verified.bind_lockfile(&lockfile, std::slice::from_ref(&foreign_declaration)),
        "evidence bound to another source is stale",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::LockfileEvidenceStale)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::ChangedSource,
            ..
        }
    ));

    // An empty declaration list has no evidence to bind and no declaration to attribute.
    let none: Vec<SourceDeclaration> = Vec::new();
    let refusal = refuse(
        verified.bind_lockfile(&lockfile, &none),
        "an empty declaration list binds nothing",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AttributionMissing)
    );
    assert!(!refusal.is_bound());
    assert_eq!(refusal.causing_entry(), Some(0));
}

/// `GNT-27.13-trust-failure-attribution` requires every trust and freshness refusal to carry the
/// causing declaration, its index, and its identity before any source is parsed.
#[test]
fn gnt_27_13_every_trust_and_freshness_refusal_names_its_declaration() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let acme_root = root(
        "acme-root",
        registry_source("acme", "widget"),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&acme_root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", widget.source().clone());
    let declarations = vec![declaration.clone()];
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(widget.source().clone(), 1);
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];

    // An admissible path: every admitted entry names the declaration that bound it.
    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &input);
    assert_eq!(verified.authorities().len(), verified.entries().len());
    assert_eq!(
        verified.authority(0).map(EntryAuthority::declaration),
        Some(0)
    );
    assert_eq!(
        verified
            .authority(0)
            .and_then(|authority| authority.grant().scope().package())
            .map(RegistryName::spelling),
        Some("widget")
    );

    // A freshness refusal names the declaration and no causing entry.
    let expired = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(200),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&store, &expired);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SnapshotExpired)
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.declaration_index(), 0);
    assert_eq!(refusal.declaration_identity(), declaration.identity());
    assert_eq!(refusal.attribution().index(), 0);
    assert_eq!(refusal.attribution().identity(), declaration.identity());
    assert_eq!(refusal.causing_entry(), None);
    assert_eq!(
        refusal.clause(),
        "GNT-27.6-expiry-freshness-and-offline-mode"
    );

    let no_retained: [RetainedState; 0] = [];
    let expired_before_retained_state = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        &no_retained,
        &ledger,
        EpochObservation::at(200),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&store, &expired_before_retained_state);
    assert!(matches!(
        refusal.condition(),
        RegistryError::SnapshotExpired { .. }
    ));

    // A publisher refusal names the causing entry and the declaration that bound it.
    let stranger = entry(
        "acme",
        "widget",
        "1.0.0",
        &publisher("stranger", "stranger-key"),
        "manifest-a",
        "artifact-a",
    );
    let stranger_snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&stranger));
    let stranger_signatures = vec![declared_signature(
        &acme_key,
        stranger_snapshot.content_digest(),
    )];
    let advisory_set = AdvisoryStore::new();
    let advisory_proof = AdvisorySetProof::authenticated(
        &stranger_snapshot,
        &advisory_set,
        RootSelectionPolicy::Unspecified,
        acme.clone(),
        &acme_key,
    );
    let stranger_input = VerificationInput::new(
        &declarations,
        &stranger_snapshot,
        &stranger_signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_advisory_proof(advisory_set, advisory_proof);
    let refusal = refuse_snapshot(&store, &stranger_input);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::PublisherUnauthorized)
    );
    assert_eq!(
        refusal.clause(),
        "GNT-27.4-trust-roots-and-delegated-authority"
    );
    assert!(refusal.is_bound());
    assert_eq!(refusal.declaration_index(), 0);
    assert_eq!(refusal.causing_entry(), Some(0));
    assert!(matches!(
        refusal.condition(),
        RegistryError::PublisherUnauthorized {
            defect: AuthorizationDefect::UnverifiedSigner,
            ..
        }
    ));

    // An entry with no bound declaration is refused without a declaration to name.
    let foreign = registry_source("other", "widget");
    let unbound_snapshot = snapshot_of(
        6,
        100,
        200,
        std::slice::from_ref(&widget.clone().with_source(foreign.clone())),
    );
    let unbound_signatures = vec![declared_signature(
        &acme_key,
        unbound_snapshot.content_digest(),
    )];
    let unbound = verification_input(
        &declarations,
        &unbound_snapshot,
        &unbound_signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &unbound);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AttributionMissing)
    );
    assert_eq!(refusal.clause(), "GNT-27.13-trust-failure-attribution");
    assert!(!refusal.is_bound());
    assert_eq!(refusal.causing_entry(), Some(0));
    assert_eq!(refusal.declaration_identity(), &foreign);
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { declared: 1, .. }
    ));

    // An empty declaration list cannot attribute a refusal to any declaration.
    let none: Vec<SourceDeclaration> = Vec::new();
    let empty_input = verification_input(
        &none,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &empty_input);
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::AttributionMissing)
    );
    assert!(!refusal.is_bound());
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing {
            declared: 0,
            attributed: 0,
        }
    ));
    assert!(REGISTRY_CLAUSES.contains(&"GNT-27.13-trust-failure-attribution"));
}

/// `GNT-27.14-registry-non-claims` publishes a closed list of explicit limits and refuses any
/// presentation of one of those limits as a guarantee.
#[test]
fn gnt_27_14_registry_non_claims_remain_limits_not_guarantees() {
    assert!(REGISTRY_CLAUSES.contains(&"GNT-27.14-registry-non-claims"));
    assert_eq!(RegistryNonClaim::ALL, REGISTRY_NON_CLAIM_ORDER);
    assert_eq!(RegistryNonClaim::ALL.len(), REGISTRY_NON_CLAIMS.len());

    for claim in RegistryNonClaim::ALL {
        assert_eq!(
            RegistryNonClaim::from_wire_name(claim.wire_name()),
            Some(claim)
        );
        assert_eq!(claim.as_str(), claim.wire_name());
        assert_eq!(claim.requirement(), "GNT-27.14-registry-non-claims");
        assert!(!claim.statement().is_empty());
    }
    assert_eq!(RegistryNonClaim::from_wire_name("verified-safe-code"), None);

    let accurately_limited = RegistryNonClaim::ALL
        .into_iter()
        .map(|claim| RegistryNonClaimAssertion::new(claim, false))
        .collect::<Vec<_>>();
    assert_eq!(check_registry_non_claims(&accurately_limited), Ok(()));

    let overstated = [RegistryNonClaimAssertion::new(
        RegistryNonClaim::OfflineCurrentness,
        true,
    )];
    let error = match check_registry_non_claims(&overstated) {
        Ok(()) => panic!("an offline observation was accepted as a currentness guarantee"),
        Err(error) => error,
    };
    assert_eq!(error.requirement_anchor(), "GNT-27.14-registry-non-claims");
    assert_eq!(error.claim(), RegistryNonClaim::OfflineCurrentness);
    assert!(
        RegistryNonClaim::TransportUniverseEquivalence
            .statement()
            .contains("No nominal-universe equivalence")
    );
}

/// `GNT-27.4-trust-roots-and-delegated-authority` admits a complete multi-hop chain without
/// depending on declaration order, binds every hop to the complete publisher identity, and
/// requires an explicit policy when a source has several roots.
#[test]
fn gnt_27_4_topological_delegation_and_root_selection_are_explicit() {
    let source = registry_source("acme", "widget");
    let root_key = key("root-key");
    let middle_key = key("middle-key");
    let leaf_key = key("leaf-key");
    let root_publisher = publisher("acme", "root-key");
    let middle = publisher("acme-release", "middle-key");
    let leaf = publisher("acme-build", "leaf-key");
    let primary_root = root(
        "acme-root",
        source.clone(),
        root_publisher.clone(),
        scope_of_namespace("acme"),
    );
    let parent = delegation(
        source.clone(),
        root_publisher.clone(),
        middle.clone(),
        scope_of_namespace("acme"),
        1,
        &root_key,
    );
    let child = delegation(
        source.clone(),
        middle.clone(),
        leaf.clone(),
        scope_of_package("acme", "widget"),
        2,
        &middle_key,
    );
    let store = store_of(
        std::slice::from_ref(&primary_root),
        &[root_key.clone(), middle_key.clone(), leaf_key.clone()],
        &[child, parent],
    );
    let delegated = entry("acme", "widget", "1.0.0", &leaf, "manifest-a", "artifact-a");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let grant = admit(
        store.authorize(&declaration, &delegated, 2),
        "a complete delegation chain is admitted independently of input order",
    );
    assert!(grant.is_delegated());
    assert_eq!(grant.authorized_by(), leaf.key());
    assert_eq!(store.delegations().len(), 2);
    assert_eq!(store.delegations()[1].ancestors().len(), 2);

    let impersonating_middle = publisher("other-publisher", "middle-key");
    let identity_mismatch = delegation(
        source.clone(),
        impersonating_middle,
        leaf.clone(),
        scope_of_package("acme", "widget"),
        2,
        &middle_key,
    );
    let error = reject(
        TrustStore::new(
            std::slice::from_ref(&primary_root),
            &[root_key.clone(), middle_key.clone(), leaf_key.clone()],
            &[
                store.delegations()[0].delegation().clone(),
                identity_mismatch,
            ],
        ),
        "a key match without the delegated publisher identity is not a chain hop",
    );
    assert!(matches!(
        error,
        RegistryError::DelegationChainIncomplete { .. }
    ));
    assert_eq!(
        error.trust_failure_reason(),
        TrustFailureReason::IncompleteDelegationChain
    );
    assert_eq!(
        error.clause(),
        TrustFailureReason::IncompleteDelegationChain.anchor()
    );

    let alternate_key = key("alternate-key");
    let alternate = publisher("acme-alternate", "alternate-key");
    let alternate_root = root(
        "acme-alternate-root",
        source.clone(),
        alternate,
        scope_of_package("acme", "widget"),
    );
    let multi_root_store = store_of(
        &[primary_root.clone(), alternate_root],
        &[root_key.clone(), alternate_key],
        &[],
    );
    let rooted = entry(
        "acme",
        "widget",
        "2.0.0",
        &root_publisher,
        "manifest-b",
        "artifact-b",
    );
    let refusal = refuse(
        multi_root_store.authorize(&declaration, &rooted, 4),
        "direct authority selection refuses an undeclared multi-root disjunction",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::TrustDecisionDisjunction { .. }
    ));
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&rooted));
    let declarations = vec![declaration.clone()];
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source, 1);
    let signatures = vec![declared_signature(&root_key, snapshot.content_digest())];
    let unspecified = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&multi_root_store, &unspecified);
    assert!(matches!(
        refusal.condition(),
        RegistryError::TrustDecisionDisjunction { .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::UndeclaredTrustDisjunction
    );
    assert_eq!(
        refusal.requirement_anchor(),
        "GNT-27.4-trust-roots-and-delegated-authority"
    );

    let selected_policy = RootSelectionPolicy::selected(accept(
        RootId::new("acme-root"),
        "the declared root identity is valid",
    ));
    let selected = verification_input_with_advisories_and_policy(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
        AdvisoryStore::new(),
        selected_policy,
    );
    assert_eq!(
        admit_snapshot(&multi_root_store, &selected)
            .authority(0)
            .map(|authority| authority.grant().root().as_str()),
        Some("acme-root")
    );
}

/// `GNT-27.4-trust-roots-and-delegated-authority` requires every public authority entry point
/// to refuse a rooted source that differs from the declaration before considering authority.
#[test]
fn gnt_27_4_authority_apis_require_the_declared_source() {
    let declaration_source = registry_source("declared", "widget");
    let rooted_source = registry_source("rooted", "widget");
    let root_key = key("root-key");
    let publisher = publisher("acme", "root-key");
    let scope = scope_of_package("acme", "widget");
    let store = store_of(
        std::slice::from_ref(&root(
            "rooted-root",
            rooted_source.clone(),
            publisher.clone(),
            scope.clone(),
        )),
        std::slice::from_ref(&root_key),
        &[],
    );
    let declaration = source_declaration(0, "widget", "widget", declaration_source.clone());
    let entry = entry_for_source(
        rooted_source.clone(),
        "acme",
        "widget",
        "1.0.0",
        &publisher,
        "manifest-a",
        "artifact-a",
        digest("source:manifest-a"),
    );
    let selected = RootSelectionPolicy::selected(accept(
        RootId::new("rooted-root"),
        "the selected root identity is valid",
    ));

    for refusal in [
        refuse(
            store.authorize(&declaration, &entry, 1),
            "entry authority rejects a source other than its declaration",
        ),
        refuse(
            store.authorize_with_root_selection(&declaration, &entry, 1, &selected),
            "selected entry authority rejects a source other than its declaration",
        ),
        refuse(
            store.authorize_coordinates(
                &declaration,
                &rooted_source,
                &publisher,
                entry.namespace(),
                entry.package(),
                1,
            ),
            "coordinate authority rejects a source other than its declaration",
        ),
        refuse(
            store.authorize_coordinates_with_root_selection(
                &declaration,
                &rooted_source,
                &publisher,
                entry.namespace(),
                entry.package(),
                1,
                &selected,
            ),
            "selected coordinate authority rejects a source other than its declaration",
        ),
    ] {
        assert_eq!(
            refusal.code(),
            Some(RegistryDiagnosticCode::SourceNotDeclared)
        );
        assert_eq!(refusal.declaration_identity(), &declaration_source);
        assert_eq!(refusal.declaration_index(), declaration.index());
        assert!(matches!(
            refusal.condition(),
            RegistryError::SourceNotDeclared { requested } if requested == &rooted_source
        ));
    }
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` retains only authenticated,
/// source-scoped lifecycle facts, while failed rotation or compromise admission leaves no state
/// that a later verification could consume.
#[test]
fn gnt_27_5_lifecycle_admission_is_atomic_and_retained() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);
    let one_sided = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        DeclaredSignature::declared(next.key().clone(), digest("forged-rotation")),
    );
    let refusal = refuse(
        store.rotate(&declaration, one_sided, std::slice::from_ref(&next)),
        "a failed rotation retains neither successor material nor lifecycle evidence",
    );
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::InvalidRotationEvidence
    );
    assert!(store.rotations().is_empty());
    assert_eq!(store.material(next.key()), None);

    let evidence = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        declared_signature(&next, payload),
    );
    admit(
        store.rotate(&declaration, evidence, std::slice::from_ref(&next)),
        "dual-signed rotation evidence is admitted atomically",
    );
    let compromised_payload = Compromise::payload(&source, &scope, &acme, old.key(), 5, 5);
    let forged_compromise = accept(
        Compromise::authenticated(
            source.clone(),
            scope.clone(),
            acme.clone(),
            old.key().clone(),
            5,
            5,
            DeclaredSignature::declared(old.key().clone(), digest("forged-compromise")),
        ),
        "the malformed compromise envelope itself is valid input",
    );
    let refusal = refuse(
        store.compromise(&declaration, forged_compromise),
        "an unauthenticated compromise does not mutate lifecycle state",
    );
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::UnauthorizedSigningAuthority
    );
    assert!(store.compromises().is_empty());
    assert_ne!(compromised_payload, digest("forged-compromise"));

    let upgraded = entry(
        "acme",
        "widget",
        "2.0.0",
        &publisher("acme", "next-key"),
        "manifest-b",
        "artifact-b",
    );
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&upgraded));
    let ledger = ledger_of(&declaration, &snapshot);
    let signatures = vec![declared_signature(&next, snapshot.content_digest())];
    let missing_facts = RetainedState::for_source(source.clone(), 1);
    let input = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&missing_facts),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &input);
    assert!(matches!(
        refusal.condition(),
        RegistryError::RetainedLifecycleFactsMissing { .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::RetainedLifecycleFactsMissing
    );

    let retained = missing_facts
        .with_rotation_fact(store.rotations()[0].evidence_digest())
        .with_lifecycle_root_policy(RootSelectionPolicy::Unspecified);
    let input = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &input);
    let derived = store.retained_state(&verified);
    assert_eq!(derived.source(), &source);
    assert_eq!(derived.expiry_epoch(), Some(snapshot.expiry_epoch()));
    assert_eq!(
        derived.rotation_facts(),
        &[store.rotations()[0].evidence_digest()]
    );
    assert!(derived.revocation_facts().is_empty());
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` compares key overlap with the
/// snapshot epoch, not the unrelated monotone snapshot sequence.
#[test]
fn gnt_27_5_rotation_overlap_uses_declared_epoch() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 100, 200),
        "the declared epoch overlap is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);
    let evidence = accept(
        RotationEvidence::authenticated(
            accept(
                RotationContext::new(
                    source.clone(),
                    scope,
                    acme.clone(),
                    old.key().clone(),
                    next.key().clone(),
                    timing,
                ),
                "the declared epoch overlap is valid",
            ),
            RotationSignatures::new(
                declared_signature(&old, payload),
                declared_signature(&next, payload),
            ),
        ),
        "the declared dual-signed epoch overlap is valid",
    );
    admit(
        store.rotate(&declaration, evidence.clone(), std::slice::from_ref(&next)),
        "the declared epoch overlap rotates the key",
    );

    let retired = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let during = snapshot_of(10, 150, 250, std::slice::from_ref(&retired));
    let during_ledger = ledger_of(&declaration, &during);
    let retained = RetainedState::for_source(source, 1)
        .with_rotation_fact(evidence.evidence_digest())
        .with_lifecycle_root_policy(RootSelectionPolicy::Unspecified);
    let during_signatures = vec![declared_signature(&old, during.content_digest())];
    let during_input = verification_input(
        std::slice::from_ref(&declaration),
        &during,
        &during_signatures,
        std::slice::from_ref(&retained),
        &during_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    admit_snapshot(&store, &during_input);

    let after = snapshot_of(11, 200, 250, std::slice::from_ref(&retired));
    let after_ledger = ledger_of(&declaration, &after);
    let after_signatures = vec![declared_signature(&old, after.content_digest())];
    let after_input = verification_input(
        std::slice::from_ref(&declaration),
        &after,
        &after_signatures,
        std::slice::from_ref(&retained),
        &after_ledger,
        EpochObservation::at(200),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &after_input);
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeySuperseded { .. }
    ));
    assert_eq!(
        refusal.requirement_anchor(),
        "GNT-27.5-signing-key-rotation-and-compromise-recovery"
    );
}

/// `GNT-27.12-lockfile-evidence-binding` binds complete dependency identities, target-qualified
/// artifacts, and every lockfile record before an acquisition witness can exist.
#[test]
fn gnt_27_12_whole_lockfile_closure_and_acquisition_admission() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let source = registry_source("acme", "widget");
    let dependency_source = registry_source("helper", "helper");
    let primary_root = root(
        "acme-root",
        source.clone(),
        acme.clone(),
        scope_of_namespace("acme"),
    );
    let dependency_root = root(
        "helper-root",
        dependency_source.clone(),
        acme.clone(),
        scope_of_namespace("helper"),
    );
    let store = store_of(
        &[primary_root, dependency_root],
        std::slice::from_ref(&acme_key),
        &[],
    );
    let dependency = entry(
        "helper",
        "helper",
        "1.0.0",
        &acme,
        "helper-manifest",
        "helper-artifact",
    );
    let dependency_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&dependency));
    let declared_dependency = accept(
        SnapshotDependency::new(
            "helper",
            dependency_source.clone(),
            "helper",
            "helper",
            "1.0.0",
            TargetKind::Library,
            dependency_snapshot.identity(),
        ),
        "the declared dependency identity is valid",
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a")
        .with_dependency(declared_dependency);
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let dependency_declaration = source_declaration(1, "helper", "helper", dependency_source);
    let dependency_record = record_of(&dependency, &dependency_snapshot, &dependency_declaration);
    let locked_dependency = accept(
        LockedDependency::new(
            "helper",
            dependency.source().clone(),
            "helper",
            "helper",
            "1.0.0",
            TargetKind::Library,
            dependency_snapshot.identity(),
        ),
        "the locked dependency identity is valid",
    );
    let widget_record = record_with_inputs(
        &widget,
        &snapshot,
        &declaration,
        LockfileInputs {
            targets: widget
                .target_artifacts()
                .iter()
                .map(TargetArtifact::target)
                .collect(),
            target_artifacts: widget.target_artifacts().to_vec(),
            dependencies: vec![locked_dependency],
            ..LockfileInputs::default()
        },
    );
    assert_eq!(widget_record.dependencies().len(), 1);
    assert_eq!(widget_record.target_artifacts(), widget.target_artifacts());
    let (history_trust, history_retained, history_signatures) =
        authenticated_fixture(&declaration, &snapshot);
    let empty = PublicationLedger::new();
    let history_input = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &history_signatures,
        std::slice::from_ref(&history_retained),
        &empty,
        EpochObservation::at(snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let history_verified = admit_snapshot(&history_trust, &history_input);
    assert!(matches!(
        refuse(
            LockfileRecord::historical(
                &widget,
                &history_verified,
                &history_retained,
                &declaration,
                LockfileInputs {
                    targets: widget
                        .target_artifacts()
                        .iter()
                        .map(TargetArtifact::target)
                        .collect(),
                    target_artifacts: widget.target_artifacts().to_vec(),
                    ..LockfileInputs::default()
                },
            ),
            "historical evidence cannot omit an authenticated dependency",
        )
        .condition(),
        RegistryError::LockfileDeclarationInvalid {
            field: "lockfile record dependencies",
            ..
        }
    ));

    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source, 1);
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let input = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &input);
    let dependency_ledger = ledger_of(&dependency_declaration, &dependency_snapshot);
    let dependency_retained = RetainedState::for_source(dependency.source().clone(), 1);
    let dependency_signatures = vec![declared_signature(
        &acme_key,
        dependency_snapshot.content_digest(),
    )];
    let dependency_input = verification_input(
        std::slice::from_ref(&dependency_declaration),
        &dependency_snapshot,
        &dependency_signatures,
        std::slice::from_ref(&dependency_retained),
        &dependency_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let dependency_verified = admit_snapshot(&store, &dependency_input);
    let declarations = [declaration.clone(), dependency_declaration.clone()];
    let closed_lockfile = lockfile_of(&[widget_record.clone(), dependency_record.clone()]);
    let gate = admit(
        verified.bind_lockfile_closure(&closed_lockfile, &declarations, &[&dependency_verified]),
        "a multi-source lockfile closure is bound before acquisition",
    );
    let admitted = admit(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::direct(&widget, snapshot.identity()),
            &AdvisoryStore::new(),
        ),
        "the fully verified delivery produces one acquisition witness",
    );
    assert_eq!(admitted.source(), declaration.identity());
    assert_eq!(admitted.snapshot(), snapshot.identity());
    assert_eq!(admitted.declaration(), 0);
    assert_eq!(admitted.publication(), PublicationState::Published);
    assert_eq!(admitted.target(), TargetKind::Library);
    assert_eq!(admitted.artifact(), widget.artifact());
    assert_eq!(admitted.route().kind(), AcquisitionRouteKind::Direct);
    assert_eq!(admitted.route().mirror(), None);
    assert_eq!(admitted.route().source(), Some(declaration.identity()));
    assert_eq!(admitted.route().snapshot(), Some(snapshot.identity()));

    let mirror = accept(
        MirrorBinding::new(
            "acquisition.example.invalid",
            widget.source().clone(),
            snapshot.identity(),
        ),
        "the acquisition mirror binding is valid",
    );
    let mirror_proof = admit(
        verify_mirror(&declaration, &mirror, &verified),
        "the acquisition mirror is verified against the lockfile source snapshot",
    );
    let mirrored = admit(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::mirror(&widget, &mirror_proof),
            &AdvisoryStore::new(),
        ),
        "a final mirror acquisition requires its source-bound verification proof",
    );
    assert_eq!(mirrored.snapshot(), snapshot.identity());
    assert_eq!(mirrored.route().kind(), AcquisitionRouteKind::Mirror);
    assert_eq!(
        mirrored.route().mirror(),
        Some("acquisition.example.invalid")
    );
    assert_eq!(mirrored.route().source(), Some(declaration.identity()));
    assert_eq!(mirrored.route().snapshot(), Some(snapshot.identity()));

    let dependency_mirror = accept(
        MirrorBinding::new(
            "helper.example.invalid",
            dependency.source().clone(),
            dependency_snapshot.identity(),
        ),
        "the dependency mirror binding is valid",
    );
    let dependency_mirror_proof = admit(
        verify_mirror(
            &dependency_declaration,
            &dependency_mirror,
            &dependency_verified,
        ),
        "the dependency mirror is verified against its own source snapshot",
    );
    let refusal = refuse(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::mirror(&widget, &dependency_mirror_proof),
            &AdvisoryStore::new(),
        ),
        "a mirror proof for another source cannot admit this acquisition",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::MirrorIdentityMismatch {
            defect: MirrorDefect::SnapshotIdentity,
            ..
        }
    ));

    let refusal = refuse(
        gate.admit_acquisition(
            0,
            TargetKind::Binary,
            &DeliveredRelease::direct(&widget, snapshot.identity()),
            &AdvisoryStore::new(),
        ),
        "an undeclared target cannot enter final acquisition",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::ChangedDelivery,
            ..
        }
    ));

    let partial_lockfile = lockfile_of(std::slice::from_ref(&widget_record));
    let refusal = refuse(
        verified.bind_lockfile_closure(&partial_lockfile, &declarations, &[&dependency_verified]),
        "a missing transitive lockfile record prevents partial acquisition",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::MissingDependency,
            ..
        }
    ));
    assert_eq!(
        refusal.causing_dependency(),
        widget_record.dependencies().first(),
        "the refusal retains the exact parent-to-dependency edge that was absent"
    );

    let refusal = refuse(
        verified.bind_lockfile_closure(&closed_lockfile, &declarations, &[]),
        "an unverified dependency snapshot is attributed to the parent edge that requires it",
    );
    assert_eq!(refusal.declaration_index(), declaration.index());
    assert_eq!(
        refusal.causing_dependency(),
        widget_record.dependencies().first()
    );

    let changed_targets = vec![accept(
        TargetArtifact::new(TargetKind::Binary, digest("binary-artifact")),
        "the changed target artifact is valid",
    )];
    let changed_delivery = DeliveredRelease::direct(&widget, snapshot.identity())
        .with_target_artifacts(changed_targets);
    let refusal = refuse(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &changed_delivery,
            &AdvisoryStore::new(),
        ),
        "a target-artifact substitution prevents acquisition",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::ChangedDelivery,
            ..
        }
    ));

    let changed_dependencies = widget.clone().with_dependency(accept(
        SnapshotDependency::new(
            "unexpected",
            dependency.source().clone(),
            "helper",
            "helper",
            "1.0.0",
            TargetKind::Library,
            dependency_snapshot.identity(),
        ),
        "the substituted delivery dependency coordinate is valid",
    ));
    let refusal = refuse(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::direct(&changed_dependencies, snapshot.identity()),
            &AdvisoryStore::new(),
        ),
        "a delivered dependency-coordinate substitution prevents acquisition",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileEvidenceStale {
            defect: EvidenceDefect::ChangedDelivery,
            ..
        }
    ));

    let advisory = accept(
        SecurityAdvisory::new(
            "GNT-27.10-build-boundary",
            accept(
                AdvisoryScope::new(
                    widget.source().clone(),
                    "acme",
                    "widget",
                    "1.0.0",
                    widget.target_artifacts(),
                ),
                "the build-boundary advisory scope is valid",
            ),
            Severity::RefuseNewBuild,
        ),
        "the build-boundary advisory is valid",
    );
    let mut advisories = AdvisoryStore::new();
    admit(
        advisories.admit(
            &declaration,
            advisory.clone(),
            declared_signature(&acme_key, advisory.digest()),
            acme,
            &store,
            snapshot.sequence(),
        ),
        "the authenticated build-boundary advisory is admitted",
    );
    let refusal = refuse(
        gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::direct(&widget, snapshot.identity()),
            &advisories,
        ),
        "a new-build advisory blocks final acquisition without substituting bytes",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AdvisoryRefusesBuild {
            severity: Severity::RefuseNewBuild,
            ..
        }
    ));

    let refusal = refuse(
        gate.admit_acquisition(0, TargetKind::Library, &changed_delivery, &advisories),
        "a new-build advisory is decided before delivery evidence is read",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AdvisoryRefusesBuild {
            severity: Severity::RefuseNewBuild,
            ..
        }
    ));
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` rejects a signer that later
/// becomes compromised even when the presented snapshot predates the compromise, in both
/// online and explicitly pinned offline verification.
#[test]
fn gnt_27_5_later_compromise_rejects_older_online_and_offline_snapshots() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(
        std::slice::from_ref(&root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let declarations = vec![declaration.clone()];
    let ledger = ledger_of(&declaration, &snapshot);
    let retained =
        RetainedState::for_source(source.clone(), 5).with_content(5, snapshot.content_digest());
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let before_compromise = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &before_compromise);
    let offline_witness = accept(
        verified.offline_witness(&source, 199),
        "the prior verified snapshot mints its offline witness",
    );
    drop(verified);

    let compromise_payload = Compromise::payload(&source, &scope, &acme, acme_key.key(), 10, 150);
    let compromise = accept(
        Compromise::authenticated(
            source.clone(),
            scope,
            acme.clone(),
            acme_key.key().clone(),
            10,
            150,
            declared_signature(&acme_key, compromise_payload),
        ),
        "the declared compromise evidence is valid",
    );
    admit(
        store.compromise(&declaration, compromise),
        "the later compromise is retained",
    );

    let online = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&store, &online);
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeyCompromised { sequence: 10, .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::CompromisedSigningAuthority
    );
    assert_eq!(
        refusal.requirement_anchor(),
        "GNT-27.5-signing-key-rotation-and-compromise-recovery"
    );

    let offline = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::offline(offline_witness),
    );
    let refusal = refuse_snapshot(&store, &offline);
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeyCompromised { sequence: 10, .. }
    ));
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` activates a successor at its
/// declared effective epoch, not merely at its effective sequence.
#[test]
fn gnt_27_5_successor_waits_for_its_effective_epoch() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 100, 200),
        "the declared effective epoch is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);
    let evidence = accept(
        RotationEvidence::authenticated(
            accept(
                RotationContext::new(
                    source.clone(),
                    scope,
                    acme.clone(),
                    old.key().clone(),
                    next.key().clone(),
                    timing,
                ),
                "the declared rotation context is valid",
            ),
            RotationSignatures::new(
                declared_signature(&old, payload),
                declared_signature(&next, payload),
            ),
        ),
        "the declared rotation evidence is valid",
    );
    admit(
        store.rotate(&declaration, evidence.clone(), std::slice::from_ref(&next)),
        "the successor rotation is admitted",
    );
    let successor = entry(
        "acme",
        "widget",
        "2.0.0",
        &publisher("acme", "next-key"),
        "manifest-b",
        "artifact-b",
    );
    let retained = RetainedState::for_source(source, 1)
        .with_rotation_fact(evidence.evidence_digest())
        .with_lifecycle_root_policy(RootSelectionPolicy::Unspecified);

    let before = snapshot_of(10, 99, 200, std::slice::from_ref(&successor));
    let before_ledger = ledger_of(&declaration, &before);
    let before_signatures = vec![declared_signature(&next, before.content_digest())];
    let before_input = verification_input(
        std::slice::from_ref(&declaration),
        &before,
        &before_signatures,
        std::slice::from_ref(&retained),
        &before_ledger,
        EpochObservation::at(99),
        FreshnessMode::online(),
    );
    assert_eq!(
        refuse_snapshot(&store, &before_input).reason(),
        TrustFailureReason::UnauthorizedSigningAuthority
    );

    let effective = snapshot_of(11, 100, 200, std::slice::from_ref(&successor));
    let effective_ledger = ledger_of(&declaration, &effective);
    let effective_signatures = vec![declared_signature(&next, effective.content_digest())];
    let effective_input = verification_input(
        std::slice::from_ref(&declaration),
        &effective,
        &effective_signatures,
        std::slice::from_ref(&retained),
        &effective_ledger,
        EpochObservation::at(100),
        FreshnessMode::online(),
    );
    admit_snapshot(&store, &effective_input);
}

/// `GNT-27.13-trust-failure-attribution` exposes every declared freshness and delegation
/// failure reason with the anchor that owns it.
#[test]
fn gnt_27_13_failure_reasons_are_reachable_and_anchored() {
    let source = registry_source("acme", "widget");
    let root_key = key("root-key");
    let delegate_key = key("delegate-key");
    let root_publisher = publisher("acme", "root-key");
    let delegate = publisher("acme-release", "delegate-key");
    let scope = scope_of_package("acme", "widget");
    let trust_root = root(
        "acme-root",
        source.clone(),
        root_publisher.clone(),
        scope.clone(),
    );
    let timing = accept(
        DelegationTiming::new(100, 200, 10),
        "the delayed delegation timing is valid",
    );
    let delegation_payload = Delegation::payload(
        &source,
        &root_publisher,
        &delegate,
        &scope,
        timing.not_before_epoch(),
        timing.expiry_epoch(),
        timing.effective_sequence(),
    );
    let delayed = accept(
        Delegation::authenticated(
            source.clone(),
            root_publisher,
            delegate.clone(),
            scope,
            timing,
            declared_signature(&root_key, delegation_payload),
        ),
        "the delayed delegation is valid",
    );
    let store = store_of(
        &[trust_root],
        &[root_key.clone(), delegate_key.clone()],
        &[delayed],
    );
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let delegated = entry(
        "acme",
        "widget",
        "1.0.0",
        &delegate,
        "manifest-a",
        "artifact-a",
    );
    let timed = refuse(
        store.authorize(&declaration, &delegated, 9),
        "a delegation is unavailable before its declared coordinates",
    );
    assert_eq!(
        timed.reason(),
        TrustFailureReason::DelegationNotCurrentlyValid
    );
    assert_eq!(timed.requirement_anchor(), timed.reason().anchor());

    let root_only = root(
        "freshness-root",
        source.clone(),
        publisher("acme", "root-key"),
        scope_of_package("acme", "widget"),
    );
    let freshness_store = store_of(
        std::slice::from_ref(&root_only),
        std::slice::from_ref(&root_key),
        &[],
    );
    let root_signed = entry(
        "acme",
        "widget",
        "1.0.0",
        &publisher("acme", "root-key"),
        "manifest-root",
        "artifact-root",
    );
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&root_signed));
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source, 1);
    let signatures = vec![declared_signature(&root_key, snapshot.content_digest())];
    let missing = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::missing(),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&freshness_store, &missing);
    assert_eq!(refusal.reason(), TrustFailureReason::MissingObservedInstant);
    assert_eq!(refusal.requirement_anchor(), refusal.reason().anchor());

    let unavailable = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::offline_unavailable(),
    )
    .with_snapshot_declaration(declaration.index());
    let refusal = refuse_snapshot(&freshness_store, &unavailable);
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::UnavailablePinnedSnapshot
    );
    assert_eq!(refusal.requirement_anchor(), refusal.reason().anchor());
}

/// `GNT-27.2`, `GNT-27.4`, and `GNT-27.11` require kind-qualified aliases, explicit root
/// selection for lifecycle authority consumers, and namespace-qualified vendor entries.
#[test]
fn gnt_27_registry_aliases_roots_and_vendors_are_coordinate_exact() {
    let package = accept(
        ExternalName::new(RegistryNameKind::Package, "widget"),
        "the external package name is valid",
    );
    let namespace = accept(
        ExternalName::new(RegistryNameKind::Namespace, "widget"),
        "the external namespace name is valid",
    );
    let mut forward = ExternalAliasMap::new();
    let package_alias = accept(
        forward.insert(package.clone()),
        "the package alias is valid",
    );
    let namespace_alias = accept(
        forward.insert(namespace.clone()),
        "the namespace alias is valid",
    );
    let mut reverse = ExternalAliasMap::new();
    accept(
        reverse.insert(namespace.clone()),
        "the namespace alias is valid",
    );
    accept(
        reverse.insert(package.clone()),
        "the package alias is valid",
    );
    assert_ne!(package_alias, namespace_alias);
    assert_eq!(forward.alias(&package), reverse.alias(&package));
    assert_eq!(forward.alias(&namespace), reverse.alias(&namespace));

    let source = registry_source("acme", "widget");
    let root_key = key("root-key");
    let root_publisher = publisher("acme", "root-key");
    let scope = scope_of_package("acme", "widget");
    let first = root(
        "first-root",
        source.clone(),
        root_publisher.clone(),
        scope.clone(),
    );
    let second = root("second-root", source.clone(), root_publisher.clone(), scope);
    let store = store_of(&[first, second], std::slice::from_ref(&root_key), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let entry = entry(
        "acme",
        "widget",
        "1.0.0",
        &root_publisher,
        "manifest-a",
        "artifact-a",
    );
    assert_eq!(
        refuse(
            store.authorize(&declaration, &entry, 4),
            "multiple roots require an explicit policy for direct authority",
        )
        .reason(),
        TrustFailureReason::UndeclaredTrustDisjunction
    );
    let selected = RootSelectionPolicy::selected(accept(
        RootId::new("first-root"),
        "the selected root identity is valid",
    ));
    assert_eq!(
        admit(
            store.authorize_with_root_selection(&declaration, &entry, 4, &selected),
            "selected-root direct authority is admitted",
        )
        .root()
        .as_str(),
        "first-root"
    );

    let vendor_snapshot =
        gantry::ir::registry::SnapshotIdentity::from_digest(digest("vendor-snapshot"));
    let vendor = accept(
        VendorDirectory::new(
            source,
            vendor_snapshot,
            &[
                accept(
                    VendorEntry::new(
                        "beta",
                        "widget",
                        "1.0.0",
                        digest("beta-manifest"),
                        digest("beta-source"),
                        digest("beta-generated"),
                        digest("beta-interface"),
                        digest("beta-artifact"),
                    ),
                    "the beta vendor entry is valid",
                ),
                accept(
                    VendorEntry::new(
                        "acme",
                        "widget",
                        "1.0.0",
                        digest("acme-manifest"),
                        digest("acme-source"),
                        digest("acme-generated"),
                        digest("acme-interface"),
                        digest("acme-artifact"),
                    ),
                    "the acme vendor entry is valid",
                ),
            ],
        ),
        "same package and version remain distinct across vendor namespaces",
    );
    assert_eq!(vendor.entries().len(), 2);
    assert_eq!(vendor.entries()[0].namespace().spelling(), "acme");
    assert_eq!(vendor.entries()[1].namespace().spelling(), "beta");
}

/// `GNT-27.13-trust-failure-attribution` keeps the closed failure-reason vocabulary exhaustive
/// and maps each reason to the clause that owns its refused condition.
#[test]
fn gnt_27_13_failure_reason_vocabulary_has_exact_anchors() {
    let expected = [
        (
            TrustFailureReason::AbsentTrustRoot,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::UnauthorizedSigningAuthority,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::InsufficientDelegationScope,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::IncompleteDelegationChain,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::DelegationNotCurrentlyValid,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::ExpiredMetadataSnapshot,
            "GNT-27.6-expiry-freshness-and-offline-mode",
        ),
        (
            TrustFailureReason::MissingObservedInstant,
            "GNT-27.6-expiry-freshness-and-offline-mode",
        ),
        (
            TrustFailureReason::StaleSnapshot,
            "GNT-27.6-expiry-freshness-and-offline-mode",
        ),
        (
            TrustFailureReason::RolledBackSequence,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::EquivocatedSequence,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::DetectedFreeze,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::NoncanonicalPublicationName,
            "GNT-27.2-canonical-publication-names-and-external-name-mapping",
        ),
        (
            TrustFailureReason::MalformedPublicationName,
            "GNT-27.2-canonical-publication-names-and-external-name-mapping",
        ),
        (
            TrustFailureReason::CanonicalNameCollision,
            "GNT-27.2-canonical-publication-names-and-external-name-mapping",
        ),
        (
            TrustFailureReason::PublicationImmutabilityViolation,
            "GNT-27.8-publication-immutability",
        ),
        (TrustFailureReason::YankedRelease, "GNT-27.9-yank-semantics"),
        (
            TrustFailureReason::RevokedArtifact,
            "GNT-27.10-security-revocation-and-durable-execution-policy",
        ),
        (
            TrustFailureReason::UnverifiedSourceRevision,
            "GNT-27.11-vcs-path-and-vendor-source-verification",
        ),
        (
            TrustFailureReason::UnverifiedSourceTreeIdentity,
            "GNT-27.11-vcs-path-and-vendor-source-verification",
        ),
        (
            TrustFailureReason::UnverifiableLockfileRecord,
            "GNT-27.12-lockfile-evidence-binding",
        ),
        (
            TrustFailureReason::InvalidLockfileRecord,
            "GNT-27.12-lockfile-evidence-binding",
        ),
        (
            TrustFailureReason::UnavailablePinnedSnapshot,
            "GNT-27.6-expiry-freshness-and-offline-mode",
        ),
        (
            TrustFailureReason::UndeclaredTrustDisjunction,
            "GNT-27.4-trust-roots-and-delegated-authority",
        ),
        (
            TrustFailureReason::MalformedSourceIdentity,
            "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary",
        ),
        (
            TrustFailureReason::SourceKindFallback,
            "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary",
        ),
        (
            TrustFailureReason::UndeclaredSourceIdentity,
            "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary",
        ),
        (
            TrustFailureReason::ConfigurationAliasAsIdentity,
            "GNT-27.1-immutable-source-identity-and-source-kind-vocabulary",
        ),
        (
            TrustFailureReason::InvalidDeclaration,
            "GNT-27.0-authenticated-package-acquisition-and-registry-trust",
        ),
        (
            TrustFailureReason::InvalidAcquisitionDeclaration,
            "GNT-27.11-vcs-path-and-vendor-source-verification",
        ),
        (
            TrustFailureReason::InvalidSecurityAdvisory,
            "GNT-27.10-security-revocation-and-durable-execution-policy",
        ),
        (
            TrustFailureReason::UnsupportedSnapshotVersion,
            "GNT-27.3-authenticated-metadata-snapshot-and-client-verification",
        ),
        (
            TrustFailureReason::InvalidSnapshotEntry,
            "GNT-27.3-authenticated-metadata-snapshot-and-client-verification",
        ),
        (
            TrustFailureReason::InconsistentSnapshotEpoch,
            "GNT-27.6-expiry-freshness-and-offline-mode",
        ),
        (
            TrustFailureReason::CompromisedSigningAuthority,
            "GNT-27.5-signing-key-rotation-and-compromise-recovery",
        ),
        (
            TrustFailureReason::SupersededSigningAuthority,
            "GNT-27.5-signing-key-rotation-and-compromise-recovery",
        ),
        (
            TrustFailureReason::InvalidRotationEvidence,
            "GNT-27.5-signing-key-rotation-and-compromise-recovery",
        ),
        (
            TrustFailureReason::RetainedSnapshotContentMissing,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::RetainedStateAmbiguous,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::RetainedLifecycleFactsMissing,
            "GNT-27.7-rollback-and-freeze-resistance",
        ),
        (
            TrustFailureReason::ArtifactSubstitutionRefused,
            "GNT-27.10-security-revocation-and-durable-execution-policy",
        ),
        (
            TrustFailureReason::FailureAttributionMissing,
            "GNT-27.13-trust-failure-attribution",
        ),
    ];
    assert_eq!(TrustFailureReason::ALL.len(), expected.len());
    for (reason, anchor) in expected {
        assert!(TrustFailureReason::ALL.contains(&reason));
        assert_eq!(reason.anchor(), anchor);
    }
}

/// `GNT-27.4` and `GNT-27.5` bind lifecycle facts to the root policy that admitted them, so
/// a rotation under one root cannot retire a key or satisfy retained evidence under another.
#[test]
fn gnt_27_5_lifecycle_facts_remain_bound_to_their_admitting_root() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let first = root("first-root", source.clone(), acme.clone(), scope.clone());
    let second = root("second-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(&[first, second], std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);
    let evidence = rotation(
        source.clone(),
        scope,
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        declared_signature(&next, payload),
    );
    let first_policy = RootSelectionPolicy::selected(accept(
        RootId::new("first-root"),
        "the first root identity is valid",
    ));
    let second_policy = RootSelectionPolicy::selected(accept(
        RootId::new("second-root"),
        "the second root identity is valid",
    ));
    admit(
        store.rotate_with_root_selection(
            &declaration,
            evidence.clone(),
            std::slice::from_ref(&next),
            &first_policy,
        ),
        "the first root admits its rotation evidence",
    );

    let retired = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    assert!(matches!(
        refuse(
            store.authorize_with_root_selection(&declaration, &retired, 5, &first_policy),
            "the admitting root retires the old key",
        )
        .condition(),
        RegistryError::KeySuperseded { .. }
    ));
    admit(
        store.authorize_with_root_selection(&declaration, &retired, 5, &second_policy),
        "a rotation admitted under the first root cannot retire the second root's key",
    );

    let snapshot = snapshot_of(5, 5, 10, std::slice::from_ref(&retired));
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source, 1)
        .with_rotation_fact(evidence.evidence_digest())
        .with_lifecycle_root_policy(first_policy.clone());
    let signatures = vec![declared_signature(&old, snapshot.content_digest())];
    let input = verification_input_with_advisories_and_policy(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(5),
        FreshnessMode::online(),
        AdvisoryStore::new(),
        second_policy.clone(),
    );
    assert!(matches!(
        refuse_snapshot(&store, &input).condition(),
        RegistryError::RetainedLifecycleFactsMissing { .. }
    ));

    let successor = entry(
        "acme",
        "widget",
        "2.0.0",
        &publisher("acme", "next-key"),
        "manifest-successor",
        "artifact-successor",
    );
    let snapshot = snapshot_of(6, 6, 10, std::slice::from_ref(&successor));
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(declaration.identity().clone(), 1)
        .with_rotation_fact(evidence.evidence_digest())
        .with_lifecycle_root_policy(first_policy);
    let signatures = vec![declared_signature(&next, snapshot.content_digest())];
    let compatible = RootSelectionPolicy::enumerated(&[
        accept(
            RootId::new("first-root"),
            "the first root identity is valid",
        ),
        accept(
            RootId::new("second-root"),
            "the second root identity is valid",
        ),
    ]);
    let input = verification_input_with_advisories_and_policy(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(6),
        FreshnessMode::online(),
        AdvisoryStore::new(),
        compatible,
    );
    admit_snapshot(&store, &input);
}

/// `GNT-27.5` authenticates the compromise observation epoch, which decides whether a retired
/// declarer was still within its rotation overlap rather than inferring that instant from sequence.
#[test]
fn gnt_27_5_compromise_uses_its_authenticated_observation_epoch() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let rotation_timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let rotation_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        next.key(),
        rotation_timing,
    );
    admit(
        store.rotate(
            &declaration,
            rotation(
                source.clone(),
                scope.clone(),
                &old,
                &next,
                4,
                declared_signature(&old, rotation_payload),
                declared_signature(&next, rotation_payload),
            ),
            std::slice::from_ref(&next),
        ),
        "the declared rotation is admitted",
    );

    let during_payload = Compromise::payload(&source, &scope, &acme, old.key(), 6, 4);
    admit(
        store.compromise(
            &declaration,
            accept(
                Compromise::authenticated(
                    source.clone(),
                    scope.clone(),
                    acme.clone(),
                    old.key().clone(),
                    6,
                    4,
                    declared_signature(&old, during_payload),
                ),
                "the compromise observed during overlap is valid",
            ),
        ),
        "the retiring authority may authenticate compromise evidence during overlap",
    );

    let after_payload = Compromise::payload(&source, &scope, &acme, old.key(), 6, 5);
    let refusal = refuse(
        store.compromise(
            &declaration,
            accept(
                Compromise::authenticated(
                    source,
                    scope,
                    acme,
                    old.key().clone(),
                    6,
                    5,
                    declared_signature(&old, after_payload),
                ),
                "the compromise observed after overlap is valid input",
            ),
        ),
        "a retired declarer cannot authenticate compromise evidence after overlap",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeySuperseded { .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::SupersededSigningAuthority
    );
}

/// `GNT-27.5` permits an independently delegated successor to rotate without retired-key
/// material or a retiring-key signature when its authority is same-or-wider under the root.
#[test]
fn gnt_27_5_rotation_accepts_an_independently_delegated_successor() {
    let source = registry_source("acme", "widget");
    let recovery = key("recovery-key");
    let old = key("acme-key");
    let next = key("next-key");
    let recovery_publisher = publisher("acme", "recovery-key");
    let successor = publisher("acme", "next-key");
    let wide_scope = scope_of_namespace("acme");
    let rotation_scope = scope_of_package("acme", "widget");
    let recovery_root = root(
        "recovery-root",
        source.clone(),
        recovery_publisher.clone(),
        wide_scope.clone(),
    );
    let successor_delegation = delegation(
        source.clone(),
        recovery_publisher,
        successor,
        wide_scope,
        1,
        &recovery,
    );
    let mut store = store_of(
        std::slice::from_ref(&recovery_root),
        &[recovery.clone(), next.clone()],
        std::slice::from_ref(&successor_delegation),
    );
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let retiring = publisher("acme", "acme-key");
    let payload = RotationEvidence::payload(
        &source,
        &rotation_scope,
        &retiring,
        old.key(),
        next.key(),
        timing,
    );
    assert_eq!(store.material(old.key()), None);
    let evidence = accept(
        RotationEvidence::authenticated(
            accept(
                RotationContext::new(
                    source,
                    rotation_scope,
                    retiring,
                    old.key().clone(),
                    next.key().clone(),
                    timing,
                ),
                "the independently delegated rotation context is valid",
            ),
            RotationSignatures::successor_only(declared_signature(&next, payload)),
        ),
        "the successor-only rotation evidence is valid",
    );
    admit(
        store.rotate(&declaration, evidence, &[]),
        "the independently delegated same-or-wider successor authorizes the rotation",
    );
    assert_eq!(store.rotations().len(), 1);
}

/// `GNT-27.4` requires the root policy during initial delegation construction, before an
/// unordered declaration list can implicitly combine several roots.
#[test]
fn gnt_27_4_initial_delegations_require_explicit_multi_root_selection() {
    let source = registry_source("acme", "widget");
    let primary = key("primary-key");
    let alternate = key("alternate-key");
    let delegate_key = key("delegate-key");
    let primary_publisher = publisher("acme", "primary-key");
    let delegate = publisher("acme", "delegate-key");
    let scope = scope_of_package("acme", "widget");
    let primary_root = root(
        "primary-root",
        source.clone(),
        primary_publisher.clone(),
        scope.clone(),
    );
    let alternate_root = root(
        "alternate-root",
        source.clone(),
        publisher("acme", "alternate-key"),
        scope.clone(),
    );
    let initial = delegation(source, primary_publisher, delegate, scope, 1, &primary);
    assert!(matches!(
        TrustStore::new(
            &[primary_root.clone(), alternate_root.clone()],
            &[primary.clone(), alternate, delegate_key],
            std::slice::from_ref(&initial),
        ),
        Err(RegistryError::TrustDecisionDisjunction { .. })
    ));
    let policy = RootSelectionPolicy::selected(accept(
        RootId::new("primary-root"),
        "the primary root identity is valid",
    ));
    let store = accept(
        TrustStore::new_with_root_selection(
            &[primary_root, alternate_root],
            &[primary, key("alternate-key"), key("delegate-key")],
            std::slice::from_ref(&initial),
            &policy,
        ),
        "the selected root constructs the initial delegation chain",
    );
    assert_eq!(store.delegations()[0].root().as_str(), "primary-root");
}

/// `GNT-27.5` rejects a second rotation presented by a key that an earlier rotation retired.
#[test]
fn gnt_27_5_retired_key_cannot_rotate_again_later() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let later = key("later-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());

    let initial_timing = accept(
        RotationTiming::new(4, 4, 5),
        "the initial rotation timing is valid",
    );
    let initial_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        next.key(),
        initial_timing,
    );
    admit(
        store.rotate(
            &declaration,
            rotation(
                source.clone(),
                scope.clone(),
                &old,
                &next,
                4,
                declared_signature(&old, initial_payload),
                declared_signature(&next, initial_payload),
            ),
            std::slice::from_ref(&next),
        ),
        "the initial rotation retires the original key",
    );

    let later_timing = accept(
        RotationTiming::new(6, 6, 7),
        "the later rotation timing is valid",
    );
    let later_payload =
        RotationEvidence::payload(&source, &scope, &acme, old.key(), later.key(), later_timing);
    let refusal = refuse(
        store.rotate(
            &declaration,
            rotation(
                source,
                scope,
                &old,
                &later,
                6,
                declared_signature(&old, later_payload),
                declared_signature(&later, later_payload),
            ),
            std::slice::from_ref(&later),
        ),
        "a retired key cannot authorize a later rotation",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeySuperseded { sequence: 4, .. }
    ));
    assert_eq!(store.rotations().len(), 1);
    assert_eq!(store.material(later.key()), None);
}

/// `GNT-27.4` and `GNT-27.5` refuse a child delegation that a retired key signs after its
/// rotation overlap, so that refused child cannot authorize a later metadata entry.
#[test]
fn gnt_27_5_retired_key_cannot_delegate_after_overlap() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let old_publisher = publisher("acme", "acme-key");
    let child = publisher("acme-release", "child-key");
    let scope = scope_of_package("acme", "widget");
    let root = root(
        "acme-root",
        source.clone(),
        old_publisher.clone(),
        scope.clone(),
    );
    let mut store = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());

    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload = RotationEvidence::payload(
        &source,
        &scope,
        &old_publisher,
        old.key(),
        next.key(),
        timing,
    );
    admit(
        store.rotate(
            &declaration,
            rotation(
                source.clone(),
                scope.clone(),
                &old,
                &next,
                4,
                declared_signature(&old, payload),
                declared_signature(&next, payload),
            ),
            std::slice::from_ref(&next),
        ),
        "the rotation retires the old key after its overlap",
    );

    let delegation_timing = accept(
        DelegationTiming::new(5, u64::MAX, 5),
        "the post-overlap delegation timing is valid",
    );
    let delegation_payload = Delegation::payload(
        &source,
        &old_publisher,
        &child,
        &scope,
        delegation_timing.not_before_epoch(),
        delegation_timing.expiry_epoch(),
        delegation_timing.effective_sequence(),
    );
    let refused_child = accept(
        Delegation::authenticated(
            source.clone(),
            old_publisher,
            child.clone(),
            scope.clone(),
            delegation_timing,
            declared_signature(&old, delegation_payload),
        ),
        "the post-overlap child delegation is valid evidence",
    );
    let refusal = refuse(
        store.delegate(&declaration, refused_child),
        "a retired key cannot admit a child delegation after overlap",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeySuperseded { .. }
    ));
    assert!(store.delegations().is_empty());

    let entry = entry(
        "acme",
        "widget",
        "1.0.0",
        &child,
        "manifest-a",
        "artifact-a",
    );
    let refusal = refuse(
        store.authorize(&declaration, &entry, 6),
        "the refused child cannot authorize a later entry",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::PublisherUnauthorized { .. }
    ));
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` refuses a newly presented child
/// delegation when a retired key remains in the parent delegation's admitted authority chain.
#[test]
fn gnt_27_5_retired_ancestor_cannot_extend_an_existing_delegation_chain() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let parent_key = key("parent-key");
    let child_key = key("child-key");
    let root_publisher = publisher("acme", "acme-key");
    let parent = publisher("acme-release", "parent-key");
    let child = publisher("acme-child", "child-key");
    let scope = scope_of_package("acme", "widget");
    let root = root(
        "acme-root",
        source.clone(),
        root_publisher.clone(),
        scope.clone(),
    );
    let mut store = store_of(
        std::slice::from_ref(&root),
        &[old.clone(), parent_key.clone(), child_key],
        &[],
    );
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let parent_timing = accept(
        DelegationTiming::new(0, u64::MAX, 1),
        "the initial parent delegation timing is valid",
    );
    let parent_payload = Delegation::payload(
        &source,
        &root_publisher,
        &parent,
        &scope,
        parent_timing.not_before_epoch(),
        parent_timing.expiry_epoch(),
        parent_timing.effective_sequence(),
    );
    admit(
        store.delegate(
            &declaration,
            accept(
                Delegation::authenticated(
                    source.clone(),
                    root_publisher.clone(),
                    parent.clone(),
                    scope.clone(),
                    parent_timing,
                    declared_signature(&old, parent_payload),
                ),
                "the initial parent delegation is valid",
            ),
        ),
        "the pre-retirement parent delegation is admitted",
    );
    let rotation_timing = accept(RotationTiming::new(4, 4, 5), "the rotation timing is valid");
    let rotation_payload = RotationEvidence::payload(
        &source,
        &scope,
        &root_publisher,
        old.key(),
        next.key(),
        rotation_timing,
    );
    admit(
        store.rotate(
            &declaration,
            rotation(
                source.clone(),
                scope.clone(),
                &old,
                &next,
                4,
                declared_signature(&old, rotation_payload),
                declared_signature(&next, rotation_payload),
            ),
            std::slice::from_ref(&next),
        ),
        "the root rotation is admitted",
    );
    let child_timing = accept(
        DelegationTiming::new(5, u64::MAX, 5),
        "the child delegation timing is valid",
    );
    let child_payload = Delegation::payload(
        &source,
        &parent,
        &child,
        &scope,
        child_timing.not_before_epoch(),
        child_timing.expiry_epoch(),
        child_timing.effective_sequence(),
    );
    let refusal = refuse(
        store.delegate(
            &declaration,
            accept(
                Delegation::authenticated(
                    source,
                    parent,
                    child,
                    scope,
                    child_timing,
                    declared_signature(&parent_key, child_payload),
                ),
                "the child delegation envelope is valid",
            ),
        ),
        "a retired ancestor cannot admit a new child delegation",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::KeySuperseded { sequence: 4, .. }
    ));
    assert_eq!(store.delegations().len(), 1);
}

/// `GNT-27.4` and `GNT-27.5` decide new delegation admission from the current
/// lifecycle state, so backdated or wider evidence cannot revive a retired key while its
/// successor can re-delegate the inherited scope.
#[test]
fn gnt_27_5_retirement_is_current_and_successors_can_redelegate() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let child_key = key("child-key");
    let old_publisher = publisher("acme", "acme-key");
    let successor = publisher("acme", "next-key");
    let child = publisher("acme-release", "child-key");
    let package_scope = scope_of_package("acme", "widget");
    let root = root(
        "acme-root",
        source.clone(),
        old_publisher.clone(),
        package_scope.clone(),
    );
    let mut store = store_of(
        std::slice::from_ref(&root),
        &[old.clone(), next.clone(), child_key],
        &[],
    );
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let rotation_timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let rotation_payload = RotationEvidence::payload(
        &source,
        &package_scope,
        &old_publisher,
        old.key(),
        next.key(),
        rotation_timing,
    );
    admit(
        store.rotate(
            &declaration,
            rotation(
                source.clone(),
                package_scope.clone(),
                &old,
                &next,
                4,
                declared_signature(&old, rotation_payload),
                declared_signature(&next, rotation_payload),
            ),
            std::slice::from_ref(&next),
        ),
        "the rotation retires the original key",
    );

    let backdated_timing = accept(
        DelegationTiming::new(0, 4, 1),
        "the backdated delegation timing is valid evidence",
    );
    let backdated_payload = Delegation::payload(
        &source,
        &old_publisher,
        &child,
        &package_scope,
        backdated_timing.not_before_epoch(),
        backdated_timing.expiry_epoch(),
        backdated_timing.effective_sequence(),
    );
    let backdated = accept(
        Delegation::authenticated(
            source.clone(),
            old_publisher.clone(),
            child.clone(),
            package_scope.clone(),
            backdated_timing,
            declared_signature(&old, backdated_payload),
        ),
        "the backdated delegation envelope is valid",
    );
    assert!(matches!(
        refuse(
            store.delegate(&declaration, backdated),
            "backdated evidence cannot revive a retired key",
        )
        .condition(),
        RegistryError::KeySuperseded { .. }
    ));

    let namespace_scope = scope_of_namespace("acme");
    let wider_timing = accept(
        DelegationTiming::new(0, u64::MAX, 1),
        "the wider delegation timing is valid evidence",
    );
    let wider_payload = Delegation::payload(
        &source,
        &old_publisher,
        &child,
        &namespace_scope,
        wider_timing.not_before_epoch(),
        wider_timing.expiry_epoch(),
        wider_timing.effective_sequence(),
    );
    let wider = accept(
        Delegation::authenticated(
            source.clone(),
            old_publisher,
            child.clone(),
            namespace_scope,
            wider_timing,
            declared_signature(&old, wider_payload),
        ),
        "the wider delegation envelope is valid",
    );
    assert!(matches!(
        refuse(
            store.delegate(&declaration, wider),
            "a wider delegation cannot revive the retired package authority",
        )
        .condition(),
        RegistryError::KeySuperseded { .. }
    ));

    let successor_timing = accept(
        DelegationTiming::new(5, u64::MAX, 5),
        "the successor delegation timing is valid",
    );
    let successor_payload = Delegation::payload(
        &source,
        &successor,
        &child,
        &package_scope,
        successor_timing.not_before_epoch(),
        successor_timing.expiry_epoch(),
        successor_timing.effective_sequence(),
    );
    admit(
        store.delegate(
            &declaration,
            accept(
                Delegation::authenticated(
                    source,
                    successor,
                    child.clone(),
                    package_scope,
                    successor_timing,
                    declared_signature(&next, successor_payload),
                ),
                "the successor delegation envelope is valid",
            ),
        ),
        "the rotated successor can re-delegate its inherited scope",
    );
    let delegated = entry(
        "acme",
        "widget",
        "1.0.0",
        &child,
        "manifest-a",
        "artifact-a",
    );
    assert_eq!(
        admit(
            store.authorize(&declaration, &delegated, 6),
            "the successor delegation authorizes a later entry",
        )
        .authorized_by(),
        child.key()
    );
}

/// `GNT-27.5` retains every root that admits identical lifecycle evidence, so one root's
/// admission cannot erase the fact for another selected or enumerated trust policy.
#[test]
fn gnt_27_5_identical_lifecycle_evidence_retains_every_admitting_root() {
    let source = registry_source("acme", "widget");
    let old = key("acme-key");
    let next = key("next-key");
    let acme = publisher("acme", "acme-key");
    let scope = scope_of_package("acme", "widget");
    let first = root("first-root", source.clone(), acme.clone(), scope.clone());
    let second = root("second-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(&[first, second], std::slice::from_ref(&old), &[]);
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload = RotationEvidence::payload(&source, &scope, &acme, old.key(), next.key(), timing);
    let evidence = rotation(
        source.clone(),
        scope,
        &old,
        &next,
        4,
        declared_signature(&old, payload),
        declared_signature(&next, payload),
    );
    let first_policy = RootSelectionPolicy::selected(accept(
        RootId::new("first-root"),
        "the first root identity is valid",
    ));
    let second_policy = RootSelectionPolicy::selected(accept(
        RootId::new("second-root"),
        "the second root identity is valid",
    ));
    admit(
        store.rotate_with_root_selection(
            &declaration,
            evidence.clone(),
            std::slice::from_ref(&next),
            &first_policy,
        ),
        "the first root admits the rotation",
    );
    admit(
        store.rotate_with_root_selection(
            &declaration,
            evidence.clone(),
            std::slice::from_ref(&next),
            &second_policy,
        ),
        "the second root retains the identical rotation evidence",
    );

    let retired = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    for policy in [
        first_policy.clone(),
        second_policy.clone(),
        RootSelectionPolicy::enumerated(&[
            accept(
                RootId::new("first-root"),
                "the first root identity is valid",
            ),
            accept(
                RootId::new("second-root"),
                "the second root identity is valid",
            ),
        ]),
    ] {
        assert!(matches!(
            refuse(
                store.authorize_with_root_selection(&declaration, &retired, 5, &policy),
                "every compatible root policy consumes the retained rotation",
            )
            .condition(),
            RegistryError::KeySuperseded { .. }
        ));
    }

    let successor = entry(
        "acme",
        "widget",
        "2.0.0",
        &publisher("acme", "next-key"),
        "manifest-b",
        "artifact-b",
    );
    let snapshot = snapshot_of(5, 5, 10, std::slice::from_ref(&successor));
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source, 1)
        .with_rotation_fact(evidence.evidence_digest())
        .with_lifecycle_root_policy(second_policy.clone());
    let signatures = vec![declared_signature(&next, snapshot.content_digest())];
    let input = verification_input_with_advisories_and_policy(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(6),
        FreshnessMode::online(),
        AdvisoryStore::new(),
        second_policy,
    );
    admit_snapshot(&store, &input);
}

/// `GNT-27.2`, `GNT-27.3`, and `GNT-27.12` reject a collision during snapshot admission and
/// require a lockfile record to bind the exact snapshot entry with its complete dependencies.
#[test]
fn gnt_27_snapshot_admission_and_lockfile_binding_reject_forged_entries() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let source = registry_source("acme", "widget");
    let lower_declaration = source_declaration(0, "widget", "widget", source.clone());
    let declaration = accept(
        source_declaration_for(0, "widget", "Widget", source.clone()),
        "the collision declaration owns the presented package subject",
    );
    let root = root(
        "acme-root",
        source.clone(),
        acme.clone(),
        scope_of_namespace("acme"),
    );
    let store = store_of(
        std::slice::from_ref(&root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let lower = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let colliding = entry("acme", "Widget", "2.0.0", &acme, "manifest-b", "artifact-b");
    let lower_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&lower));
    let collision_snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&colliding));
    let collision_ledger = ledger_of(&lower_declaration, &lower_snapshot);
    let retained = RetainedState::for_source(source.clone(), 1);
    let collision_signatures = vec![declared_signature(
        &acme_key,
        collision_snapshot.content_digest(),
    )];
    let collision_input = verification_input(
        std::slice::from_ref(&declaration),
        &collision_snapshot,
        &collision_signatures,
        std::slice::from_ref(&retained),
        &collision_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let collision_refusal = refuse_snapshot(&store, &collision_input);
    assert_eq!(
        collision_refusal.reason(),
        TrustFailureReason::CanonicalNameCollision
    );
    assert_eq!(
        collision_refusal.requirement_anchor(),
        "GNT-27.2-canonical-publication-names-and-external-name-mapping"
    );
    assert!(collision_refusal.causing_entry().is_some());
    assert_eq!(collision_refusal.declaration_index(), declaration.index());

    // A failed signature wins over a later canonical-name collision in the ordered verifier.
    let forged_signatures = [DeclaredSignature::declared(
        acme_key.key().clone(),
        digest("forged-collision-signature"),
    )];
    let precedence_input = verification_input(
        std::slice::from_ref(&declaration),
        &collision_snapshot,
        &forged_signatures,
        std::slice::from_ref(&retained),
        &collision_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    assert!(matches!(
        refuse_snapshot(&store, &precedence_input).condition(),
        RegistryError::SignatureUnverified { .. }
    ));

    let dependency = accept(
        SnapshotDependency::new(
            "helper",
            registry_source("helper", "helper"),
            "helper",
            "helper",
            "1.0.0",
            TargetKind::Library,
            gantry::ir::registry::SnapshotIdentity::from_digest(digest("helper-snapshot")),
        ),
        "the declared dependency identity is valid",
    );
    let forged = lower.clone().with_dependency(dependency);
    let original_snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&lower));
    let (original_trust, original_retained, original_signatures) =
        authenticated_fixture(&lower_declaration, &original_snapshot);
    let original_empty = PublicationLedger::new();
    let original_input = verification_input(
        std::slice::from_ref(&lower_declaration),
        &original_snapshot,
        &original_signatures,
        std::slice::from_ref(&original_retained),
        &original_empty,
        EpochObservation::at(original_snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let original_verified = admit_snapshot(&original_trust, &original_input);
    assert!(matches!(
        refuse(
            LockfileRecord::historical(
                &forged,
                &original_verified,
                &original_retained,
                &lower_declaration,
                LockfileInputs::default(),
            ),
            "a record cannot bind a same-coordinate entry absent from the authenticated snapshot",
        )
        .condition(),
        RegistryError::LockfileDeclarationInvalid {
            field: "lockfile record release",
            ..
        }
    ));
    let forged_snapshot = snapshot_of(6, 100, 200, std::slice::from_ref(&forged));
    let (forged_trust, forged_retained, forged_signatures) =
        authenticated_fixture(&lower_declaration, &forged_snapshot);
    let forged_empty = PublicationLedger::new();
    let forged_input = verification_input(
        std::slice::from_ref(&lower_declaration),
        &forged_snapshot,
        &forged_signatures,
        std::slice::from_ref(&forged_retained),
        &forged_empty,
        EpochObservation::at(forged_snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let forged_verified = admit_snapshot(&forged_trust, &forged_input);
    assert!(matches!(
        refuse(
            LockfileRecord::historical(
                &forged,
                &forged_verified,
                &forged_retained,
                &lower_declaration,
                LockfileInputs {
                    targets: forged
                        .target_artifacts()
                        .iter()
                        .map(TargetArtifact::target)
                        .collect(),
                    target_artifacts: forged.target_artifacts().to_vec(),
                    ..LockfileInputs::default()
                },
            ),
            "a forged record cannot omit an authenticated dependency",
        )
        .condition(),
        RegistryError::LockfileDeclarationInvalid {
            field: "lockfile record dependencies",
            ..
        }
    ));
}

/// `GNT-27.9` decides rewrites from the greatest verified snapshot, so a lockfile created
/// before a yank cannot silently discard the release after the authenticated state changes.
#[test]
fn gnt_27_9_post_lockfile_yank_refuses_a_silent_rewrite() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let source = registry_source("acme", "widget");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let root = root(
        "acme-root",
        source.clone(),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let store = store_of(
        std::slice::from_ref(&root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let published = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let published_snapshot = snapshot_of(3, 100, 200, std::slice::from_ref(&published));
    let lockfile = lockfile_of(std::slice::from_ref(&record_of(
        &published,
        &published_snapshot,
        &declaration,
    )));
    let yanked = published.with_publication(PublicationState::Yanked);
    let current_snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&yanked));
    let current_ledger = ledger_of(&declaration, &current_snapshot);
    let current_retained =
        RetainedState::for_source(source, 4).with_content(4, current_snapshot.content_digest());
    let current_signatures = vec![declared_signature(
        &acme_key,
        current_snapshot.content_digest(),
    )];
    let current_input = verification_input(
        std::slice::from_ref(&declaration),
        &current_snapshot,
        &current_signatures,
        std::slice::from_ref(&current_retained),
        &current_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let current_verified = admit_snapshot(&store, &current_input);
    assert!(matches!(
        refuse(
            lockfile.rewrite_kept(&declaration, &[], &current_verified, &current_retained,),
            "a later authenticated yank cannot be removed from a prior lockfile silently",
        )
        .condition(),
        RegistryError::LockfileRewriteRefused { .. }
    ));
    assert_eq!(
        admit(
            lockfile.rewrite_kept(&declaration, &[0], &current_verified, &current_retained,),
            "keeping the prior locked release remains reproducible",
        )
        .replay()
        .len(),
        1
    );
}

/// `GNT-27.11-vcs-path-and-vendor-source-verification` requires final VCS and path acquisition
/// to consume the proof minted by immutable checkout or content verification.
#[test]
fn gnt_27_11_vcs_and_path_acquisition_require_verified_source_proofs() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let commit_text = "a".repeat(40);
    let pinned_commit = commit(&commit_text);
    let vcs_source = accept(
        SourceIdentity::vcs("acme.widget", &pinned_commit),
        "the VCS source identity is valid",
    );
    let path_source = accept(
        SourceIdentity::path("workspace.widget"),
        "the path source identity is valid",
    );
    let vcs_entry = entry_for_source(
        vcs_source.clone(),
        "acme",
        "widget",
        "1.0.0",
        &acme,
        "vcs-manifest",
        "vcs-artifact",
        digest("vcs-tree"),
    );
    let path_entry = entry_for_source(
        path_source.clone(),
        "acme",
        "path-widget",
        "1.0.0",
        &acme,
        "path-manifest",
        "path-artifact",
        digest("path-tree"),
    );
    let vcs_snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&vcs_entry));
    let path_snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&path_entry));
    let vcs_declaration = source_declaration(0, "widget", "widget", vcs_source.clone());
    let path_declaration = accept(
        source_declaration_for(1, "path_widget", "path-widget", path_source.clone()),
        "the path declaration owns the path-widget package subject",
    );
    let store = store_of(
        &[
            root(
                "vcs-root",
                vcs_source.clone(),
                acme.clone(),
                scope_of_package("acme", "widget"),
            ),
            root(
                "path-root",
                path_source.clone(),
                acme.clone(),
                scope_of_package("acme", "path-widget"),
            ),
        ],
        std::slice::from_ref(&acme_key),
        &[],
    );
    let vcs_retained = RetainedState::for_source(vcs_source.clone(), 1);
    let path_retained = RetainedState::for_source(path_source.clone(), 1);
    let vcs_ledger = ledger_of(&vcs_declaration, &vcs_snapshot);
    let path_ledger = ledger_of(&path_declaration, &path_snapshot);
    let vcs_signatures = [declared_signature(&acme_key, vcs_snapshot.content_digest())];
    let path_signatures = [declared_signature(
        &acme_key,
        path_snapshot.content_digest(),
    )];
    let vcs_input = verification_input(
        std::slice::from_ref(&vcs_declaration),
        &vcs_snapshot,
        &vcs_signatures,
        std::slice::from_ref(&vcs_retained),
        &vcs_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let vcs_verified = admit_snapshot(&store, &vcs_input);
    let path_input = verification_input(
        std::slice::from_ref(&path_declaration),
        &path_snapshot,
        &path_signatures,
        std::slice::from_ref(&path_retained),
        &path_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let path_verified = admit_snapshot(&store, &path_input);
    let vcs_lockfile = lockfile_of(std::slice::from_ref(&record_of(
        &vcs_entry,
        &vcs_snapshot,
        &vcs_declaration,
    )));
    let path_lockfile = lockfile_of(std::slice::from_ref(&record_of(
        &path_entry,
        &path_snapshot,
        &path_declaration,
    )));
    let vcs_gate = admit(
        vcs_verified.bind_lockfile(&vcs_lockfile, std::slice::from_ref(&vcs_declaration)),
        "the VCS lockfile is bound",
    );
    let path_gate = admit(
        path_verified.bind_lockfile(&path_lockfile, std::slice::from_ref(&path_declaration)),
        "the path lockfile is bound",
    );
    assert!(matches!(
        refuse(
            vcs_gate.admit_acquisition(
                0,
                TargetKind::Library,
                &DeliveredRelease::direct(&vcs_entry, vcs_snapshot.identity()),
                &AdvisoryStore::new(),
            ),
            "a VCS delivery without a checkout proof is refused",
        )
        .condition(),
        RegistryError::PinMismatch { .. }
    ));
    assert!(matches!(
        refuse(
            path_gate.admit_acquisition(
                1,
                TargetKind::Library,
                &DeliveredRelease::direct(&path_entry, path_snapshot.identity()),
                &AdvisoryStore::new(),
            ),
            "a path delivery without a content proof is refused",
        )
        .condition(),
        RegistryError::ContentMismatch { .. }
    ));
    let vcs_proof = admit(
        verify_pinned_tree(
            &vcs_declaration,
            &accept(
                VcsPin::new(vcs_source.clone(), &commit_text, digest("vcs-tree")),
                "the VCS pin is valid",
            ),
            &PinnedTree::observed(vcs_source, Some(pinned_commit), digest("vcs-tree")),
        ),
        "the pinned checkout verifies",
    );
    let path_proof = admit(
        verify_path_tree(
            &path_declaration,
            &accept(
                PathPin::new(path_source.clone(), digest("path-tree")),
                "the path pin is valid",
            ),
            &PinnedTree::observed(path_source, None, digest("path-tree")),
        ),
        "the pinned path content verifies",
    );
    admit(
        vcs_gate.admit_acquisition(
            0,
            TargetKind::Library,
            &DeliveredRelease::direct(&vcs_entry, vcs_snapshot.identity())
                .with_vcs_proof(vcs_proof),
            &AdvisoryStore::new(),
        ),
        "a VCS delivery consumes its checkout proof",
    );
    admit(
        path_gate.admit_acquisition(
            1,
            TargetKind::Library,
            &DeliveredRelease::direct(&path_entry, path_snapshot.identity())
                .with_path_proof(path_proof),
            &AdvisoryStore::new(),
        ),
        "a path delivery consumes its content proof",
    );
}

/// `GNT-27.12-lockfile-evidence-binding` domain-separates each collection, so values from one
/// collection cannot be retagged as another without changing the record attestation.
#[test]
fn gnt_27_12_collection_attestations_cannot_be_retagged() {
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", widget.source().clone());
    let common = digest("retagged-collection-value");
    let targets: Vec<_> = widget
        .target_artifacts()
        .iter()
        .map(TargetArtifact::target)
        .collect();
    let target_artifacts = widget.target_artifacts().to_vec();
    let interfaces = record_with_inputs(
        &widget,
        &snapshot,
        &declaration,
        LockfileInputs {
            targets: targets.clone(),
            target_artifacts: target_artifacts.clone(),
            interfaces: vec![common],
            ..LockfileInputs::default()
        },
    );
    let generators = record_with_inputs(
        &widget,
        &snapshot,
        &declaration,
        LockfileInputs {
            targets,
            target_artifacts,
            generator_inputs: vec![common],
            ..LockfileInputs::default()
        },
    );
    assert_ne!(interfaces.attest(), generators.attest());
    assert_ne!(interfaces.evidence(), generators.evidence());
}

/// `GNT-27.13-trust-failure-attribution` anchors every structured refusal to its closed reason,
/// including lifecycle, source-kind, snapshot-format, and attribution failures.
#[test]
fn gnt_27_13_reason_owned_anchors_cover_every_error_surface() {
    let source = registry_source("acme", "widget");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let alternate_kind = accept(
        SourceIdentity::path(source.canonical_text()),
        "the alternate source kind is valid",
    );
    let fallback = refuse(
        resolve_source(
            std::slice::from_ref(&declaration),
            &declaration,
            &alternate_kind,
        ),
        "a source-kind fallback is refused",
    );
    assert_eq!(fallback.requirement_anchor(), fallback.reason().anchor());

    let mut unsupported = MetadataSnapshot::VERSION;
    unsupported.major = 9;
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let format_error = reject(
        MetadataSnapshot::new(
            unsupported,
            widget.source().clone(),
            4,
            100,
            200,
            std::slice::from_ref(&widget),
        ),
        "an unsupported format is refused",
    );
    assert_eq!(
        format_error.requirement_anchor(),
        format_error.trust_failure_reason().anchor()
    );

    let unbound_snapshot = snapshot_of(
        4,
        100,
        200,
        std::slice::from_ref(&widget.with_source(registry_source("other", "widget"))),
    );
    let store = store_of(&[], &[], &[]);
    let signatures: [DeclaredSignature; 0] = [];
    let retained: [RetainedState; 0] = [];
    let ledger = PublicationLedger::new();
    let attribution = refuse_snapshot(
        &store,
        &verification_input(
            std::slice::from_ref(&declaration),
            &unbound_snapshot,
            &signatures,
            &retained,
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        ),
    );
    assert_eq!(
        attribution.requirement_anchor(),
        attribution.reason().anchor()
    );
}

/// `GNT-27.9-yank-semantics` checks every source in a multi-source lockfile before a rewrite
/// can drop one record, so a yank from a dependency source cannot be silently bypassed.
#[test]
fn gnt_27_9_multi_source_rewrite_checks_every_greatest_snapshot() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let primary = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let helper = entry(
        "helper",
        "helper",
        "1.0.0",
        &acme,
        "manifest-b",
        "artifact-b",
    );
    let primary_declaration = source_declaration(0, "widget", "widget", primary.source().clone());
    let helper_declaration = source_declaration(1, "helper", "helper", helper.source().clone());
    let store = store_of(
        &[
            root(
                "acme-root",
                primary.source().clone(),
                acme.clone(),
                scope_of_package("acme", "widget"),
            ),
            root(
                "helper-root",
                helper.source().clone(),
                acme.clone(),
                scope_of_package("helper", "helper"),
            ),
        ],
        std::slice::from_ref(&acme_key),
        &[],
    );
    let locked_primary = snapshot_of(3, 100, 200, std::slice::from_ref(&primary));
    let locked_helper = snapshot_of(3, 100, 200, std::slice::from_ref(&helper));
    let lockfile = lockfile_of(&[
        record_of(&primary, &locked_primary, &primary_declaration),
        record_of(&helper, &locked_helper, &helper_declaration),
    ]);
    let current_primary = snapshot_of(4, 100, 200, std::slice::from_ref(&primary));
    let yanked_helper = helper.clone().with_publication(PublicationState::Yanked);
    let current_helper = snapshot_of(4, 100, 200, std::slice::from_ref(&yanked_helper));
    let primary_retained = RetainedState::for_source(primary.source().clone(), 4)
        .with_content(4, current_primary.content_digest());
    let helper_retained = RetainedState::for_source(helper.source().clone(), 4)
        .with_content(4, current_helper.content_digest());
    let primary_signatures = [declared_signature(
        &acme_key,
        current_primary.content_digest(),
    )];
    let helper_signatures = [declared_signature(
        &acme_key,
        current_helper.content_digest(),
    )];
    let primary_ledger = ledger_of(&primary_declaration, &current_primary);
    let helper_ledger = ledger_of(&helper_declaration, &current_helper);
    let primary_input = verification_input(
        std::slice::from_ref(&primary_declaration),
        &current_primary,
        &primary_signatures,
        std::slice::from_ref(&primary_retained),
        &primary_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let helper_input = verification_input(
        std::slice::from_ref(&helper_declaration),
        &current_helper,
        &helper_signatures,
        std::slice::from_ref(&helper_retained),
        &helper_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let primary_verified = admit_snapshot(&store, &primary_input);
    let helper_verified = admit_snapshot(&store, &helper_input);
    let refusal = refuse(
        lockfile.rewrite_kept_closure(
            &[primary_declaration.clone(), helper_declaration.clone()],
            &[],
            &[
                (&primary_verified, &primary_retained),
                (&helper_verified, &helper_retained),
            ],
        ),
        "a dependency-source yank prevents a silent lockfile rewrite",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::LockfileRewriteRefused { .. }
    ));
    assert_eq!(refusal.declaration_index(), helper_declaration.index());

    let refusal = refuse(
        lockfile.rewrite_kept_closure(
            &[],
            &[0, 1],
            &[
                (&primary_verified, &primary_retained),
                (&helper_verified, &helper_retained),
            ],
        ),
        "a multi-source rewrite cannot fall back when a record has no declaration",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::FailureAttributionMissing
    );

    let refusal = refuse(
        lockfile.rewrite_kept_closure(
            &[
                primary_declaration.clone(),
                helper_declaration.clone(),
                helper_declaration.clone(),
            ],
            &[0, 1],
            &[
                (&primary_verified, &primary_retained),
                (&helper_verified, &helper_retained),
            ],
        ),
        "a multi-source rewrite cannot choose between duplicate record declarations",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { .. }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::FailureAttributionMissing
    );
}

/// `GNT-27.7`, `GNT-27.9`, `GNT-27.10`, `GNT-27.11`, `GNT-27.12`, and `GNT-27.13`
/// require fresh evidence to carry all current admission proofs, while durable evidence stays
/// separately replayable and every source-specific failure identifies its exact declaration.
#[test]
fn gnt_27_registry_repair_boundaries_refuse_fresh_evidence_bypasses() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let published = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let source = published.source().clone();
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let declarations = [declaration.clone()];
    let store = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&published));
    let ledger = ledger_of(&declaration, &snapshot);
    let retained =
        RetainedState::for_source(source.clone(), 4).with_content(4, snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];
    let verification = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &verification);
    let inputs = LockfileInputs {
        targets: published
            .target_artifacts()
            .iter()
            .map(TargetArtifact::target)
            .collect(),
        target_artifacts: published.target_artifacts().to_vec(),
        ..LockfileInputs::default()
    };

    let missing_digest = RetainedState::for_source(source.clone(), 4);
    let refusal = refuse_snapshot(
        &store,
        &verification_input(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&missing_digest),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        ),
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::RetainedContentMissing { sequence: 4 }
    ));
    assert_eq!(
        refusal.reason(),
        TrustFailureReason::RetainedSnapshotContentMissing
    );

    let yanked = published.clone().with_publication(PublicationState::Yanked);
    let yanked_snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&yanked));
    let yanked_ledger = ledger_of(&declaration, &yanked_snapshot);
    let yanked_retained = RetainedState::for_source(source.clone(), 5)
        .with_content(5, yanked_snapshot.content_digest());
    let yanked_signatures = [declared_signature(
        &acme_key,
        yanked_snapshot.content_digest(),
    )];
    let yanked_input = verification_input(
        &declarations,
        &yanked_snapshot,
        &yanked_signatures,
        std::slice::from_ref(&yanked_retained),
        &yanked_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let yanked_verified = admit_snapshot(&store, &yanked_input);
    let refusal = refuse(
        LockfileRecord::mint(
            &yanked,
            &yanked_verified,
            &yanked_retained,
            &declaration,
            inputs.clone(),
            &AdvisoryStore::new(),
        ),
        "a yanked release cannot mint fresh lockfile evidence",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::ReleaseYanked { .. }
    ));
    let refusal = refuse(
        LockfileRecord::historical(
            &yanked,
            &yanked_verified,
            &yanked_retained,
            &declaration,
            inputs.clone(),
        ),
        "a current yanked snapshot cannot forge historical lockfile evidence",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::ReleaseYanked { .. }
    ));

    let scope = accept(
        AdvisoryScope::new(
            source.clone(),
            "acme",
            "widget",
            "1.0.0",
            published.target_artifacts(),
        ),
        "the exact new-resolution advisory scope is valid",
    );
    let advisory = accept(
        SecurityAdvisory::new("GNT-27.10-fresh", scope, Severity::RefuseNewResolution),
        "the new-resolution advisory is valid",
    );
    let mut advisories = AdvisoryStore::new();
    admit(
        advisories.admit(
            &declaration,
            advisory.clone(),
            declared_signature(&acme_key, advisory.digest()),
            acme.clone(),
            &store,
            snapshot.sequence(),
        ),
        "the authenticated new-resolution advisory is admitted",
    );
    let refusal = refuse(
        LockfileRecord::mint(
            &published,
            &verified,
            &retained,
            &declaration,
            inputs,
            &advisories,
        ),
        "a revoked release cannot mint fresh lockfile evidence",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AdvisoryRefusesBuild {
            severity: Severity::RefuseNewResolution,
            ..
        }
    ));

    let vcs_commit = commit(&"a".repeat(40));
    let vcs = accept(
        SourceIdentity::vcs("acme.widget", &vcs_commit),
        "the VCS source identity is valid",
    );
    let mismatch = reject(
        VcsPin::new(vcs, &"b".repeat(40), digest("vcs-content")),
        "a VCS pin must repeat the commit encoded by its source identity",
    );
    assert!(matches!(
        mismatch,
        RegistryError::VcsPinIdentityMismatch { .. }
    ));
    assert_eq!(
        mismatch.trust_failure_reason(),
        TrustFailureReason::UnverifiedSourceRevision
    );
    assert_eq!(
        mismatch.requirement_anchor(),
        TrustFailureReason::UnverifiedSourceRevision.anchor()
    );

    let foreign_source = accept(
        SourceIdentity::path("foreign.widget"),
        "the foreign source is valid",
    );
    let foreign = entry_for_source(
        foreign_source,
        "acme",
        "widget",
        "2.0.0",
        &acme,
        "foreign-manifest",
        "foreign-artifact",
        digest("foreign-source"),
    );
    let foreign_snapshot = snapshot_of(6, 100, 200, std::slice::from_ref(&foreign));
    let foreign_declaration = accept(
        source_declaration_for(1, "foreign", "widget", foreign.source().clone()),
        "the foreign declaration owns the widget package subject",
    );
    let (foreign_trust, foreign_retained, foreign_signatures) =
        authenticated_fixture(&foreign_declaration, &foreign_snapshot);
    let empty = PublicationLedger::new();
    let foreign_input = verification_input(
        std::slice::from_ref(&foreign_declaration),
        &foreign_snapshot,
        &foreign_signatures,
        std::slice::from_ref(&foreign_retained),
        &empty,
        EpochObservation::at(foreign_snapshot.issue_epoch()),
        FreshnessMode::online(),
    );
    let foreign_verified = admit_snapshot(&foreign_trust, &foreign_input);
    let mut ledger = PublicationLedger::new();
    let refusal = refuse(
        ledger.admit_verified(&foreign_verified, std::slice::from_ref(&declaration)),
        "verified entries cannot occupy a ledger without their exact declaration",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { .. }
    ));
    assert!(ledger.is_empty());
}

/// The clause-owned failure vocabulary keeps structural errors with the clause that decides
/// them instead of reporting each as an unrelated generic declaration defect.
#[test]
fn gnt_27_clause_owned_structural_failures_have_matching_reasons_and_anchors() {
    let malformed = reject(
        RegistryName::package("widget/sub"),
        "a malformed publication name is refused",
    );
    assert!(matches!(malformed, RegistryError::NameMalformed { .. }));
    assert_eq!(
        malformed.trust_failure_reason(),
        TrustFailureReason::MalformedPublicationName
    );
    assert_eq!(
        malformed.requirement_anchor(),
        malformed.trust_failure_reason().anchor()
    );

    let acquisition = reject(
        PathPin::new(registry_source("acme", "widget"), digest("path-content")),
        "a path pin cannot name a registry source",
    );
    assert!(matches!(
        acquisition,
        RegistryError::AcquisitionDeclarationInvalid { .. }
    ));
    assert_eq!(
        acquisition.trust_failure_reason(),
        TrustFailureReason::InvalidAcquisitionDeclaration
    );
    assert_eq!(
        acquisition.requirement_anchor(),
        acquisition.trust_failure_reason().anchor()
    );

    let scope = accept(
        AdvisoryScope::new(
            registry_source("acme", "widget"),
            "acme",
            "widget",
            "1.0.0",
            &[accept(
                TargetArtifact::new(TargetKind::Library, digest("artifact")),
                "the advisory artifact is valid",
            )],
        ),
        "the advisory scope is valid",
    );
    let advisory = reject(
        SecurityAdvisory::new("invalid advisory", scope, Severity::RefuseNewBuild),
        "an advisory identifier outside the declared spelling is refused",
    );
    assert!(matches!(
        advisory,
        RegistryError::AdvisoryDeclarationInvalid { .. }
    ));
    assert_eq!(
        advisory.trust_failure_reason(),
        TrustFailureReason::InvalidSecurityAdvisory
    );
    assert_eq!(
        advisory.requirement_anchor(),
        advisory.trust_failure_reason().anchor()
    );
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` requires one canonical material
/// value for a successor key and leaves lifecycle state unchanged when it conflicts.
#[test]
fn gnt_27_5_rejects_conflicting_successor_material_atomically() {
    let old = key("acme-key");
    let successor = key("next-key");
    let conflicting = accept(
        KeyRecord::new(successor.key().clone(), digest("conflicting-next-material")),
        "the conflicting successor record is structurally valid",
    );
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let acme = publisher("acme", old.key().as_str());
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let mut store = store_of(&[root], &[old.clone(), successor.clone()], &[]);
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload =
        RotationEvidence::payload(&source, &scope, &acme, old.key(), successor.key(), timing);
    let evidence = rotation(
        source.clone(),
        scope,
        &old,
        &successor,
        4,
        declared_signature(&old, payload),
        declared_signature(&successor, payload),
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let refusal = refuse(
        store.rotate(&declaration, evidence, std::slice::from_ref(&conflicting)),
        "successor material cannot replace material already declared for its key id",
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::RotationEvidenceInvalid {
            defect: RotationDefect::SuccessorMaterialConflict,
            ..
        }
    ));
    assert_eq!(store.material(successor.key()), Some(successor.material()));
    assert!(store.rotations().is_empty());
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` seals competing successors before
/// admission, so no permutation can retain the first candidate it happened to observe.
#[test]
fn gnt_27_5_sealed_competing_rotations_have_identical_permutations() {
    let old = key("acme-key");
    let first_successor = key("next-a-key");
    let second_successor = key("next-b-key");
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let acme = publisher("acme", old.key().as_str());
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let first_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        first_successor.key(),
        timing,
    );
    let second_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        second_successor.key(),
        timing,
    );
    let first = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &first_successor,
        4,
        declared_signature(&old, first_payload),
        declared_signature(&first_successor, first_payload),
    );
    let second = rotation(
        source.clone(),
        scope,
        &old,
        &second_successor,
        4,
        declared_signature(&old, second_payload),
        declared_signature(&second_successor, second_payload),
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let mut forward = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let forward_refusal = refuse(
        forward.rotate_batch(
            &declaration,
            &[first.clone(), second.clone()],
            &[first_successor.clone(), second_successor.clone()],
        ),
        "competing successors refuse their sealed batch",
    );

    let mut reverse = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let reverse_refusal = refuse(
        reverse.rotate_batch(
            &declaration,
            &[second, first],
            &[second_successor.clone(), first_successor],
        ),
        "a reversed sealed batch has the same refusal",
    );

    for refusal in [&forward_refusal, &reverse_refusal] {
        assert!(matches!(
            refusal.condition(),
            RegistryError::RotationEvidenceInvalid {
                defect: RotationDefect::ConflictingSuccessor,
                ..
            }
        ));
    }
    assert_eq!(forward_refusal.condition(), reverse_refusal.condition());
    assert_eq!(forward, reverse);
    assert!(forward.rotations().is_empty());
    assert_eq!(forward.material(second_successor.key()), None);
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` verifies each sealed candidate
/// before context deduplication, so a forged equal-context duplicate cannot be hidden by its
/// valid duplicate's arrival order.
#[test]
fn gnt_27_5_sealed_equal_context_forged_duplicates_have_identical_permutations() {
    let old = key("acme-key");
    let successor = key("next-key");
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let acme = publisher("acme", old.key().as_str());
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload =
        RotationEvidence::payload(&source, &scope, &acme, old.key(), successor.key(), timing);
    let valid = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &successor,
        4,
        declared_signature(&old, payload),
        declared_signature(&successor, payload),
    );
    let forged = rotation(
        source.clone(),
        scope,
        &old,
        &successor,
        4,
        declared_signature(&old, payload),
        DeclaredSignature::declared(successor.key().clone(), digest("forged-rotation")),
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let mut forward = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let forward_refusal = refuse(
        forward.rotate_batch(
            &declaration,
            &[valid.clone(), forged.clone()],
            std::slice::from_ref(&successor),
        ),
        "a forged equal-context duplicate refuses the sealed batch",
    );
    let mut reverse = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let reverse_refusal = refuse(
        reverse.rotate_batch(
            &declaration,
            &[forged, valid],
            std::slice::from_ref(&successor),
        ),
        "a reversed forged equal-context duplicate also refuses the sealed batch",
    );

    for refusal in [&forward_refusal, &reverse_refusal] {
        assert!(matches!(
            refusal.condition(),
            RegistryError::RotationEvidenceInvalid {
                defect: RotationDefect::NewKeyUnverified,
                ..
            }
        ));
    }
    assert_eq!(forward_refusal.condition(), reverse_refusal.condition());
    assert_eq!(forward, reverse);
    assert!(forward.rotations().is_empty());
    assert_eq!(forward.material(successor.key()), None);
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` aggregates every invalid complete
/// evidence form at the sealed boundary, so forged retiring and successor signatures have one
/// fixed refusal regardless of their presentation order.
#[test]
fn gnt_27_5_sealed_equal_context_signature_defects_have_fixed_precedence() {
    let old = key("acme-key");
    let successor = key("next-key");
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let acme = publisher("acme", old.key().as_str());
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let payload =
        RotationEvidence::payload(&source, &scope, &acme, old.key(), successor.key(), timing);
    let forged_old = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &successor,
        4,
        DeclaredSignature::declared(old.key().clone(), digest("forged-old-rotation")),
        declared_signature(&successor, payload),
    );
    let forged_successor = rotation(
        source.clone(),
        scope,
        &old,
        &successor,
        4,
        declared_signature(&old, payload),
        DeclaredSignature::declared(successor.key().clone(), digest("forged-successor-rotation")),
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let mut forward = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let forward_refusal = refuse(
        forward.rotate_batch(
            &declaration,
            &[forged_old.clone(), forged_successor.clone()],
            std::slice::from_ref(&successor),
        ),
        "forged complete forms refuse their sealed batch",
    );
    let mut reverse = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let reverse_refusal = refuse(
        reverse.rotate_batch(
            &declaration,
            &[forged_successor, forged_old],
            std::slice::from_ref(&successor),
        ),
        "reversed forged complete forms have the fixed sealed refusal",
    );

    for refusal in [&forward_refusal, &reverse_refusal] {
        assert!(matches!(
            refusal.condition(),
            RegistryError::RotationEvidenceInvalid {
                defect: RotationDefect::NewKeyUnverified,
                ..
            }
        ));
    }
    assert_eq!(forward_refusal.condition(), reverse_refusal.condition());
    assert_eq!(forward, reverse);
    assert!(forward.rotations().is_empty());
    assert_eq!(forward.material(successor.key()), None);
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` retains one canonical complete
/// evidence form for a context, so valid dual-signed and successor-only forms have identical
/// lifecycle state under either presentation order.
#[test]
fn gnt_27_5_sealed_equal_context_valid_forms_retain_one_canonical_representation() {
    let source = registry_source("acme", "widget");
    let recovery = key("recovery-key");
    let old = key("acme-key");
    let successor = key("next-key");
    let recovery_publisher = publisher("acme", recovery.key().as_str());
    let successor_publisher = publisher("acme", successor.key().as_str());
    let wide_scope = scope_of_namespace("acme");
    let scope = scope_of_package("acme", "widget");
    let root = root(
        "recovery-root",
        source.clone(),
        recovery_publisher.clone(),
        wide_scope.clone(),
    );
    let successor_delegation = delegation(
        source.clone(),
        recovery_publisher,
        successor_publisher,
        wide_scope,
        1,
        &recovery,
    );
    let timing = accept(
        RotationTiming::new(4, 4, 5),
        "the declared rotation timing is valid",
    );
    let retiring = publisher("acme", old.key().as_str());
    let payload = RotationEvidence::payload(
        &source,
        &scope,
        &retiring,
        old.key(),
        successor.key(),
        timing,
    );
    let dual_signed = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &successor,
        4,
        declared_signature(&old, payload),
        declared_signature(&successor, payload),
    );
    let successor_only = accept(
        RotationEvidence::authenticated(
            accept(
                RotationContext::new(
                    source.clone(),
                    scope,
                    retiring,
                    old.key().clone(),
                    successor.key().clone(),
                    timing,
                ),
                "the independently delegated rotation context is valid",
            ),
            RotationSignatures::successor_only(declared_signature(&successor, payload)),
        ),
        "the successor-only rotation evidence is valid",
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let mut forward = store_of(
        std::slice::from_ref(&root),
        &[recovery.clone(), successor.clone()],
        std::slice::from_ref(&successor_delegation),
    );
    admit(
        forward.rotate_batch(
            &declaration,
            &[dual_signed.clone(), successor_only.clone()],
            &[old.clone(), successor.clone()],
        ),
        "complete forms with one independently delegated successor are admitted",
    );
    let mut reverse = store_of(
        std::slice::from_ref(&root),
        &[recovery, successor.clone()],
        std::slice::from_ref(&successor_delegation),
    );
    admit(
        reverse.rotate_batch(
            &declaration,
            &[successor_only, dual_signed],
            &[old, successor],
        ),
        "reversed complete forms retain the same canonical evidence",
    );

    assert_eq!(forward, reverse);
    assert_eq!(forward.rotations().len(), 1);
    assert!(forward.rotations()[0].old_signature().is_none());
}

/// `GNT-27.5-signing-key-rotation-and-compromise-recovery` classifies a backdated successor
/// timeline before retention, independently of the candidate set's presentation order.
#[test]
fn gnt_27_5_sealed_backdated_rotations_have_identical_permutations() {
    let old = key("acme-key");
    let successor = key("next-key");
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let acme = publisher("acme", old.key().as_str());
    let root = root("acme-root", source.clone(), acme.clone(), scope.clone());
    let early_timing = accept(
        RotationTiming::new(4, 4, 5),
        "the early rotation timing is valid",
    );
    let late_timing = accept(
        RotationTiming::new(5, 5, 6),
        "the backdated rotation timing is valid",
    );
    let early_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        successor.key(),
        early_timing,
    );
    let late_payload = RotationEvidence::payload(
        &source,
        &scope,
        &acme,
        old.key(),
        successor.key(),
        late_timing,
    );
    let early = rotation(
        source.clone(),
        scope.clone(),
        &old,
        &successor,
        4,
        declared_signature(&old, early_payload),
        declared_signature(&successor, early_payload),
    );
    let late = rotation(
        source.clone(),
        scope,
        &old,
        &successor,
        5,
        declared_signature(&old, late_payload),
        declared_signature(&successor, late_payload),
    );
    let declaration = source_declaration(0, "widget", "widget", source);

    let mut forward = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let forward_refusal = refuse(
        forward.rotate_batch(
            &declaration,
            &[early.clone(), late.clone()],
            std::slice::from_ref(&successor),
        ),
        "a backdated timeline refuses its sealed batch",
    );
    let mut reverse = store_of(std::slice::from_ref(&root), std::slice::from_ref(&old), &[]);
    let reverse_refusal = refuse(
        reverse.rotate_batch(
            &declaration,
            &[late, early],
            std::slice::from_ref(&successor),
        ),
        "a reversed backdated timeline has the same refusal",
    );

    for refusal in [&forward_refusal, &reverse_refusal] {
        assert!(matches!(
            refusal.condition(),
            RegistryError::RotationEvidenceInvalid {
                defect: RotationDefect::Backdated,
                ..
            }
        ));
    }
    assert_eq!(forward_refusal.condition(), reverse_refusal.condition());
    assert_eq!(forward, reverse);
    assert!(forward.rotations().is_empty());
    assert_eq!(forward.material(successor.key()), None);
}

/// `GNT-27.4-trust-roots-and-delegated-authority` rejects self and repeated-key delegation
/// cycles before a chain can become admitted authority.
#[test]
fn gnt_27_4_rejects_self_and_two_key_delegation_cycles() {
    let root_key = key("root-key");
    let delegate_key = key("delegate-key");
    let source = registry_source("acme", "widget");
    let scope = scope_of_package("acme", "widget");
    let root_publisher = publisher("acme", root_key.key().as_str());
    let delegate_publisher = publisher("acme", delegate_key.key().as_str());
    let root = root(
        "acme-root",
        source.clone(),
        root_publisher.clone(),
        scope.clone(),
    );
    let self_cycle = delegation(
        source.clone(),
        root_publisher.clone(),
        root_publisher.clone(),
        scope.clone(),
        1,
        &root_key,
    );
    let self_error = reject(
        TrustStore::new(
            std::slice::from_ref(&root),
            std::slice::from_ref(&root_key),
            &[self_cycle],
        ),
        "a self delegation cycle is refused",
    );
    assert!(matches!(
        self_error,
        RegistryError::DelegationChainIncomplete { .. }
    ));

    let root_to_delegate = delegation(
        source.clone(),
        root_publisher.clone(),
        delegate_publisher.clone(),
        scope.clone(),
        1,
        &root_key,
    );
    let delegate_to_root = delegation(
        source,
        delegate_publisher,
        root_publisher,
        scope,
        1,
        &delegate_key,
    );
    let cycle_error = reject(
        TrustStore::new(
            &[root],
            &[root_key, delegate_key],
            &[root_to_delegate, delegate_to_root],
        ),
        "a two-key delegation cycle is refused",
    );
    assert!(matches!(
        cycle_error,
        RegistryError::DelegationChainIncomplete { .. }
    ));
}

/// `GNT-27.12-lockfile-evidence-binding` requires unique declaration indices before snapshot
/// verification or lockfile binding can mint an evidence gate.
#[test]
fn gnt_27_12_rejects_duplicate_declaration_indices_before_binding() {
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(4, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", widget.source().clone());
    let duplicate = source_declaration(0, "widget_other", "widget_other", widget.source().clone());
    let declarations = [declaration.clone()];
    let duplicates = [declaration.clone(), duplicate];
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(widget.source().clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = vec![declared_signature(&acme_key, snapshot.content_digest())];
    let store = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            widget.source().clone(),
            acme,
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let duplicate_input = verification_input(
        &duplicates,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verification_refusal = refuse_snapshot(&store, &duplicate_input);
    assert!(matches!(
        verification_refusal.condition(),
        RegistryError::DeclarationInvalid {
            field: "source declaration index",
            ..
        }
    ));

    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let verified = admit_snapshot(&store, &input);
    let record = record_of(&widget, &snapshot, &declaration);
    let lockfile = lockfile_of(std::slice::from_ref(&record));
    let binding_refusal = refuse(
        verified.bind_lockfile(&lockfile, &duplicates),
        "duplicate declaration indices cannot produce an evidence gate",
    );
    assert!(matches!(
        binding_refusal.condition(),
        RegistryError::DeclarationInvalid {
            field: "source declaration index",
            ..
        }
    ));
}

/// `GNT-27.1-immutable-source-identity-and-source-kind-vocabulary` classifies an attempted
/// registry-to-path substitution as a source-kind fallback rather than an absent source.
#[test]
fn gnt_27_1_classifies_cross_kind_substitution_as_fallback() {
    let declared = registry_source("acme", "widget");
    let declaration = source_declaration(0, "widget", "widget", declared.clone());
    let declarations = [declaration.clone()];
    let requested = accept(
        SourceIdentity::path("registry:acme-registry"),
        "the attempted path substitution has a valid identity spelling",
    );

    let refusal = refuse(
        resolve_source(&declarations, &declaration, &requested),
        "a different source kind cannot satisfy the declared registry source",
    );
    assert_eq!(
        refusal.code(),
        Some(RegistryDiagnosticCode::SourceKindFallback)
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::SourceKindFallback {
            declared: SourceKind::Registry,
            requested: SourceKind::Path,
            ..
        }
    ));
}

/// `GNT-27.7` retains every authenticated advisory fact for its source and root policy, so
/// omitted or extra facts refuse both online and offline verification rather than defaulting to
/// an empty advisory set.
#[test]
fn gnt_27_7_retains_authenticated_advisory_lifecycle_facts() {
    let source = registry_source("acme", "widget");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let root = root(
        "acme-root",
        source.clone(),
        acme.clone(),
        scope_of_package("acme", "widget"),
    );
    let trust = store_of(
        std::slice::from_ref(&root),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let ledger = ledger_of(&declaration, &snapshot);
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];
    let advisory = accept(
        SecurityAdvisory::new(
            "GNT-27.10-advisory-lifecycle",
            accept(
                AdvisoryScope::new(
                    source.clone(),
                    "acme",
                    "widget",
                    "1.0.0",
                    &[accept(
                        TargetArtifact::new(TargetKind::Library, digest("artifact-a")),
                        "the advisory target artifact is valid",
                    )],
                ),
                "the advisory scope is valid",
            ),
            Severity::AdvisoryOnly,
        ),
        "the authenticated advisory is valid",
    );
    let mut advisories = AdvisoryStore::new();
    admit(
        advisories.admit(
            &declaration,
            advisory.clone(),
            declared_signature(&acme_key, advisory.digest()),
            acme.clone(),
            &trust,
            snapshot.sequence(),
        ),
        "the authenticated advisory is admitted",
    );
    let retained = RetainedState::for_source(source.clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest())
        .with_lifecycle_root_policy(RootSelectionPolicy::Unspecified)
        .with_advisory_fact(advisory.digest());
    let online = verification_input_with_advisories(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
        advisories.clone(),
    )
    .with_snapshot_declaration(declaration.index());
    let verified = admit_snapshot(&trust, &online);
    assert_eq!(
        trust.retained_state(&verified).advisory_facts(),
        &[advisory.digest()]
    );
    let empty_replacement = AdvisoryStore::new();
    let replacement_advisory = accept(
        SecurityAdvisory::new(
            "GNT-27.10-substituted-advisory",
            accept(
                AdvisoryScope::new(
                    source.clone(),
                    "acme",
                    "widget",
                    "1.0.0",
                    &[accept(
                        TargetArtifact::new(TargetKind::Library, digest("artifact-a")),
                        "the substituted advisory target artifact is valid",
                    )],
                ),
                "the substituted advisory scope is valid",
            ),
            Severity::AdvisoryOnly,
        ),
        "the substituted advisory is valid",
    );
    let mut different_replacement = AdvisoryStore::new();
    admit(
        different_replacement.admit(
            &declaration,
            replacement_advisory.clone(),
            declared_signature(&acme_key, replacement_advisory.digest()),
            acme,
            &trust,
            snapshot.sequence(),
        ),
        "the substituted advisory is independently authenticated",
    );
    assert!(empty_replacement.is_empty());
    assert!(!different_replacement.is_empty());
    assert_ne!(
        verified.advisory_facts(),
        &[replacement_advisory.digest()],
        "the verified snapshot retains the accepted set rather than later evidence"
    );
    assert_eq!(
        trust.retained_state(&verified).advisory_facts(),
        &[advisory.digest()],
        "durable state cannot be replaced by empty or different fresh evidence"
    );
    let offline_witness = accept(
        verified.offline_witness(declaration.identity(), 150),
        "the verified snapshot mints an offline witness",
    );
    let offline = verification_input_with_advisories(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::offline(offline_witness),
        advisories.clone(),
    )
    .with_snapshot_declaration(declaration.index());
    admit_snapshot(&trust, &offline);

    for incomplete in [
        RetainedState::for_source(source.clone(), snapshot.sequence())
            .with_content(snapshot.sequence(), snapshot.content_digest())
            .with_lifecycle_root_policy(RootSelectionPolicy::Unspecified),
        retained
            .clone()
            .with_advisory_fact(digest("extra-advisory-fact")),
    ] {
        let input = verification_input_with_advisories(
            std::slice::from_ref(&declaration),
            &snapshot,
            &signatures,
            std::slice::from_ref(&incomplete),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
            advisories.clone(),
        )
        .with_snapshot_declaration(declaration.index());
        let refusal = refuse_snapshot(&trust, &input);
        assert!(matches!(
            refusal.condition(),
            RegistryError::RetainedLifecycleFactsMissing { .. }
        ));
        assert_eq!(
            refusal.reason(),
            TrustFailureReason::RetainedLifecycleFactsMissing
        );
        assert_eq!(refusal.declaration_index(), declaration.index());
    }
}

/// `GNT-27.3`, `GNT-27.7`, and `GNT-27.13` require a verification caller to present
/// advisory evidence explicitly and require every entry to match its declaration's exact
/// source and package subject rather than borrowing a same-source declaration.
#[test]
fn gnt_27_explicit_advisories_and_exact_package_subjects_fail_closed() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let declaration = accept(
        source_declaration_for(0, "widget_alias", "widget", source.clone()),
        "an alias may differ from the exact package subject",
    );
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme,
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source.clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];

    let declared_empty = verification_input(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    let verified = admit_snapshot(&trust, &declared_empty);
    let witness = accept(
        verified.offline_witness(declaration.identity(), 150),
        "the explicitly evidenced snapshot mints an offline witness",
    );

    for freshness in [FreshnessMode::online(), FreshnessMode::offline(witness)] {
        let omitted = VerificationInput::new(
            std::slice::from_ref(&declaration),
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(150),
            freshness,
        )
        .with_snapshot_declaration(declaration.index());
        let refusal = refuse_snapshot(&trust, &omitted);
        assert!(matches!(
            refusal.condition(),
            RegistryError::RetainedLifecycleFactsMissing { .. }
        ));
        assert!(refusal.is_bound());
        assert_eq!(refusal.declaration_index(), declaration.index());
    }

    let forged = [DeclaredSignature::declared(
        acme_key.key().clone(),
        digest("forged"),
    )];
    let precedence = VerificationInput::new(
        std::slice::from_ref(&declaration),
        &snapshot,
        &forged,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    assert!(matches!(
        refuse_snapshot(&trust, &precedence).condition(),
        RegistryError::RetainedLifecycleFactsMissing { .. }
    ));

    let mismatched = accept(
        source_declaration_for(1, "widget_alias", "gadget", source.clone()),
        "the mismatched subject declaration is structurally valid",
    );
    let empty = PublicationLedger::new();
    let mismatch = verification_input(
        std::slice::from_ref(&mismatched),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &empty,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let refusal = refuse_snapshot(&trust, &mismatch);
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { .. }
    ));
    assert!(!refusal.is_bound());
    assert_eq!(refusal.declaration_identity(), &source);
    assert!(empty.is_empty());
}

/// `GNT-27.3` and `GNT-27.7` reject an advisory proof unless its authenticated canonical set
/// binds the exact source, snapshot sequence, root policy, and signature; an omitted set still
/// has precedence over every signature failure.
#[test]
fn gnt_27_advisory_set_proofs_reject_truncation_forgery_and_rebinding() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let declaration = accept(
        source_declaration_for(0, "widget_alias", "widget", source.clone()),
        "the proof fixture declaration owns the widget package subject",
    );
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let ledger = ledger_of(&declaration, &snapshot);
    let retained = RetainedState::for_source(source.clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];

    let advisory = accept(
        SecurityAdvisory::new(
            "GNT-27-advisory-proof",
            accept(
                AdvisoryScope::new(
                    source.clone(),
                    "acme",
                    "widget",
                    "1.0.0",
                    &[accept(
                        TargetArtifact::new(TargetKind::Library, digest("artifact-a")),
                        "the advisory target artifact is valid",
                    )],
                ),
                "the advisory scope is valid",
            ),
            Severity::AdvisoryOnly,
        ),
        "the advisory is valid",
    );
    let advisory_signature = declared_signature(&acme_key, advisory.digest());
    let mut complete = AdvisoryStore::new();
    admit(
        complete.admit(
            &declaration,
            advisory,
            advisory_signature,
            acme.clone(),
            &trust,
            snapshot.sequence(),
        ),
        "the advisory is authenticated",
    );
    let complete_proof = AdvisorySetProof::authenticated(
        &snapshot,
        &complete,
        RootSelectionPolicy::Unspecified,
        acme.clone(),
        &acme_key,
    );
    let truncated = VerificationInput::new(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_advisory_proof(AdvisoryStore::new(), complete_proof)
    .with_snapshot_declaration(declaration.index());
    assert!(matches!(
        refuse_snapshot(&trust, &truncated).condition(),
        RegistryError::SignatureUnverified { .. }
    ));

    let empty = AdvisoryStore::new();
    let forged = AdvisorySetProof::authenticated(
        &snapshot,
        &empty,
        RootSelectionPolicy::Unspecified,
        acme.clone(),
        &key("forged-key"),
    );
    let forged = VerificationInput::new(
        std::slice::from_ref(&declaration),
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_advisory_proof(empty, forged)
    .with_snapshot_declaration(declaration.index());
    assert!(matches!(
        refuse_snapshot(&trust, &forged).condition(),
        RegistryError::SignatureUnverified { .. }
    ));

    let foreign_entry = entry(
        "other",
        "widget",
        "1.0.0",
        &acme,
        "manifest-b",
        "artifact-b",
    );
    let foreign = snapshot_of(5, 100, 200, std::slice::from_ref(&foreign_entry));
    let wrong_source = AdvisorySetProof::authenticated(
        &foreign,
        &AdvisoryStore::new(),
        RootSelectionPolicy::Unspecified,
        acme.clone(),
        &acme_key,
    );
    let wrong_sequence = AdvisorySetProof::authenticated(
        &snapshot_of(6, 100, 200, std::slice::from_ref(&widget)),
        &AdvisoryStore::new(),
        RootSelectionPolicy::Unspecified,
        acme.clone(),
        &acme_key,
    );
    let selected_policy = RootSelectionPolicy::selected(accept(
        RootId::new("acme-root"),
        "the selected root is valid",
    ));
    let wrong_policy = AdvisorySetProof::authenticated(
        &snapshot,
        &AdvisoryStore::new(),
        selected_policy,
        acme,
        &acme_key,
    );
    for proof in [wrong_source, wrong_sequence, wrong_policy] {
        let input = VerificationInput::new(
            std::slice::from_ref(&declaration),
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &ledger,
            EpochObservation::at(150),
            FreshnessMode::online(),
        )
        .with_advisory_proof(AdvisoryStore::new(), proof)
        .with_snapshot_declaration(declaration.index());
        assert!(matches!(
            refuse_snapshot(&trust, &input).condition(),
            RegistryError::SignatureUnverified { .. }
        ));
    }

    let forged_snapshot_signatures = [DeclaredSignature::declared(
        acme_key.key().clone(),
        digest("forged"),
    )];
    let omitted = VerificationInput::new(
        std::slice::from_ref(&declaration),
        &snapshot,
        &forged_snapshot_signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(declaration.index());
    assert!(matches!(
        refuse_snapshot(&trust, &omitted).condition(),
        RegistryError::RetainedLifecycleFactsMissing { .. }
    ));
}

/// `GNT-27.3` binds an advisory completeness proof's claimed publisher to the key that signed
/// it, even when a different known key can otherwise verify the proof payload.
#[test]
fn gnt_27_advisory_proof_rejects_a_known_key_for_another_publisher() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let reviewer_key = key("reviewer-key");
    let acme = publisher("acme", "acme-key");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        )),
        &[acme_key.clone(), reviewer_key.clone()],
        &[],
    );
    let retained = RetainedState::for_source(source, snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];
    let proof = AdvisorySetProof::authenticated(
        &snapshot,
        &AdvisoryStore::new(),
        RootSelectionPolicy::Unspecified,
        acme,
        &reviewer_key,
    );
    let refusal = refuse_snapshot(
        &trust,
        &VerificationInput::new(
            std::slice::from_ref(&declaration),
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &PublicationLedger::new(),
            EpochObservation::at(150),
            FreshnessMode::online(),
        )
        .with_advisory_proof(AdvisoryStore::new(), proof),
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::PublisherUnauthorized {
            defect: AuthorizationDefect::UnverifiedSigner,
            ..
        }
    ));
    assert_eq!(refusal.declaration_index(), declaration.index());
}

/// `GNT-27.3` authorizes the proof publisher across every consumed package, not only the first
/// entry that happened to anchor the snapshot.
#[test]
fn gnt_27_advisory_proof_authority_covers_every_snapshot_entry() {
    let source = registry_source("acme", "workspace");
    let acme_key = key("acme-key");
    let reviewer_key = key("reviewer-key");
    let acme = publisher("acme", "acme-key");
    let reviewer = publisher("reviewer", "reviewer-key");
    let widget = entry_for_source(
        source.clone(),
        "acme",
        "widget",
        "1.0.0",
        &acme,
        "manifest-widget",
        "artifact-widget",
        digest("source-widget"),
    );
    let gadget = entry_for_source(
        source.clone(),
        "acme",
        "gadget",
        "1.0.0",
        &acme,
        "manifest-gadget",
        "artifact-gadget",
        digest("source-gadget"),
    );
    let snapshot = snapshot_of(5, 100, 200, &[widget, gadget]);
    let widget_declaration = source_declaration(0, "widget", "widget", source.clone());
    let gadget_declaration = source_declaration(1, "gadget", "gadget", source.clone());
    let declarations = [widget_declaration.clone(), gadget_declaration.clone()];
    let reviewer_delegation = delegation(
        source.clone(),
        acme.clone(),
        reviewer.clone(),
        scope_of_package("acme", "widget"),
        1,
        &acme_key,
    );
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme.clone(),
            scope_of_namespace("acme"),
        )),
        &[acme_key.clone(), reviewer_key.clone()],
        std::slice::from_ref(&reviewer_delegation),
    );
    let retained = RetainedState::for_source(source, snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];
    let proof = AdvisorySetProof::authenticated(
        &snapshot,
        &AdvisoryStore::new(),
        RootSelectionPolicy::Unspecified,
        reviewer,
        &reviewer_key,
    );
    let refusal = refuse_snapshot(
        &trust,
        &VerificationInput::new(
            &declarations,
            &snapshot,
            &signatures,
            std::slice::from_ref(&retained),
            &PublicationLedger::new(),
            EpochObservation::at(150),
            FreshnessMode::online(),
        )
        .with_advisory_proof(AdvisoryStore::new(), proof),
    );
    assert!(matches!(
        refusal.condition(),
        RegistryError::DelegationOutOfScope { .. }
    ));
    assert_eq!(refusal.declaration_index(), gadget_declaration.index());
}

/// `GNT-27.7` permits a newly proven current advisory set to advance an older authenticated
/// retained set; the verifier compares retained lifecycle facts at the retained sequence while
/// preserving the normal rollback and freeze checks for the new snapshot.
#[test]
fn gnt_27_advisory_proof_advances_an_older_retained_set() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme.clone(),
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let previous_entry = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let previous = snapshot_of(4, 100, 200, std::slice::from_ref(&previous_entry));
    let previous_signatures = [declared_signature(&acme_key, previous.content_digest())];
    let initial_retained = RetainedState::for_source(source.clone(), 0);
    let previous_ledger = PublicationLedger::new();
    let previous_input = verification_input(
        std::slice::from_ref(&declaration),
        &previous,
        &previous_signatures,
        std::slice::from_ref(&initial_retained),
        &previous_ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    );
    let previous_verified = admit_snapshot(&trust, &previous_input);
    let retained = trust.retained_state(&previous_verified);

    let current_entry = entry("acme", "widget", "1.1.0", &acme, "manifest-b", "artifact-b");
    let current = snapshot_of(5, 150, 250, std::slice::from_ref(&current_entry));
    let advisory = accept(
        SecurityAdvisory::new(
            "GNT-27-current-advisory",
            accept(
                AdvisoryScope::new(
                    source,
                    "acme",
                    "widget",
                    "1.1.0",
                    &[accept(
                        TargetArtifact::new(TargetKind::Library, digest("artifact-b")),
                        "the current advisory target is valid",
                    )],
                ),
                "the current advisory scope is valid",
            ),
            Severity::AdvisoryOnly,
        ),
        "the current advisory is valid",
    );
    let mut advisories = AdvisoryStore::new();
    admit(
        advisories.admit(
            &declaration,
            advisory.clone(),
            declared_signature(&acme_key, advisory.digest()),
            acme,
            &trust,
            current.sequence(),
        ),
        "the current advisory is authenticated",
    );
    let current_signatures = [declared_signature(&acme_key, current.content_digest())];
    let current_ledger = PublicationLedger::new();
    let current_input = verification_input_with_advisories(
        std::slice::from_ref(&declaration),
        &current,
        &current_signatures,
        std::slice::from_ref(&retained),
        &current_ledger,
        EpochObservation::at(175),
        FreshnessMode::online(),
        advisories.clone(),
    );
    let current_verified = admit_snapshot(&trust, &current_input);
    assert_eq!(
        trust.retained_state(&current_verified).advisory_facts(),
        &[advisory.digest()]
    );
}

/// `GNT-27.13` refuses a snapshot-wide evidence attribution that names a same-source
/// declaration for another package instead of blaming that declaration for the failure.
#[test]
fn gnt_27_snapshot_evidence_rejects_a_same_source_wrong_subject_attribution() {
    let source = registry_source("acme", "widget");
    let acme_key = key("acme-key");
    let acme = publisher("acme", "acme-key");
    let widget = entry("acme", "widget", "1.0.0", &acme, "manifest-a", "artifact-a");
    let snapshot = snapshot_of(5, 100, 200, std::slice::from_ref(&widget));
    let declaration = source_declaration(0, "widget", "widget", source.clone());
    let wrong_subject = source_declaration(1, "gadget", "gadget", source.clone());
    let declarations = [declaration.clone(), wrong_subject.clone()];
    let trust = store_of(
        std::slice::from_ref(&root(
            "acme-root",
            source.clone(),
            acme,
            scope_of_package("acme", "widget"),
        )),
        std::slice::from_ref(&acme_key),
        &[],
    );
    let retained = RetainedState::for_source(source.clone(), snapshot.sequence())
        .with_content(snapshot.sequence(), snapshot.content_digest());
    let signatures = [declared_signature(&acme_key, snapshot.content_digest())];
    let ledger = PublicationLedger::new();
    let input = verification_input(
        &declarations,
        &snapshot,
        &signatures,
        std::slice::from_ref(&retained),
        &ledger,
        EpochObservation::at(150),
        FreshnessMode::online(),
    )
    .with_snapshot_declaration(wrong_subject.index());
    let refusal = refuse_snapshot(&trust, &input);
    assert!(matches!(
        refusal.condition(),
        RegistryError::AttributionMissing { .. }
    ));
    assert!(!refusal.is_bound());
    assert_eq!(refusal.declaration_identity(), &source);
}

/// The committed registry-trust note names every clause anchor and non-claim the model publishes.
/// The check is deliberately narrow: it pins the declared names so a renamed or added clause or
/// non-claim cannot leave the note stale, and it says nothing about the note's wording, which the
/// clause lanes above cover.
#[test]
fn registry_trust_note_names_every_declared_clause_and_non_claim() {
    let note = fs::read_to_string(workspace_root().join("docs/registry-trust.md"))
        .unwrap_or_else(|error| panic!("the registry note is readable: {error}"));
    for clause in REGISTRY_CLAUSES {
        assert!(note.contains(clause), "the note names `{clause}`");
    }
    for claim in RegistryNonClaim::ALL {
        assert!(
            note.contains(claim.wire_name()),
            "the note names `{}`",
            claim.wire_name()
        );
    }
}

/// `GNT-27.2` inherits the identifier bound, and the model declares that bound once: a name of
/// exactly `REGISTRY_NAME_SCALAR_LIMIT` scalars is canonical, one more scalar is refused as too long
/// rather than truncated, normalized, or accepted as a second name, and the kind stays part of the
/// identity at the boundary.
#[test]
fn gnt_27_2_name_scalar_bound_is_inclusive_and_refuses_one_more_scalar() {
    let boundary = "a".repeat(REGISTRY_NAME_SCALAR_LIMIT);
    assert_eq!(boundary.chars().count(), REGISTRY_NAME_SCALAR_LIMIT);
    let package = name(RegistryNameKind::Package, &boundary);
    let namespace = name(RegistryNameKind::Namespace, &boundary);
    assert_ne!(package, namespace);

    let overlong = format!("{boundary}a");
    let refused = reject(
        RegistryName::new(RegistryNameKind::Package, &overlong),
        "an overlong publication name",
    );
    assert!(matches!(
        refused,
        RegistryError::NameMalformed {
            defect: NameDefect::TooLong,
            ..
        }
    ));
    assert_eq!(
        refused.trust_failure_reason(),
        TrustFailureReason::MalformedPublicationName
    );
    assert_eq!(
        refused.clause(),
        "GNT-27.2-canonical-publication-names-and-external-name-mapping"
    );
}
