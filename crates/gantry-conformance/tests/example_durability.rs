//! Executable offline durable and embedding demonstrations, independent of the corpus sweep.

#[path = "../examples/support/mod.rs"]
mod support;

#[path = "../../../examples/embedding/demos.rs"]
mod embedding;

use std::path::Path;

/// Drives real host lifecycle, event delivery and resource-policy examples.
#[test]
fn embedding_demonstrations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/embedding");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .unwrap_or_else(|e| panic!("runtime: {e}"));
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            embedding::lifecycle(&root.join("lifecycle")).await?;
            embedding::observation(&root.join("observation")).await?;
            embedding::resource_policy(&root.join("resource_policy")).await
        })
        .await
        .unwrap_or_else(|_| panic!("embedding timeout"))
        .unwrap_or_else(|e: String| panic!("{e}"));
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
}

/// Checked-in durability packages assert restart results and unchanged rejected prefixes.
#[test]
fn sqlite_restart_demonstrations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/durability");
    let packages = support::discover(&root).unwrap_or_else(|e| panic!("discovery: {e}"));
    assert_eq!(packages.len(), 6);
    for package in packages {
        support::run_package(&package).unwrap_or_else(|e| panic!("{e}"));
    }
}

/// Reject unknown or misplaced durable modes before opening a journal.
#[test]
fn durable_schema_is_closed() {
    for json in [
        r#"{"class":"durable","expected":42,"durable_mode":"crash-magic"}"#,
        r#"{"class":"host","expected":42,"durable_mode":"source-free"}"#,
    ] {
        let case = serde_json::from_str(json).unwrap_or_else(|e| panic!("case: {e}"));
        assert!(support::durable::validate(&case).is_err());
    }
}
