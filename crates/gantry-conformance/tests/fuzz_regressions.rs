//! Deterministic replay for minimized byte-oriented fuzz regressions.

use std::fs;
use std::path::{Path, PathBuf};

use gantry::identity::ProtocolIdentity;

#[test]
fn protocol_identity_fuzz_regressions_remain_nonpanicking() {
    let directory = workspace_root().join("fuzz/regressions/protocol_identity");
    let entries = fs::read_dir(&directory);
    assert!(entries.is_ok(), "could not read {}", directory.display());
    let mut paths = entries
        .unwrap_or_else(|_| unreachable!("checked above"))
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>();
    assert!(paths.is_ok(), "could not enumerate {}", directory.display());
    let paths = paths
        .as_mut()
        .unwrap_or_else(|_| unreachable!("checked above"));
    paths.sort();
    assert!(!paths.is_empty(), "no fuzz regressions are checked in");

    for path in paths {
        let bytes = fs::read(&*path);
        assert!(bytes.is_ok(), "could not read {}", path.display());
        if let Ok(value) = std::str::from_utf8(
            bytes
                .as_deref()
                .unwrap_or_else(|_| unreachable!("checked above")),
        ) {
            let _ = ProtocolIdentity::parse(value.trim_end_matches(['\r', '\n']));
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| unreachable!("conformance crate has a workspace root"))
}
