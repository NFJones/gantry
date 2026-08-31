//! Builds the subprocess-only SQLite fault-injection helper.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=tests/fixtures/sqlite_fault_helper.c");
    println!("cargo:rustc-check-cfg=cfg(gantry_sqlite_fault_helper)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    if !matches!(target_os.as_str(), "linux" | "macos") || host != target {
        return;
    }

    let (include, library) = bundled_sqlite_metadata();
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("tests/fixtures/sqlite_fault_helper.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default())
        .join("gantry-sqlite-fault-helper");
    let compiler = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));

    let mut command = Command::new(compiler);
    command
        .arg("-std=c11")
        .arg("-O0")
        .arg("-w")
        .arg("-DSQLITE_CORE")
        .arg("-DSQLITE_DEFAULT_FOREIGN_KEYS=1")
        .arg("-DSQLITE_ENABLE_API_ARMOR")
        .arg("-DSQLITE_ENABLE_COLUMN_METADATA")
        .arg("-DSQLITE_ENABLE_DBSTAT_VTAB")
        .arg("-DSQLITE_ENABLE_FTS3")
        .arg("-DSQLITE_ENABLE_FTS3_PARENTHESIS")
        .arg("-DSQLITE_ENABLE_FTS5")
        .arg("-DSQLITE_ENABLE_JSON1")
        .arg("-DSQLITE_ENABLE_LOAD_EXTENSION=1")
        .arg("-DSQLITE_ENABLE_MEMORY_MANAGEMENT")
        .arg("-DSQLITE_ENABLE_RTREE")
        .arg("-DSQLITE_ENABLE_STAT4")
        .arg("-DSQLITE_SOUNDEX")
        .arg("-DSQLITE_THREADSAFE=1")
        .arg("-DSQLITE_USE_URI")
        .arg("-DHAVE_USLEEP=1")
        .arg("-DHAVE_ISNAN")
        .arg("-D_POSIX_THREAD_SAFE_FUNCTIONS")
        .arg("-I")
        .arg(&include)
        .arg(&source)
        .arg(&library)
        .arg("-o")
        .arg(&output)
        .arg("-lpthread")
        .arg("-lm");
    if target_os == "linux" {
        command.arg("-ldl");
    }
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("could not execute SQLite fault-helper compiler: {error}"));
    assert!(status.success(), "SQLite fault-helper compilation failed");

    println!("cargo:rustc-cfg=gantry_sqlite_fault_helper");
    println!(
        "cargo:rustc-env=GANTRY_SQLITE_FAULT_HELPER={}",
        output.display()
    );
}

fn bundled_sqlite_metadata() -> (PathBuf, PathBuf) {
    let out_directory = PathBuf::from(
        env::var_os("OUT_DIR").unwrap_or_else(|| panic!("Cargo did not provide OUT_DIR")),
    );
    let build_directory = out_directory
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("conformance output has no Cargo build directory"));
    let entries = fs::read_dir(build_directory)
        .unwrap_or_else(|error| panic!("could not inspect Cargo build metadata: {error}"));
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("libsqlite3-sys-")
        {
            continue;
        }
        let metadata = entry.path().join("output");
        let Ok(contents) = fs::read_to_string(metadata) else {
            continue;
        };
        let Some(library_directory) = contents
            .lines()
            .find_map(|line| line.strip_prefix("cargo:lib_dir="))
            .map(PathBuf::from)
            .filter(|path| path.join("libsqlite3.a").is_file())
        else {
            continue;
        };
        let Some(include) = contents
            .lines()
            .find_map(|line| line.strip_prefix("cargo:include="))
            .map(PathBuf::from)
            .filter(|path| path.join("sqlite3.h").is_file())
        else {
            continue;
        };
        let modified = fs::metadata(library_directory.join("libsqlite3.a"))
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        candidates.push((modified, include, library_directory));
    }
    candidates.sort_by_key(|candidate| candidate.0);
    let (_, include, library_directory) = candidates
        .pop()
        .unwrap_or_else(|| panic!("could not locate Cargo's bundled libsqlite3.a metadata"));
    (include, library_directory.join("libsqlite3.a"))
}
