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
    let library_directory = env::split_paths(
        &env::var_os("LD_LIBRARY_PATH")
            .unwrap_or_else(|| panic!("Cargo did not provide a native library search path")),
    )
    .find(|path| path.join("libsqlite3.a").is_file())
    .unwrap_or_else(|| panic!("could not locate Cargo's bundled libsqlite3.a"));
    let build_directory = library_directory
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("bundled SQLite library path has no Cargo build directory"));
    let expected_library = format!("cargo:lib_dir={}", library_directory.display());
    let entries = fs::read_dir(build_directory)
        .unwrap_or_else(|error| panic!("could not inspect Cargo build metadata: {error}"));
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
        if !contents.lines().any(|line| line == expected_library) {
            continue;
        }
        let include = contents
            .lines()
            .find_map(|line| line.strip_prefix("cargo:include="))
            .map(PathBuf::from)
            .filter(|path| path.join("sqlite3.h").is_file())
            .unwrap_or_else(|| panic!("bundled SQLite metadata has no usable include path"));
        return (include, library_directory.join("libsqlite3.a"));
    }
    panic!("could not match bundled SQLite library to its Cargo metadata");
}
