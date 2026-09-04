#!/usr/bin/env python3
"""Assemble and verify Gantry's coherent publishable Rust package set."""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "target/package-set-verify"
VERSION = "0.1.0"
REPOSITORY = "https://github.com/NFJones/gantry"

PACKAGES = [
    "gantry-core",
    "gantry-frontend",
    "gantry-host",
    "gantry-ir",
    "gantry-observe",
    "gantry-analysis",
    "gantry-adapter-tokio",
    "gantry-storage-sqlite",
    "gantry-runtime",
    "gantry",
]

DEPENDENCIES = {
    "gantry-core": [],
    "gantry-frontend": ["gantry-core"],
    "gantry-host": ["gantry-core"],
    "gantry-ir": ["gantry-core"],
    "gantry-observe": ["gantry-core", "gantry-host"],
    "gantry-analysis": ["gantry-core", "gantry-frontend", "gantry-ir"],
    "gantry-adapter-tokio": ["gantry-host"],
    "gantry-storage-sqlite": ["gantry-core", "gantry-host"],
    "gantry-runtime": ["gantry-core", "gantry-host", "gantry-ir", "gantry-observe"],
    "gantry": [
        "gantry-analysis",
        "gantry-core",
        "gantry-frontend",
        "gantry-host",
        "gantry-ir",
        "gantry-observe",
        "gantry-runtime",
    ],
}


def run(arguments: list[str], *, cwd: Path = ROOT) -> None:
    subprocess.run(arguments, cwd=cwd, check=True)


def package_metadata() -> dict[str, dict]:
    output = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(output.stdout)
    return {package["name"]: package for package in metadata["packages"]}


def validate_metadata(packages: dict[str, dict]) -> None:
    for name in PACKAGES:
        package = packages[name]
        if package["version"] != VERSION:
            raise SystemExit(f"{name} version differs")
        if package["publish"] == []:
            raise SystemExit(f"{name} is not publishable")
        if package["repository"] != REPOSITORY:
            raise SystemExit(f"{name} repository metadata differs")
        if not package["description"] or not package["documentation"]:
            raise SystemExit(f"{name} human package metadata is incomplete")
        internal = sorted(
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["name"] in PACKAGES
        )
        if internal != DEPENDENCIES[name]:
            raise SystemExit(
                f"{name} package dependencies differ: expected {DEPENDENCIES[name]}, found {internal}"
            )
        for dependency in package["dependencies"]:
            if dependency["name"] in PACKAGES and dependency["req"] != f"={VERSION}":
                raise SystemExit(f"{name} does not exactly pin {dependency['name']}")


def assemble() -> dict[str, Path]:
    shutil.rmtree(TARGET, ignore_errors=True)
    archives = TARGET / "archives"
    unpacked = TARGET / "unpacked"
    archives.mkdir(parents=True)
    unpacked.mkdir()
    result: dict[str, Path] = {}
    for name in PACKAGES:
        arguments = [
            "cargo",
            "package",
            "--locked",
            "--allow-dirty",
            "--no-verify",
            "--target-dir",
            str(TARGET / "cargo-target"),
            "-p",
            name,
        ]
        for dependency in DEPENDENCIES[name]:
            arguments.extend(
                [
                    "--config",
                    f'patch.crates-io.{dependency}.path="crates/{dependency}"',
                ]
            )
        run(arguments)
        source = TARGET / f"cargo-target/package/{name}-{VERSION}.crate"
        if not source.is_file():
            raise SystemExit(f"Cargo did not produce {source}")
        archive = archives / source.name
        shutil.copy2(source, archive)
        with tarfile.open(archive) as package:
            package.extractall(unpacked, filter="data")
        package_root = unpacked / f"{name}-{VERSION}"
        if not (package_root / "Cargo.toml").is_file() or not (package_root / "src").is_dir():
            raise SystemExit(f"{name} archive omits normalized manifest or sources")
        normalized = tomllib.loads((package_root / "Cargo.toml").read_text(encoding="utf-8"))
        if normalized["package"].get("repository") != REPOSITORY:
            raise SystemExit(f"{name} normalized repository metadata differs")
        result[name] = package_root
    return result


def verify_together(package_roots: dict[str, Path]) -> None:
    consumer = TARGET / "consumer"
    (consumer / "src").mkdir(parents=True)
    patches = "\n".join(
        f'{name} = {{ path = {json.dumps(str(path))} }}'
        for name, path in package_roots.items()
        if name != "gantry"
    )
    manifest = f"""[package]
name = "gantry-package-set-verifier"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
gantry = {{ path = {json.dumps(str(package_roots['gantry']))}, default-features = false, features = ["concurrent", "durable"] }}
gantry-adapter-tokio = {{ path = {json.dumps(str(package_roots['gantry-adapter-tokio']))} }}
gantry-storage-sqlite = {{ path = {json.dumps(str(package_roots['gantry-storage-sqlite']))} }}

[patch.crates-io]
{patches}
"""
    (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (consumer / "src/lib.rs").write_text(
        "pub fn packaged_surface() {\n"
        "    let features = gantry::compiled_features();\n"
        "    assert!(features.concurrent && features.durable);\n"
        "    let _ = gantry_adapter_tokio::TokioExecutor::new;\n"
        "    let _ = std::mem::size_of::<gantry_storage_sqlite::SqliteJournalStore>();\n"
        "}\n",
        encoding="utf-8",
    )
    run(["cargo", "check", "--offline", "--all-targets"], cwd=consumer)


def main() -> None:
    packages = package_metadata()
    validate_metadata(packages)
    package_roots = assemble()
    verify_together(package_roots)
    print("publishable Gantry package set is current")


if __name__ == "__main__":
    main()
