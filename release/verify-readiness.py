#!/usr/bin/env python3
"""Verify Gantry's final qualified release-readiness record."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RECORD_PATH = ROOT / "release/readiness-v1.json"

PROFILES = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
]

PUBLISHABLE_LIBRARIES = [
    "gantry",
    "gantry-adapter-tokio",
    "gantry-analysis",
    "gantry-core",
    "gantry-frontend",
    "gantry-host",
    "gantry-ir",
    "gantry-observe",
    "gantry-runtime",
    "gantry-storage-sqlite",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_digest(entry: dict[str, object]) -> None:
    path = ROOT / str(entry["path"])
    if sha256(path) != entry["sha256"]:
        raise SystemExit(f"readiness input digest differs: {entry['path']}")


def cargo_metadata() -> dict[str, dict]:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    return {package["name"]: package for package in metadata["packages"]}


def main() -> None:
    record = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    if record["format"] != "gantry.release-readiness/v1":
        raise SystemExit("readiness format differs")
    if record["status"] != "qualified-release-ready":
        raise SystemExit("readiness must remain qualified")
    if record["unqualified_full_v1"] is not False:
        raise SystemExit("unqualified full-v1 claim is not permitted")

    source_revision = record["source_revision"]
    subprocess.run(
        ["git", "cat-file", "-e", f"{source_revision}^{{commit}}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_revision, "HEAD"],
        cwd=ROOT,
        check=True,
    )
    if sha256(ROOT / "SPEC.md") != record["specification_sha256"]:
        raise SystemExit("readiness specification digest differs")

    publication = record["publication"]
    index_path = ROOT / publication["index_path"]
    if sha256(index_path) != publication["publication_set_identity"]:
        raise SystemExit("readiness publication identity differs")
    verification_entry = {
        "path": publication["verification_path"],
        "sha256": publication["verification_sha256"],
    }
    require_digest(verification_entry)
    verification = json.loads((ROOT / publication["verification_path"]).read_text())
    if verification["publication_set_identity"] != publication["publication_set_identity"]:
        raise SystemExit("publication verification report differs")

    conformance = record["conformance"]
    require_digest(conformance["requirement_registry"])
    require_digest(conformance["manifest"])
    require_digest(conformance["combined_gate"])
    manifest = json.loads((ROOT / conformance["manifest"]["path"]).read_text())
    if manifest["profile_results"] != conformance["profile_results"]:
        raise SystemExit("profile readiness results differ")
    if [result["profile"] for result in conformance["profile_results"]] != PROFILES:
        raise SystemExit("profile readiness membership differs")
    if any(result["status"] != "verified" for result in conformance["profile_results"]):
        raise SystemExit("a profile result is not verified")
    combined = json.loads((ROOT / conformance["combined_gate"]["path"]).read_text())
    if (
        combined["gate"] != conformance["combined_gate"]["gate"]
        or combined["status"] != "verified"
        or combined["claim"]["advertises_profiles"] != PROFILES
        or conformance["combined_gate"]["advertises_profiles"] != PROFILES
    ):
        raise SystemExit("combined readiness gate differs")

    packaging = record["packaging"]
    if packaging["version"] != "0.1.0":
        raise SystemExit("package-set version differs")
    if packaging["publishable_libraries"] != PUBLISHABLE_LIBRARIES:
        raise SystemExit("publishable library set differs")
    if packaging["private_packages"] != ["gantry-cli", "gantry-conformance", "xtask"]:
        raise SystemExit("private package set differs")
    require_digest(packaging["package_verifier"])
    if packaging["verified_toolchains"] != ["1.91.0", "1.97.1", "stable"]:
        raise SystemExit("package verification toolchains differ")
    packages = cargo_metadata()
    for name in PUBLISHABLE_LIBRARIES:
        package = packages[name]
        if package["version"] != "0.1.0" or package["publish"] == []:
            raise SystemExit(f"publishable package metadata differs: {name}")
        if not package["description"] or not package["documentation"] or not package["repository"]:
            raise SystemExit(f"publishable package metadata is incomplete: {name}")
    for name in packaging["private_packages"]:
        if packages[name]["publish"] != []:
            raise SystemExit(f"private package became publishable: {name}")
    cli = packaging["cli"]
    if (
        cli["package"] != "gantry-cli"
        or cli["binary"] != "gantry"
        or cli["distribution"] != "source-build"
        or cli["release_build"] != "passed"
        or cli["smoke_exit"] != 0
        or cli["smoke_stdout"] != "gantry: agent-control language for Mezzanine"
    ):
        raise SystemExit("CLI packaging evidence differs")

    matrix_entry = {"path": record["matrix"]["path"], "sha256": record["matrix"]["sha256"]}
    require_digest(matrix_entry)
    matrix_verifier = {
        "path": record["matrix"]["verifier_path"],
        "sha256": record["matrix"]["verifier_sha256"],
    }
    require_digest(matrix_verifier)
    subprocess.run(["python3", record["matrix"]["verifier_path"]], cwd=ROOT, check=True)
    matrix = json.loads((ROOT / record["matrix"]["path"]).read_text())
    if matrix["overall_status"] != record["matrix"]["status"]:
        raise SystemExit("matrix readiness status differs")
    passed = [cell["id"] for cell in matrix["product_cells"] if cell["status"] == "passed"]
    blocked = [cell["id"] for cell in matrix["product_cells"] if cell["status"] == "blocked"]
    if passed != record["matrix"]["passed_cells"] or blocked != record["matrix"]["blocked_cells"]:
        raise SystemExit("matrix cell classification differs")
    if matrix["publication"]["publication_set_identity"] != publication["publication_set_identity"]:
        raise SystemExit("matrix publication binding differs")
    if matrix["publication"]["source_revision"] != source_revision:
        raise SystemExit("matrix source binding differs")

    claim = record["claim"]
    if claim["role"] != "implementation" or claim["profiles"] != PROFILES:
        raise SystemExit("qualified implementation claim differs")
    if claim["platforms"] != ["linux-x86_64-unknown-linux-gnu"]:
        raise SystemExit("qualified platform claim differs")
    if claim["qualification"][:3] != matrix["claim_limits"]:
        raise SystemExit("readiness claim limits differ from the matrix")
    if len(claim["qualification"]) != 4 or "not permitted" not in claim["qualification"][3]:
        raise SystemExit("unqualified readiness prohibition is absent")

    print("qualified Gantry v1 release readiness is current")


if __name__ == "__main__":
    main()
