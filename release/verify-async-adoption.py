#!/usr/bin/env python3
"""Independently verify the qualified executor-backed release adoption."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ADOPTION_PATH = "protocol/conformance/async-execution-adoption-v1.json"
CONTRACT_PATH = "protocol/conformance/async-execution-contract-v1.json"
MATRIX_PATH = "release/release-matrix-v1.json"
PROFILES_PATH = "protocol/catalogs/profiles-v1.json"
READINESS_PATH = "release/readiness-v1.json"

PROFILES = [
    "analyzer",
    "concurrent-evaluator",
    "durable-runtime",
    "embedding",
    "evaluator",
    "frontend",
]
EXPECTED_ASSIGNMENTS = [
    ("GNT-1.0", "clause-001", tuple(PROFILES)),
    ("GNT-1.5", "clause-002", tuple(PROFILES)),
    ("GNT-15.8", "clause-001", ("embedding",)),
    ("GNT-2.1", "clause-001", tuple(PROFILES)),
]
CLAIM_LIMITS = [
    "No local macOS 1.97.1 result is claimed; that cell remains blocked pending hosted CI evidence.",
    "No local macOS rolling-stable result is claimed; that cell remains blocked pending hosted CI evidence.",
    "The Linux WSL2 ext4 run does not establish a stable-media power-loss claim; the SQLite matrix covers deterministic injected cuts and rejects unqualified strict environments.",
]


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def validate_adoption(adoption: dict, specification_sha256: str) -> None:
    if set(adoption) != {
        "format",
        "gate",
        "status",
        "specification_sha256",
        "amended_profiles",
        "advertises_profiles",
        "blocked_by",
    }:
        raise ValueError("async adoption fields differ")
    if (
        adoption["format"] != "gantry.async-execution-adoption/v1"
        or adoption["gate"] != "GNT-ASYNC-GATE-000"
        or adoption["status"] != "verified"
        or adoption["specification_sha256"] != specification_sha256
        or adoption["amended_profiles"] != PROFILES
        or adoption["advertises_profiles"] != PROFILES
        or adoption["blocked_by"]
    ):
        raise ValueError("async adoption is not the exact terminal profile set")


def release_assignments(contract: dict) -> list[tuple[str, str, tuple[str, ...]]]:
    rows = [
        (
            assignment["requirement"],
            assignment["clause"],
            tuple(assignment["profiles"]),
        )
        for assignment in contract["requirement_assignments"]
        if "GNT-ASYNC-REL-001" in assignment["evidence_owners"]
    ]
    return sorted(rows)


def validate_assignments(contract: dict) -> None:
    if release_assignments(contract) != sorted(EXPECTED_ASSIGNMENTS):
        raise ValueError("GNT-ASYNC-REL-001 does not own exactly four frozen assignments")


def validate_migration_boundary() -> None:
    guide = (ROOT / "docs/async-execution-release.md").read_text(encoding="utf-8")
    facade = (ROOT / "crates/gantry/src/lib.rs").read_text(encoding="utf-8")
    required = [
        "no compatibility mode that restores caller polling",
        "rather than manually advancing interpreter steps",
        "source-free resume",
        "without restoring manual driving",
    ]
    if any(text not in guide for text in required):
        raise ValueError("release migration guide omits the no-manual-driving boundary")
    if "ExecutorAdapter" not in facade or "pub use gantry_runtime::Machine" in facade:
        raise ValueError("public facade does not preserve executor ownership")


def validate_publication(specification_sha256: str) -> str:
    index_path = "protocol/publication/index-v1.json"
    report_path = "protocol/publication/verification-v1.json"
    index_bytes = (ROOT / index_path).read_bytes()
    identity = hashlib.sha256(index_bytes).hexdigest()
    index = json.loads(index_bytes)
    report = read_json(report_path)
    if (
        index["publication_revision"] != f"gantry-v1-{specification_sha256}"
        or report["publication_set_identity"] != identity
        or report["index"]
        != {
            "path": index_path,
            "byte_length": str(len(index_bytes)),
            "sha256": identity,
        }
    ):
        raise ValueError("publication index or verification identity differs")
    index_artifacts = {artifact["id"]: artifact for artifact in index["artifacts"]}
    expected_artifacts = {
        "gantry.authoring",
        "gantry.conformance",
        "gantry.embedding",
        "gantry.ir",
        "gantry.journal",
        "gantry.spec",
        "gantry.values",
    }
    report_artifacts = {artifact["id"]: artifact for artifact in report["artifacts"]}
    if set(index_artifacts) != expected_artifacts or set(report_artifacts) != expected_artifacts:
        raise ValueError("publication membership differs")
    for artifact in report["artifacts"]:
        path = artifact["path"]
        data = (ROOT / path).read_bytes()
        if (
            artifact["byte_length"] != str(len(data))
            or artifact["sha256"] != hashlib.sha256(data).hexdigest()
            or index_artifacts[artifact["id"]]["sha256"] != artifact["sha256"]
        ):
            raise ValueError(f"publication artifact differs: {path}")
    return identity


def validate_profiles(profiles: dict, specification_sha256: str) -> None:
    if (
        profiles["catalog"] != "gantry.profiles"
        or profiles["claims_enabled"] is not True
        or profiles["specification_revision"] != specification_sha256
        or [profile["name"] for profile in profiles["profiles"]] != PROFILES
        or "superseded_specification_revision" in profiles
    ):
        raise ValueError("profile activation differs")


def validate_release_records(matrix: dict, readiness: dict, identity: str) -> None:
    publication = matrix["publication"]
    if (
        matrix["overall_status"] != "qualified-passed"
        or publication["publication_set_identity"] != identity
        or publication["specification_sha256"] != sha256("SPEC.md")
        or publication["source_revision"]
        != "46c82f39c5485c6f05fec10c4d8bc74b913f6977"
        or matrix["claim_limits"] != CLAIM_LIMITS
    ):
        raise ValueError("release matrix binding or qualification differs")
    product_cells = {cell["id"]: cell for cell in matrix["product_cells"]}
    if any(
        product_cells[cell]["status"] != "blocked"
        or product_cells[cell]["claim_supported"] is not False
        for cell in ["macos-rust-1.97.1", "macos-rust-stable"]
    ):
        raise ValueError("release matrix fabricates macOS evidence")
    if matrix["environment"]["sqlite"]["power_loss_qualified"] is not False:
        raise ValueError("release matrix fabricates stable-media qualification")
    if (
        readiness["status"] != "qualified-release-ready"
        or readiness["unqualified_full_v1"] is not False
        or readiness["source_revision"] != publication["source_revision"]
        or readiness["specification_sha256"] != publication["specification_sha256"]
        or readiness["publication"]["publication_set_identity"] != identity
        or readiness["conformance"]["adoption_gate"]["path"] != ADOPTION_PATH
        or readiness["conformance"]["adoption_validator"]["path"]
        != "release/verify-async-adoption.py"
        or readiness["claim"]["profiles"] != PROFILES
        or readiness["claim"]["platforms"] != ["linux-x86_64-unknown-linux-gnu"]
        or readiness["claim"]["qualification"][:3] != CLAIM_LIMITS
        or "not permitted" not in readiness["claim"]["qualification"][3]
    ):
        raise ValueError("readiness binding or qualified claim differs")


def expect_rejected(function, *arguments) -> None:
    try:
        function(*arguments)
    except (KeyError, TypeError, ValueError):
        return
    raise AssertionError("negative release-adoption vector was accepted")


def validate_negative_vectors(
    adoption: dict,
    contract: dict,
    matrix: dict,
    readiness: dict,
    specification_sha256: str,
    identity: str,
) -> None:
    blocked = copy.deepcopy(adoption)
    blocked["status"] = "blocked"
    blocked["blocked_by"] = ["GNT-ASYNC-REL-001"]
    blocked["advertises_profiles"] = []
    expect_rejected(validate_adoption, blocked, specification_sha256)

    overclaim = copy.deepcopy(adoption)
    overclaim["advertises_profiles"].append("unqualified-full-v1")
    expect_rejected(validate_adoption, overclaim, specification_sha256)

    missing = copy.deepcopy(contract)
    for assignment in missing["requirement_assignments"]:
        if "GNT-ASYNC-REL-001" in assignment["evidence_owners"]:
            assignment["evidence_owners"].remove("GNT-ASYNC-REL-001")
            break
    expect_rejected(validate_assignments, missing)

    extra = copy.deepcopy(contract)
    next(
        assignment
        for assignment in extra["requirement_assignments"]
        if "GNT-ASYNC-REL-001" not in assignment["evidence_owners"]
    )["evidence_owners"].append("GNT-ASYNC-REL-001")
    expect_rejected(validate_assignments, extra)

    macos = copy.deepcopy(matrix)
    next(cell for cell in macos["product_cells"] if cell["id"] == "macos-rust-stable")[
        "status"
    ] = "passed"
    expect_rejected(validate_release_records, macos, readiness, identity)

    power_loss = copy.deepcopy(matrix)
    power_loss["environment"]["sqlite"]["power_loss_qualified"] = True
    expect_rejected(validate_release_records, power_loss, readiness, identity)

    unqualified = copy.deepcopy(readiness)
    unqualified["unqualified_full_v1"] = True
    expect_rejected(validate_release_records, matrix, unqualified, identity)


def main() -> None:
    specification_sha256 = sha256("SPEC.md")
    adoption = read_json(ADOPTION_PATH)
    contract = read_json(CONTRACT_PATH)
    matrix = read_json(MATRIX_PATH)
    profiles = read_json(PROFILES_PATH)
    readiness = read_json(READINESS_PATH)

    validate_adoption(adoption, specification_sha256)
    validate_assignments(contract)
    validate_migration_boundary()
    identity = validate_publication(specification_sha256)
    validate_profiles(profiles, specification_sha256)
    validate_release_records(matrix, readiness, identity)
    validate_negative_vectors(
        adoption,
        contract,
        matrix,
        readiness,
        specification_sha256,
        identity,
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", matrix["publication"]["source_revision"], "HEAD"],
        cwd=ROOT,
        check=True,
    )
    print("qualified async release adoption is current")


if __name__ == "__main__":
    main()
