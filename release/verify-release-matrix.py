#!/usr/bin/env python3
"""Verify the frozen qualified Gantry release matrix evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = ROOT / "release/release-matrix-v1.json"

FEATURE_SETS = [
    "none",
    "frontend",
    "analyzer",
    "evaluator",
    "concurrent",
    "durable",
    "combined",
]

ADAPTER_SUITES = [
    "concurrent_executor",
    "executor_services",
    "execution_observation",
    "durable_events",
    "journal_storage",
    "sqlite_storage",
    "publication_set",
    "conformance_publication",
    "external_facade_matrix",
    "facade",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise SystemExit(f"{label} fields differ: expected {sorted(expected)}, found {sorted(actual)}")


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    require_exact_keys(
        matrix,
        {
            "format",
            "overall_status",
            "publication",
            "inputs",
            "environment",
            "feature_sets",
            "product_cells",
            "adapter_cells",
            "dependency_policy",
            "fuzz",
            "claim_limits",
        },
        "matrix",
    )
    if matrix["format"] != "gantry.release-matrix/v1":
        raise SystemExit("matrix format differs")
    if matrix["overall_status"] != "qualified-passed":
        raise SystemExit("matrix must remain qualified while macOS cells are blocked")

    publication = matrix["publication"]
    require_exact_keys(
        publication,
        {"index_path", "publication_set_identity", "source_revision", "specification_sha256"},
        "publication",
    )
    index_path = ROOT / publication["index_path"]
    if sha256(index_path) != publication["publication_set_identity"]:
        raise SystemExit("publication identity differs")
    if sha256(ROOT / "SPEC.md") != publication["specification_sha256"]:
        raise SystemExit("specification identity differs")
    subprocess.run(
        ["git", "cat-file", "-e", f"{publication['source_revision']}^{{commit}}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    input_paths = [entry["path"] for entry in matrix["inputs"]]
    if input_paths != sorted(input_paths) or len(input_paths) != len(set(input_paths)):
        raise SystemExit("matrix inputs are not sorted and unique")
    for entry in matrix["inputs"]:
        require_exact_keys(entry, {"path", "sha256"}, f"input {entry['path']}")
        if sha256(ROOT / entry["path"]) != entry["sha256"]:
            raise SystemExit(f"matrix input digest differs: {entry['path']}")

    if matrix["feature_sets"] != FEATURE_SETS:
        raise SystemExit("feature-set matrix differs")
    product_cells = {cell["id"]: cell for cell in matrix["product_cells"]}
    expected_product_ids = {
        "linux-rust-1.91.0",
        "linux-rust-1.97.1",
        "linux-rust-stable",
        "macos-rust-1.97.1",
        "macos-rust-stable",
    }
    if set(product_cells) != expected_product_ids:
        raise SystemExit("product matrix membership differs")
    for cell_id, cell in product_cells.items():
        if cell["feature_sets"] != FEATURE_SETS:
            raise SystemExit(f"feature sets differ for {cell_id}")
        if cell_id.startswith("linux-"):
            if cell["status"] != "passed" or cell["claim_supported"] is not True:
                raise SystemExit(f"Linux cell is not passed: {cell_id}")
            if not cell.get("evidence"):
                raise SystemExit(f"Linux cell has no evidence: {cell_id}")
        else:
            if cell["status"] != "blocked" or cell["claim_supported"] is not False:
                raise SystemExit(f"macOS cell must remain blocked: {cell_id}")
            if not cell.get("blocker"):
                raise SystemExit(f"macOS cell has no blocker: {cell_id}")

    adapter_cells = {cell["id"]: cell for cell in matrix["adapter_cells"]}
    if set(adapter_cells) != {
        "linux-adapters-rust-1.91.0",
        "linux-adapters-rust-1.97.1",
        "linux-adapters-rust-stable",
    }:
        raise SystemExit("adapter matrix membership differs")
    for cell_id, cell in adapter_cells.items():
        if cell["status"] != "passed" or cell["suites"] != ADAPTER_SUITES:
            raise SystemExit(f"adapter cell differs: {cell_id}")

    dependency = matrix["dependency_policy"]
    if dependency != {
        "tool": "cargo-deny",
        "version": "0.20.2",
        "status": "passed",
        "checks": ["advisories", "bans", "licenses", "sources"],
        "result": "advisories ok, bans ok, licenses ok, sources ok",
    }:
        raise SystemExit("dependency-policy result differs")

    fuzz = matrix["fuzz"]
    if (
        fuzz["target"] != "protocol_identity"
        or fuzz["toolchain"] != "nightly-2026-07-01"
        or fuzz["rustc"] != "1.98.0-nightly"
        or fuzz["rustc_commit"] != "f46ec5218fe7829ac18323b5ee0b409a63169f27"
        or fuzz["cargo_fuzz"] != "0.13.2"
        or fuzz["libfuzzer_sys"] != "0.4.9"
        or fuzz["runs"] != 2000
        or fuzz["max_len"] != 256
        or fuzz["seed"] != 1881717514
        or fuzz["status"] != "passed"
    ):
        raise SystemExit("fuzz result differs")
    retained_paths = [entry["path"] for entry in fuzz["retained_inputs"]]
    if retained_paths != sorted(retained_paths):
        raise SystemExit("retained fuzz inputs are not sorted")
    for entry in fuzz["retained_inputs"]:
        if sha256(ROOT / entry["path"]) != entry["sha256"]:
            raise SystemExit(f"retained fuzz input differs: {entry['path']}")

    if len(matrix["claim_limits"]) != 3 or not all(matrix["claim_limits"]):
        raise SystemExit("claim limits differ")
    print("qualified release matrix is current")


if __name__ == "__main__":
    main()
