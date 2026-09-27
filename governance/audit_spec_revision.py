#!/usr/bin/env python3
"""Report SPEC revision bindings without rewriting evidence or qualifying claims."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RECORDS = (
    "protocol/requirements/reviewed-v1.json",
    "protocol/requirements/section14-v1.json",
    "protocol/conformance/async-execution-adoption-v1.json",
    "protocol/conformance/generics-traits-adoption-v1.json",
)
CATALOGS = (
    "embedding-contracts-v1.json",
    "general-purpose-preregistration-v1.json",
    "host-domain-contracts-v1.json",
    "ir-contracts-v1.json",
    "portable-contracts-v1.json",
    "profiles-v1.json",
    "public-formats-v1.json",
)


def sha256(path: Path) -> str:
    """Hash actual file bytes; missing files remain errors, not empty digests."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(root: Path) -> dict:
    """Compare revision bindings, collecting malformed and missing input errors."""
    revision = sha256(root / "SPEC.md")
    bindings = []

    def record(path: str, field: str, value: object) -> None:
        """Retain the observed field and a strict comparison with current bytes."""
        bindings.append({"path": path, "field": field, "recorded": value,
                         "matches_current_spec": value == revision})

    def read_field(path: str, field: str) -> None:
        """Treat absent or malformed records as mismatches and continue auditing."""
        try:
            value = json.loads((root / path).read_text(encoding="utf-8"))[field]
            record(path, field, value)
        except (OSError, ValueError, KeyError, TypeError) as error:
            record(path, field, None)
            bindings[-1]["error"] = str(error)

    for path in RECORDS:
        read_field(path, "specification_sha256")
    for name in CATALOGS:
        read_field(f"protocol/catalogs/{name}", "specification_revision")
    catalogs = sorted((root / "protocol/catalogs").glob("*.json"))
    for path in catalogs:
        if path.name in CATALOGS:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("catalog must be an object")
            if "specification_revision" in document:
                record(relative, "specification_revision", document["specification_revision"])
        except (OSError, ValueError) as error:
            record(relative, "specification_revision", None)
            bindings[-1]["error"] = str(error)
    snapshot = "protocol/publication/v1/SPEC.md"
    try:
        record(snapshot, "sha256(bytes)", sha256(root / snapshot))
    except OSError as error:
        record(snapshot, "sha256(bytes)", None)
        bindings[-1]["error"] = str(error)
    index = "protocol/publication/index-v1.json"
    try:
        document = json.loads((root / index).read_text(encoding="utf-8"))
        members = [item for item in document["artifacts"] if item["id"] == "gantry.spec"]
        if len(members) != 1:
            raise ValueError("expected exactly one gantry.spec member")
        record(index, "artifacts[gantry.spec].sha256", members[0]["sha256"])
        record(index, "publication_revision", document["publication_revision"])
        bindings[-1]["matches_current_spec"] = document["publication_revision"] == f"gantry-v1-{revision}"
    except (OSError, ValueError, KeyError, TypeError) as error:
        record(index, "gantry.spec", None)
        bindings[-1]["error"] = str(error)
    return {"current_specification_sha256": revision, "bindings": bindings,
            "mismatch_count": sum(not row["matches_current_spec"] for row in bindings),
            "qualification": "not-assessed"}


def main() -> int:
    """Print the aggregate report and fail closed for mismatched/unreadable input."""
    try:
        report = audit(ROOT)
    except OSError as error:
        print(json.dumps({"error": str(error), "qualification": "not-assessed"}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(report["mismatch_count"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
