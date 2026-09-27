"""Synthetic revision-binding checks; never attest to real conformance evidence."""

import json
import tempfile
import unittest
from pathlib import Path

from audit_spec_revision import CATALOGS, RECORDS, audit, sha256


class RevisionAuditTests(unittest.TestCase):
    """Exercise coherent, stale, missing, and malformed binding reports."""

    def setUp(self):
        """Create a disposable coherent fixture outside the repository."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "SPEC.md").write_text("fixture specification\n")
        self.revision = sha256(self.root / "SPEC.md")
        for path in RECORDS:
            self.write(path, {"specification_sha256": self.revision})
        for name in CATALOGS:
            self.write(f"protocol/catalogs/{name}", {"specification_revision": self.revision})
        self.write("protocol/catalogs/fixture.json", {"specification_revision": self.revision})
        snapshot = self.root / "protocol/publication/v1/SPEC.md"
        snapshot.parent.mkdir(parents=True)
        snapshot.write_bytes((self.root / "SPEC.md").read_bytes())
        self.write("protocol/publication/index-v1.json", {
            "artifacts": [{"id": "gantry.spec", "sha256": self.revision}],
            "publication_revision": f"gantry-v1-{self.revision}",
        })

    def write(self, path, value):
        """Write only synthetic test inputs."""
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def test_coherence_is_not_qualification(self):
        """Equal bindings do not manufacture a qualification verdict."""
        report = audit(self.root)
        self.assertEqual(report["mismatch_count"], 0)
        self.assertEqual(report["qualification"], "not-assessed")

    def test_collects_all_stale_bindings_without_rewriting(self):
        """Multiple failures survive in one report and input bytes stay intact."""
        self.write(RECORDS[0], {"specification_sha256": "stale"})
        (self.root / RECORDS[1]).unlink()
        catalog = self.root / "protocol/catalogs/fixture.json"
        catalog.write_text("malformed")
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        report = audit(self.root)
        self.assertEqual(report["mismatch_count"], 3)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_duplicate_publication_member_is_rejected(self):
        """A duplicated matching member cannot masquerade as a coherent index."""
        self.write("protocol/publication/index-v1.json", {
            "artifacts": [{"id": "gantry.spec", "sha256": self.revision}] * 2,
            "publication_revision": f"gantry-v1-{self.revision}",
        })
        self.assertEqual(audit(self.root)["mismatch_count"], 1)

    def test_snapshot_drift_is_independent_of_index_pin(self):
        """A matching index cannot hide different snapshot bytes."""
        (self.root / "protocol/publication/v1/SPEC.md").write_text("different\n")
        self.assertEqual(audit(self.root)["mismatch_count"], 1)

    def test_required_catalog_cannot_disappear_or_drop_its_revision(self):
        """Known revision-bearing catalogs are required even when discovery misses them."""
        (self.root / f"protocol/catalogs/{CATALOGS[0]}").unlink()
        self.write(f"protocol/catalogs/{CATALOGS[1]}", {})
        self.assertEqual(audit(self.root)["mismatch_count"], 2)


if __name__ == "__main__":
    unittest.main()
