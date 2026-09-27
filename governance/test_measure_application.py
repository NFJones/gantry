"""Synthetic subprocess tests for non-gating benchmark observations."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from measure_application import MAX_OUTPUT_BYTES, measure, refuse_constant


class MeasurementTests(unittest.TestCase):
    """A failed or unbounded workload must never produce a partial record."""

    def setUp(self):
        """Create an isolated fake CLI and an authored application source."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = self.root / "package"
        self.package.mkdir()
        (self.package / "main.gnt").write_text('fn main() -> String { "ok" }\n')
        self.binary = self.root / "gantry"

    def fake_cli(self, body):
        """Install a test-only executable; production measurements use the real CLI."""
        self.binary.write_text("#!/usr/bin/env python3\n" + body)
        self.binary.chmod(0o700)

    def test_records_only_complete_matching_repetitions(self):
        """Every sample names identical input and canonical outcome bytes."""
        self.fake_cli('import sys\nassert sys.argv[1] == "run"\nprint("\\\"ok\\\"")\n')
        result = measure(self.binary, self.package, '"ok"', 2, 5)
        self.assertEqual(len(result["elapsed_ns"]), 2)
        self.assertEqual(result["qualification"], "none")
        self.assertEqual(result["semantic_charges"], "not-observed")
        self.assertEqual(result["execution_budget_policy"], "cli-default-unlimited")
        self.assertTrue(result["rustc"].startswith("rustc "))
        self.assertEqual(result["package_sources"][0]["path"], "main.gnt")

    def test_failure_output_and_timeout_refuse_a_record(self):
        """Unexpected output, stderr, nonzero exit, and timeout all fail closed."""
        for body in ['print("wrong")\n', 'import sys\nprint("error", file=sys.stderr)\n',
                     'raise SystemExit(2)\n', 'import time\ntime.sleep(1)\n']:
            with self.subTest(body=body):
                self.fake_cli(body)
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    measure(self.binary, self.package, '"ok"', 1, 0.01)

    def test_invalid_json_constants_are_refused(self):
        """Python's JSON extensions cannot become expected product outcomes."""
        with self.assertRaises(ValueError):
            refuse_constant("NaN")

    def test_source_mutation_refuses_an_observation(self):
        """An application cannot change while a sample is being collected."""
        self.fake_cli('from pathlib import Path\nimport sys\n'
                      'Path(sys.argv[2], "main.gnt").write_text("changed")\n'
                      'print("\\\"ok\\\"")\n')
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            measure(self.binary, self.package, '"ok"', 1, 5)

    def test_excessive_output_refuses_without_retaining_the_stream(self):
        """A process that emits too much output never produces a timing record."""
        self.fake_cli(f'import sys\nsys.stdout.write("x" * {MAX_OUTPUT_BYTES + 1})\n')
        with self.assertRaisesRegex(ValueError, "output exceeds"):
            measure(self.binary, self.package, '"ok"', 1, 5)

    def test_bounds_and_missing_inputs_refuse(self):
        """The runner cannot issue unbounded or source-free requests."""
        self.fake_cli('print("\\\"ok\\\"")\n')
        for repetitions, timeout in [(0, 5), (31, 5), (1, 0), (1, 121)]:
            with self.assertRaises(ValueError):
                measure(self.binary, self.package, '"ok"', repetitions, timeout)
        (self.package / "main.gnt").unlink()
        with self.assertRaises(ValueError):
            measure(self.binary, self.package, '"ok"', 1, 5)
