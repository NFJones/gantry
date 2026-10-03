#!/usr/bin/env python3
"""Bounded regressions for validator exit codes and isolated process cleanup."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("validate-examples.py")
SPEC = importlib.util.spec_from_file_location("validate_examples", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ValidatorTests(unittest.TestCase):
    """Use fake Cargo processes, not compilation or the example corpus."""

    def test_exit_codes_are_preserved(self):
        """Successful and failed validators must keep their original status."""
        with tempfile.TemporaryDirectory() as directory:
            for status in (0, 7):
                with self.subTest(status=status):
                    command = [sys.executable, "-c", f"raise SystemExit({status})"]
                    real_popen = subprocess.Popen
                    with mock.patch.object(sys, "argv", [str(SCRIPT), directory]), mock.patch.object(
                        VALIDATOR.subprocess, "Popen", side_effect=lambda *a, **kw: real_popen(command, **kw)
                    ):
                        self.assertEqual(VALIDATOR.main(), status)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_kills_descendant_even_after_parent_terminates(self):
        """A TERM-resistant descendant cannot outlive the total deadline."""
        self.check_group_cleanup(interrupt=False)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_keyboard_interrupt_kills_group(self):
        """Interrupting the wrapper must clean up its isolated Cargo group."""
        self.check_group_cleanup(interrupt=True)

    def check_group_cleanup(self, interrupt):
        """Bound every wait and clean test children even when assertions fail."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "ready"
            heartbeat = root / "heartbeat"
            group = root / "group"
            fake_cargo = root / "cargo"
            fake_cargo.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, signal, subprocess, sys, time\n"
                f"pathlib.Path({str(group)!r}).write_text(str(os.getpgrp()))\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                + repr(
                    "import pathlib, signal, time\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    f"pathlib.Path({str(ready)!r}).write_text('ready')\n"
                    "deadline = time.monotonic() + 15\n"
                    "while time.monotonic() < deadline:\n"
                    f" pathlib.Path({str(heartbeat)!r}).write_text(str(time.monotonic_ns()))\n"
                    " time.sleep(0.02)\n"
                )
                + "])\n"
                "time.sleep(15)\n"
            )
            fake_cargo.chmod(0o755)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), str(root), "--timeout", "2"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "fake Cargo descendant did not start")
                self.assertNotEqual(int(group.read_text()), process.pid)
                self.assertNotEqual(int(group.read_text()), os.getpgrp())
                if interrupt:
                    process.send_signal(signal.SIGINT)
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 130 if interrupt else 124, stderr)
                if not interrupt:
                    self.assertIn("example validation exceeded 2s", stderr)
                previous = heartbeat.read_text()
                time.sleep(0.2)
                self.assertEqual(heartbeat.read_text(), previous, "descendant survived cleanup")
            finally:
                # Never signal a recorded group after its leader was reaped:
                # it could have been reused. Fake children expire independently
                # even when running against an implementation that leaks them.
                process.kill()
                process.communicate(timeout=20)


if __name__ == "__main__":
    unittest.main()
