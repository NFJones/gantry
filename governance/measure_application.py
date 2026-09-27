#!/usr/bin/env python3
"""Record bounded, non-gating product-CLI observations for one application.

This is not strategy, semantic-metering, publication, or release qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import selectors
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MAX_OUTPUT_BYTES = 1_048_576


def digest(path: Path) -> str:
    """Return the identity of an exact input file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refuse_constant(value: str) -> None:
    """Reject Python's non-JSON NaN and Infinity parser extensions."""
    raise ValueError(f"non-JSON numeric constant: {value}")


def run_bounded(command: list[str], timeout_seconds: float) -> tuple[int, bytes, bytes]:
    """Drain both streams with a deadline and a separate byte ceiling for each."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        with selectors.DefaultSelector() as ready:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                ready.register(stream, selectors.EVENT_READ, name)
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
                for key, _ in ready.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        ready.unregister(key.fileobj)
                    else:
                        collected = output[key.data]
                        if len(collected) + len(chunk) > MAX_OUTPUT_BYTES:
                            raise ValueError("application output exceeds the measurement byte limit")
                        collected.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        return process.wait(timeout=remaining), bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def measure(binary: Path, package: Path, expected: str, repetitions: int,
            timeout_seconds: float) -> dict:
    """Measure successful CLI runs, failing closed on drift or incomplete runs."""
    if not 1 <= repetitions <= 30 or not 0 < timeout_seconds <= 120:
        raise ValueError("repetitions must be 1..30 and timeout must be in (0, 120]")
    if len(expected.encode()) + 1 > MAX_OUTPUT_BYTES:
        raise ValueError("expected output exceeds the measurement byte limit")
    sources = sorted(package.rglob("*.gnt"))
    if not sources or not binary.is_file():
        raise ValueError("a product binary and at least one .gnt source are required")
    binary_sha256 = digest(binary)
    specification_sha256 = digest(ROOT / "SPEC.md")
    inputs = [{"path": str(path.relative_to(package)), "sha256": digest(path)}
              for path in sources]
    observations = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        code, stdout, stderr = run_bounded([str(binary), "run", str(package)], timeout_seconds)
        elapsed = time.perf_counter_ns() - start
        if code or stderr or stdout != (expected + "\n").encode():
            raise ValueError("application failed or produced unexpected output; no observation recorded")
        if (digest(binary) != binary_sha256
                or digest(ROOT / "SPEC.md") != specification_sha256
                or sorted(package.rglob("*.gnt")) != sources
                or any(digest(package / item["path"]) != item["sha256"] for item in inputs)):
            raise ValueError("application inputs changed during measurement")
        observations.append(elapsed)
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True,
                           timeout=timeout_seconds, check=True).stdout.strip()
    return {
        "format": "gantry.non-gating-application-observation/v1",
        "qualification": "none",
        "strategy": "product-cli-default",
        "execution_budget_policy": "cli-default-unlimited",
        "semantic_charges": "not-observed",
        "binary_sha256": binary_sha256,
        "specification_sha256": specification_sha256,
        "package_sources": inputs,
        "expected_canonical_json": expected,
        "rustc": rustc,
        "measurement_python": platform.python_version(),
        "platform": platform.platform(),
        "configured_timeout_seconds": timeout_seconds,
        "repetitions": repetitions,
        "elapsed_ns": observations,
    }


def main() -> int:
    """Print a record only when every bounded repetition succeeds."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-json", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=30)
    args = parser.parse_args()
    try:
        expected = json.loads(args.expected_json, parse_constant=refuse_constant)
        if json.dumps(expected, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")) != args.expected_json:
            raise ValueError("expected output must be canonical compact JSON")
        record = measure(args.binary.resolve(), args.package.resolve(), args.expected_json,
                         args.repetitions, args.timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        print(f"measurement refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
