#!/usr/bin/env python3
"""Validate offline case.json packages through the shared public Rust runner.

Run from any directory. An optional package/corpus path is resolved relative to
the caller; the default is this checkout's examples directory. No network host
is used, and Cargo is invoked offline. Individual scenarios have Rust deadlines;
the subprocess deadline also bounds compilation and unexpected runtime hangs.
On POSIX, timeout or interruption terminates the isolated Cargo process group,
allows one second for shutdown, then kills it with a one-second reap bound.
"""

import argparse
import errno
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


def wait_for_exit(process: subprocess.Popen, deadline: float) -> None:
    """Observe exit without reaping the POSIX group leader before cleanup.

    Keeping the leader's PID reserved prevents group-ID reuse during timeout or
    interrupt cleanup. Use waitid on Linux and kqueue on macOS Python builds
    without waitid; neither observation reaps the child.
    """
    if os.name != "posix":
        process.wait(timeout=max(0, deadline - time.monotonic()))
        return
    if not hasattr(os, "waitid"):
        event = select.kevent(
            process.pid, filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
            fflags=select.KQ_NOTE_EXIT,
        )
        with select.kqueue() as queue:
            try:
                events = queue.control([event], 1, max(0, deadline - time.monotonic()))
            except ProcessLookupError:
                # A child that exited before registration is still unreaped.
                return
            if not events:
                raise subprocess.TimeoutExpired(process.args, 0)
            if events[0].flags & select.KQ_EV_ERROR:
                if events[0].data != errno.ESRCH:
                    raise OSError(events[0].data, "cannot observe corpus validator")
        return
    while True:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is not None and result.si_pid == process.pid:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 0)
        time.sleep(min(0.02, remaining))


def stop_process(process: subprocess.Popen) -> None:
    """Terminate then kill only the newly created group; bound cleanup waits.

    Do not reap the leader until after the last group signal, even if it exits
    on TERM while descendants ignore it. Further interrupts cannot skip cleanup.
    """
    def send(sig: int) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            elif sig == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
        except ProcessLookupError:
            pass

    previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        send(signal.SIGTERM)
        time.sleep(1)
        if os.name == "posix":
            send(signal.SIGKILL)
        else:
            process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            # An uninterruptible kernel wait must not hang this wrapper.
            pass
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def main() -> int:
    """Run corpus validation, preserving failure exit codes and timeout evidence."""
    repository = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=repository / "examples")
    parser.add_argument("--timeout", type=int, default=600, help="total deadline in seconds")
    arguments = parser.parse_args()
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    root = arguments.path.resolve()
    if not root.is_dir():
        parser.error(f"not a package or corpus directory: {root}")
    command = ["cargo", "run", "--offline", "-p", "gantry-conformance", "--example", "corpus", "--"]
    command += [str(root)] if (root / "case.json").is_file() else ["--all", str(root)]
    try:
        deadline = time.monotonic() + arguments.timeout
        process = subprocess.Popen(command, cwd=repository, start_new_session=os.name == "posix")
    except OSError as error:
        print(f"cannot run corpus validator: {error}", file=sys.stderr)
        return 1
    try:
        wait_for_exit(process, deadline)
        # Commit the observed successful exit before reaping. An interrupt
        # after reaping must never enter cleanup with a reusable group ID.
        previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except subprocess.TimeoutExpired:
        stop_process(process)
        print(f"example validation exceeded {arguments.timeout}s", file=sys.stderr)
        return 124
    except KeyboardInterrupt:
        stop_process(process)
        return 130
    except OSError as error:
        stop_process(process)
        print(f"cannot observe corpus validator: {error}", file=sys.stderr)
        return 1
    try:
        return process.wait()
    finally:
        signal.signal(signal.SIGINT, previous_handler)


if __name__ == "__main__":
    sys.exit(main())
