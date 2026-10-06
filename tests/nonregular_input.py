#!/usr/bin/env python3
"""Shared checks that sealmark only ever processes regular files.

digest, verify-digest and key-id share one input rule: the type decision is
made on the file descriptor actually opened -- fstat() after open() -- never
on a separate stat() of the path done beforehand. The tests here pin the
consequences of that rule for the three commands identically:

* a FIFO with no writer is rejected with exit code 1 immediately: the command
  neither blocks in open() waiting for the other end nor reports a digest, a
  match/mismatch or a fingerprint;
* a FIFO that already carries data and is held open by a writer (opened here
  O_RDWR, so no EOF ever arrives) is rejected just as fast and the data is
  never read -- even when the bytes look exactly like a valid document, a
  matching digest's content or a valid PUBLIC KEY block;
* a symlink resolving to a readable regular file works exactly like the file
  itself (a symlink chain included), while a symlink resolving to a FIFO or a
  directory is refused like that object and a dangling symlink is an ordinary
  file-access failure.

The FIFO cases are the security regression guards: an implementation that
opened a path checked regular beforehand (TOCTOU) or that blocked in open()
on a FIFO would either hang -- every command is run with an explicit timeout,
so that fails the test loudly instead of stalling the suite -- or process the
piped bytes. Linux gives us both os.mkfifo() and O_RDWR-on-a-FIFO semantics,
which is what the ready-data fixture relies on, so the cases are skipped on
other platforms.
"""

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")
TOCTOU_PRELOAD = os.environ.get("SEALMARK_TOCTOU_PRELOAD")


def supported():
    # os.mkfifo and O_RDWR-on-FIFO without blocking are the POSIX/Linux
    # behavior the fixtures below depend on.
    return bool(SEALMARK_BIN) and sys.platform.startswith("linux")


requires_nonregular_input = unittest.skipUnless(
    supported(),
    "FIFO/non-regular-file checks need Linux and SEALMARK_BIN",
)

requires_toctou_preload = unittest.skipUnless(
    supported() and TOCTOU_PRELOAD and Path(TOCTOU_PRELOAD).is_file(),
    "SEALMARK_TOCTOU_PRELOAD is unavailable; the check/open swap cannot be "
    "injected on this platform",
)


def run(argv, timeout=10):
    """Run sealmark with argv (without the binary); a hang fails the test."""
    return subprocess.run(
        [SEALMARK_BIN, *argv],
        capture_output=True,
        timeout=timeout,
    )


def make_fifo(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    os.mkfifo(path)


def assert_rejected_as_nonregular(case, result, path):
    """Exit 1, empty stdout, and a 'not a regular file' error naming path."""
    case.assertEqual(result.returncode, 1, result.stderr)
    case.assertEqual(result.stdout, b"")
    stderr = result.stderr
    case.assertIn(b"not a regular file", stderr)
    case.assertIn(os.fsencode(str(path)), stderr)
    # No success output of any command may leak into the error channel.
    case.assertNotIn(b"match", stderr)
    case.assertNotIn(b"mismatch", stderr)
    case.assertNotIn(b"sha256:", stderr)
    case.assertNotIn(b"spki-sha256:", stderr)
    case.assertTrue(stderr.endswith(b"\n"))


def assert_access_failure(case, result, path):
    """Exit 1, empty stdout, an access/open error naming path (no usage
    error and no content verdict)."""
    case.assertEqual(result.returncode, 1, result.stderr)
    case.assertEqual(result.stdout, b"")
    stderr = result.stderr
    case.assertIn(os.fsencode(str(path)), stderr)
    case.assertNotIn(b"Usage", stderr)
    case.assertNotIn(b"mismatch", stderr)
    case.assertNotIn(b"spki-sha256:", stderr)
    case.assertTrue(stderr.endswith(b"\n"))


class OpenFifo:
    """Context manager holding a FIFO open O_RDWR with `payload` in it.

    One descriptor is both a reader and a writer, so: open() returns at once,
    the payload is immediately readable, and -- crucially -- EOF can never
    arrive while the holder is open, no matter who else closes their end.
    """

    def __init__(self, path, payload):
        self.path = path
        self.payload = payload
        self.fd = -1

    def __enter__(self):
        make_fifo(self.path)
        self.fd = os.open(self.path, os.O_RDWR)
        if self.payload:
            os.write(self.fd, self.payload)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd >= 0:
            os.close(self.fd)
        return False


def run_all(case, args, regular_path, expected_stdout, valid_payload,
            tmp):
    """Exercise the full non-regular-input contract for one command.

    args(path)            full argv after the binary for this command;
    regular_path          an existing readable regular file that succeeds;
    expected_stdout       exact stdout of processing regular_path;
    valid_payload         bytes a naive reader would accept (valid content);
    tmp                   the test's temp directory (pathlib.Path).
    """
    # -- FIFO without a writer: open must not wait, result is rejection.
    idle_fifo = tmp / "idle no writer.fifo"
    make_fifo(idle_fifo)
    t0 = time.monotonic()
    result = run(args(idle_fifo))
    elapsed = time.monotonic() - t0
    assert_rejected_as_nonregular(case, result, idle_fifo)
    case.assertLess(elapsed, 5.0, "blocked on a writerless FIFO")

    # -- FIFO holding valid-looking data with a persistent writer/reader:
    # rejected without consuming a byte and without waiting for EOF.
    fed_fifo = tmp / "fed 目录.fifo"
    with OpenFifo(fed_fifo, valid_payload):
        t0 = time.monotonic()
        result = run(args(fed_fifo))
        elapsed = time.monotonic() - t0
    assert_rejected_as_nonregular(case, result, fed_fifo)
    case.assertLess(elapsed, 5.0, "blocked on FIFO data or pipe shutdown")

    # -- Symlink directly to a FIFO (no writer): same rejection, no block.
    link_fifo = tmp / "link to fifo"
    os.symlink(idle_fifo, link_fifo)
    t0 = time.monotonic()
    result = run(args(link_fifo))
    elapsed = time.monotonic() - t0
    assert_rejected_as_nonregular(case, result, link_fifo)
    case.assertLess(elapsed, 5.0)

    # -- Symlink whose target is a data-ready FIFO held open.
    fed_link = tmp / "link to fed fifo"
    with OpenFifo(tmp / "fed-target.fifo", valid_payload):
        os.symlink(tmp / "fed-target.fifo", fed_link)
        result = run(args(fed_link))
    assert_rejected_as_nonregular(case, result, fed_link)

    # -- Symlink (and a symlink chain) to a readable regular file: behaves
    # exactly like opening the file directly, spaces/Chinese included.
    direct_link = tmp / "a 链接" / "link to key"
    direct_link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(regular_path, direct_link)
    result = run(args(direct_link))
    case.assertEqual(result.returncode, 0, result.stderr)
    case.assertEqual(result.stderr, b"")
    case.assertEqual(result.stdout, expected_stdout)

    chain_link = tmp / "chain link"
    middle = tmp / "chain middle"
    os.symlink(regular_path, middle)
    os.symlink(middle, chain_link)
    result = run(args(chain_link))
    case.assertEqual(result.returncode, 0, result.stderr)
    case.assertEqual(result.stderr, b"")
    case.assertEqual(result.stdout, expected_stdout)

    # -- Symlink to a directory: non-regular, rejected as such.
    directory = tmp / "a directory target"
    directory.mkdir()
    dir_link = tmp / "link to dir"
    os.symlink(directory, dir_link)
    assert_rejected_as_nonregular(case, run(args(dir_link)), dir_link)

    # -- Dangling symlink: ordinary file-access failure, never a content
    # verdict (mismatch / invalid key) or a usage error.
    dangling = tmp / "dangling link"
    os.symlink(tmp / "gone 缺失", dangling)
    assert_access_failure(case, run(args(dangling)), dangling)


def _toctou_env(path):
    """Environment with the stat-spoofing preload aimed at `path`."""
    env = dict(os.environ)
    preload = TOCTOU_PRELOAD
    if env.get("LD_PRELOAD"):
        preload = preload + ":" + env["LD_PRELOAD"]
    env["LD_PRELOAD"] = preload
    env["SEALMARK_TOCTOU_PATH"] = str(path)
    return env


def assert_spoof_is_live(case, fifo):
    """Prove the preload really makes a *path* stat call see a regular file.

    Without this control the main check could pass even with a broken or
    unloaded preload (the fixed binary rejects FIFOs regardless), silently
    testing nothing. Python's os.stat goes through the same libc path calls
    the interposer rewrites.
    """
    env = _toctou_env(fifo.resolve())
    probe = subprocess.run(
        [sys.executable, "-c",
         "import os,stat,sys; "
         "sys.exit(0 if stat.S_ISREG(os.stat(sys.argv[1]).st_mode) else 1)",
         str(fifo)],
        env=env,
    )
    case.assertEqual(
        probe.returncode, 0,
        "TOCTOU preload did not spoof the path stat as a regular file; "
        "the race condition would not actually be exercised",
    )


def _one_spoofed_run(case, args, env, passed_path):
    """Run one command against a stat-spoofed input and demand rejection.

    Passed to sealmark as `passed_path` (which may be a symlink); the error
    must name that exact user argument. A stat-first client blocks on the
    underlying FIFO instead, which the timeout turns into a failure.
    """
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            [SEALMARK_BIN, *args(passed_path)],
            capture_output=True,
            env=env,
            timeout=8,
        )
    except subprocess.TimeoutExpired as exc:
        case.fail(
            "sealmark blocked on the spoofed FIFO (waiting for a writer, "
            "pipe data or pipe EOF) instead of rejecting it; "
            f"partial stdout was {exc.stdout!r}"
        )
    elapsed = time.monotonic() - t0
    assert_rejected_as_nonregular(case, result, passed_path)
    case.assertLess(elapsed, 5.0, "did not reject the swapped input promptly")


def run_toctou_all(case, args, valid_payload, tmp):
    """The decisive check/open-swap test for one command.

    A FIFO is made to look like a regular file to every path-based stat while
    open() still opens the FIFO itself (see tests/toctou_preload.c). The FIFO
    is held open O_RDWR with valid-looking bytes already in it, so a
    stat-first implementation opens the pipe, blocks waiting for the other
    end / pipe EOF and/or consumes the bytes -- either hanging (the run is
    timed out, which fails the test) or emitting a success result. Only an
    implementation that decides the type on the descriptor actually opened
    returns promptly with an "is not a regular file" failure.

    The same swap is exercised through a symlink: the link is presented as
    the user's path, its target is the FIFO, and the rejection must name the
    link path exactly as passed.
    """
    fifo = tmp / "spoofed 换名.fifo"
    with OpenFifo(fifo, valid_payload):
        env = _toctou_env(fifo.resolve())
        assert_spoof_is_live(case, fifo)

        # Direct path.
        _one_spoofed_run(case, args, env, fifo)

        # Symlink whose target is the swapped FIFO.
        link = tmp / "link to swapped 链接"
        os.symlink(fifo, link)
        _one_spoofed_run(case, args, env, link)
