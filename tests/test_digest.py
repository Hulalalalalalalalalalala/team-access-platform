#!/usr/bin/env python3
"""Regression tests for ``sealmark digest``.

The digest contract under test (see README):

* success: exit code 0, empty stderr, stdout is exactly one line
  ``sha256:<64 lowercase hex digits>`` terminated by a single newline;
* the digest is the standard SHA-256 of the file's complete raw bytes
  (verified here against the independent ``hashlib`` implementation);
* the same bytes digest identically regardless of file name or directory,
  including paths with spaces or non-ASCII characters;
* an empty file is a valid input (standard empty-content SHA-256);
* missing path / directory / other unreadable input: exit code 1 with an
  empty stdout and a stderr message that contains the path as passed;
* a regular file that opens successfully and then fails on read() after
  delivering part of its raw bytes: exit code 1, empty stdout, stderr says
  the read failed and names the path -- distinct from normal EOF, where the
  final short read (and an empty file) is still a success;
* a read() interrupted by a signal (EINTR) -- before any byte arrived or
  after partial content, once or several times in a row, with short reads
  around it -- is retried transparently: the digest still covers the
  complete raw bytes from start to finish and is byte-identical to an
  uninterrupted run, while a genuine I/O error after an interruption is
  still the read failure above;
* missing or empty path argument (and other usage errors): exit code 2
  with the usage text on stderr.

The read-failure case is produced deterministically by a small LD_PRELOAD
fault injector (tests/readfail_preload.c) that makes read() return EIO on
one selected regular file after an exact number of bytes have been read.
It needs no privileges, does not mutate the file, and does not depend on
timing. Its path arrives in $SEALMARK_READFAIL_PRELOAD from CTest; the
injector-based tests skip if it is unavailable, and fail loudly (never pass
silently) if the fault does not actually take effect.

The interrupted-read cases use a second LD_PRELOAD injector
(tests/eintr_preload.c, $SEALMARK_EINTR_PRELOAD) that replays a scripted
per-read schedule on one selected regular file: EINTR interruptions (no
data delivered), short reads, and -- for the failure test -- a genuine EIO
after the interruptions. The injector records how many interrupts it
actually injected and how far the schedule was consumed, and the tests
assert those counters, so a regression can never hide behind a schedule
that silently never fired.

All test content and paths are created by the tests themselves inside a
fresh temporary directory, so the suite is independent of the working
directory it is launched from and of any pre-existing files on the machine.

The path to the sealmark executable is taken from $SEALMARK_BIN (wired up
by CTest via the CMakeLists.txt add_test entry).
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import nonregular_input as nri

# Must match the read buffer size in src/main.cpp.
CHUNK_SIZE = 64 * 1024

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")

# Path to the LD_PRELOAD fault injector built by CMake (Linux only).
READFAIL_PRELOAD = os.environ.get("SEALMARK_READFAIL_PRELOAD")

# Path to the LD_PRELOAD read-interrupt injector built by CMake (Linux only).
EINTR_PRELOAD = os.environ.get("SEALMARK_EINTR_PRELOAD")

requires_readfail_preload = unittest.skipUnless(
    READFAIL_PRELOAD and Path(READFAIL_PRELOAD).is_file(),
    "SEALMARK_READFAIL_PRELOAD is unavailable; mid-read failure cannot be "
    "injected on this platform",
)

requires_eintr_preload = unittest.skipUnless(
    EINTR_PRELOAD and Path(EINTR_PRELOAD).is_file(),
    "SEALMARK_EINTR_PRELOAD is unavailable; read interrupts cannot be "
    "injected on this platform",
)

OUTPUT_RE = re.compile(rb"\Asha256:[0-9a-f]{64}\n\Z")
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Bytes that naive text-oriented handling tends to drop, translate or strip:
# a NUL, LF/CRLF line endings, the UTF-8 and UTF-16 byte-order marks, and a
# ramp over every single byte value (including high/non-text bytes).
_HEAD = (
    b"\x00"
    b"\n\r\n"
    b"\xef\xbb\xbf"      # UTF-8 BOM
    b"\xff\xfe"          # UTF-16 LE BOM
    b"\xfe\xff"          # UTF-16 BE BOM
    + bytes(range(256))
)
# Deliberately awkward tail so bytes immediately at/after a chunk boundary
# and at EOF are covered as well.
_TAIL = b"\r\n\x00\xff\xef\xbb\xbf"


def make_content(size):
    """Return ``size`` deterministic raw bytes containing tricky content."""
    if size == 0:
        return b""
    if size <= len(_HEAD) + len(_TAIL):
        return (_HEAD + _TAIL)[:size]
    middle_len = size - len(_HEAD) - len(_TAIL)
    middle = bytes((i * 31 + 7) % 256 for i in range(middle_len))
    return _HEAD + middle + _TAIL


def expected_output(content):
    return b"sha256:" + hashlib.sha256(content).hexdigest().encode("ascii") + b"\n"


class SealmarkDigestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SEALMARK_BIN:
            raise RuntimeError(
                "SEALMARK_BIN is not set; point it at the sealmark executable"
            )
        if not Path(SEALMARK_BIN).is_file():
            raise RuntimeError(f"SEALMARK_BIN does not point to a file: {SEALMARK_BIN}")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sealmark-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_sealmark(self, *args):
        return subprocess.run(
            [SEALMARK_BIN, *args],
            capture_output=True,
        )

    def run_digest(self, path_arg):
        return self.run_sealmark("digest", path_arg)

    def _preload_env(self, preload, **extra):
        env = dict(os.environ)
        if env.get("LD_PRELOAD"):
            preload = preload + ":" + env["LD_PRELOAD"]
        env["LD_PRELOAD"] = preload
        env.update(extra)
        return env

    def run_digest_with_read_failure(self, path, after):
        """Run digest with the preloaded injector armed: read() on `path`
        fails with EIO once `after` bytes have been delivered."""
        env = self._preload_env(
            READFAIL_PRELOAD,
            SEALMARK_READFAIL_PATH=str(path),
            SEALMARK_READFAIL_AFTER=str(after),
        )
        return subprocess.run(
            [SEALMARK_BIN, "digest", str(path)],
            capture_output=True,
            env=env,
        )

    def run_digest_preloaded(self, path, after=None):
        """Run digest under the preloaded injector. With `after` left None
        no fault is armed (pure pass-through); with `after` set the fault is
        scheduled at that byte offset, which is useful for the controls that
        place the threshold at or beyond normal EOF."""
        extra = {"SEALMARK_READFAIL_PATH": str(path)}
        if after is not None:
            extra["SEALMARK_READFAIL_AFTER"] = str(after)
        return subprocess.run(
            [SEALMARK_BIN, "digest", str(path)],
            capture_output=True,
            env=self._preload_env(READFAIL_PRELOAD, **extra),
        )

    def run_digest_with_eintr(self, path, schedule):
        """Run digest with the read-interrupt injector replaying `schedule`
        (a comma-separated string of E / S<n> / F directives, see
        tests/eintr_preload.c) on the reads of `path`.

        Returns (result, eintr_count, target_reads, directives_consumed)
        where the counters come from the injector's own exit-time stats
        file, so every test can prove the scripted interrupts genuinely
        happened rather than silently never firing."""
        stats_fd, stats_path = tempfile.mkstemp(
            prefix="eintr-stats-", dir=self.tmp
        )
        os.close(stats_fd)
        env = self._preload_env(
            EINTR_PRELOAD,
            SEALMARK_EINTR_PATH=str(path),
            SEALMARK_EINTR_SCHEDULE=schedule,
            SEALMARK_EINTR_STATS=stats_path,
        )
        result = subprocess.run(
            [SEALMARK_BIN, "digest", str(path)],
            capture_output=True,
            env=env,
        )
        counters = Path(stats_path).read_text(encoding="ascii").split()
        self.assertEqual(
            len(counters), 3,
            "EINTR injector wrote no stats; the preload is not active and "
            "the scheduled interrupts never happened",
        )
        eintr_count, target_reads, consumed = (int(c) for c in counters)
        return result, eintr_count, target_reads, consumed

    def write_file(self, relative_path, content):
        path = self.tmp / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    # -- success ---------------------------------------------------------

    def test_digest_matches_independent_sha256_across_chunk_boundaries(self):
        # Sizes: empty-ish/sub-chunk files, a file one byte short of a
        # boundary, a file ending exactly on a boundary, a file crossing a
        # boundary by one byte, exact multiples, and a few tail bytes left
        # after several complete chunks.
        sizes = [
            0,
            1,
            13,
            300,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 13,
            3 * CHUNK_SIZE + 5,
        ]
        for size in sizes:
            with self.subTest(size=size):
                content = make_content(size)
                path = self.write_file(f"sizes/{size}.bin", content)

                result = self.run_digest(str(path))

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                # Exact wire contract: one line, trailing newline, nothing else.
                self.assertRegex(result.stdout, OUTPUT_RE)
                self.assertEqual(len(result.stdout), len("sha256:") + 64 + 1)
                # Known-answer check against an independent SHA-256 over the
                # complete raw bytes -- not a length check and not a
                # comparison with another sealmark run.
                self.assertEqual(result.stdout, expected_output(content))

    def test_empty_file_has_standard_empty_digest(self):
        path = self.write_file("empty.dat", b"")

        result = self.run_digest(str(path))

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout, f"sha256:{EMPTY_FILE_SHA256}\n".encode("ascii")
        )

    def test_same_bytes_digest_identically_under_various_names_and_paths(self):
        content = make_content(CHUNK_SIZE + 37)
        names = [
            "plain.bin",
            "nested/dir/report.dat",
            "with space/file name.bin",
            "目录/报告 副本.pdf",
            "deep/deeper/deepest/文件 0.tmp",
        ]
        outputs = set()
        for name in names:
            with self.subTest(name=name):
                path = self.write_file(Path(name), content)
                result = self.run_digest(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, expected_output(content))
                outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)

    def test_tail_byte_change_is_reflected_in_digest(self):
        base = make_content(3 * CHUNK_SIZE + 5)
        changed = base[:-1] + bytes([base[-1] ^ 0xA5])
        self.assertNotEqual(base, changed)

        base_path = self.write_file("tail/base.bin", base)
        changed_path = self.write_file("tail/changed.bin", changed)

        base_result = self.run_digest(str(base_path))
        changed_result = self.run_digest(str(changed_path))

        self.assertEqual(base_result.returncode, 0, base_result.stderr)
        self.assertEqual(changed_result.returncode, 0, changed_result.stderr)
        self.assertNotEqual(base_result.stdout, changed_result.stdout)
        self.assertEqual(base_result.stdout, expected_output(base))
        self.assertEqual(changed_result.stdout, expected_output(changed))

    def test_raw_bytes_counted_verbatim_at_straddle_boundary(self):
        # One byte over a boundary; the lone tail byte is 0x00, which a
        # text-mode or C-string handling bug would lose.
        content = make_content(CHUNK_SIZE) + b"\x00"
        path = self.write_file("straddle/nul-tail.bin", content)

        result = self.run_digest(str(path))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, expected_output(content))

    # -- input failures (exit code 1) ------------------------------------

    def test_nonexistent_path_fails_with_exit_code_1(self):
        missing = self.tmp / "目录" / "missing file.bin"
        self.assertFalse(missing.exists())

        result = self.run_digest(str(missing))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(missing)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def test_directory_fails_with_exit_code_1(self):
        directory = self.tmp / "a directory"
        directory.mkdir()

        result = self.run_digest(str(directory))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(directory)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)

    # -- non-regular inputs are judged on the opened object --------------
    #
    # A FIFO (whether or not anyone is writing) must never be digested and
    # must never make the command wait for the other end; only the object
    # actually opened decides regularity, and symlinks resolving to a regular
    # file keep working. Shared with the other two suites.

    @nri.requires_nonregular_input
    def test_fifo_and_symlink_inputs_follow_the_single_regular_file_rule(self):
        content = make_content(1000)
        path = self.write_file("regular 文档/doc.bin", content)
        nri.run_all(
            self,
            args=lambda p: ["digest", str(p)],
            regular_path=path,
            expected_stdout=expected_output(content),
            valid_payload=content,
            tmp=self.tmp,
        )

    @nri.requires_toctou_preload
    def test_file_swapped_to_fifo_after_check_is_judged_on_opened_object(self):
        # Deterministic check/open swap: path-based stat is fed "regular
        # file" while open() really opens a data-ready FIFO. The digest must
        # be refused promptly with no digest and no blocking on the pipe.
        nri.run_toctou_all(
            self,
            args=lambda p: ["digest", str(p)],
            valid_payload=make_content(5000),
            tmp=self.tmp,
        )

    # -- read failure after a successful open (exit code 1) -------------
    #
    # A regular file may open fine and then have read() fail part-way
    # through. That cannot be staged reliably with chmod/renames, so the
    # LD_PRELOAD injector forces a real EIO on the target fd after an exact
    # number of delivered bytes.

    @requires_readfail_preload
    def test_read_error_after_partial_content_fails_with_exit_code_1(self):
        # More than one full chunk, and the offset below lands inside a
        # later chunk so several reads succeed before the error.
        content = make_content(3 * CHUNK_SIZE + 5)
        path = self.write_file("readfail/binary doc.dat", content)

        # Control first: without the fault the very same file is digested
        # successfully, so a failure below is attributable to the injected
        # read error rather than to a bad path, permissions, or setup.
        healthy = self.run_digest(str(path))
        self.assertEqual(healthy.returncode, 0, healthy.stderr)
        self.assertEqual(healthy.stdout, expected_output(content))

        # The pre-failure prefix deliberately contains a NUL byte and line
        # endings (see make_content's head), covering ordinary binary
        # documents rather than only plain text.
        self.assertIn(b"\x00", content[:CHUNK_SIZE])
        self.assertIn(b"\n", content[:CHUNK_SIZE])

        for after in (1, CHUNK_SIZE, CHUNK_SIZE + 4096, 2 * CHUNK_SIZE + 17):
            with self.subTest(after=after):
                result = self.run_digest_with_read_failure(path, after)

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b"")
                stderr = result.stderr
                self.assertTrue(stderr.endswith(b"\n"))
                # The message must describe a read failure (not an open or
                # usage failure) and name the path exactly as passed.
                self.assertIn(b"read", stderr.lower())
                self.assertNotIn(b"Usage", stderr)
                self.assertIn(os.fsencode(str(path)), stderr)

    @requires_readfail_preload
    def test_short_final_read_and_eof_are_not_treated_as_read_errors(self):
        # The injector is loaded but unarmed: read() is passed straight
        # through. A final read shorter than one chunk, a file ending
        # exactly on a chunk boundary, and an empty file must all remain
        # normal successes -- only a genuine read error may fail.
        for size in (0, 1, CHUNK_SIZE - 1, CHUNK_SIZE,
                     CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 13):
            with self.subTest(size=size):
                content = make_content(size)
                path = self.write_file(f"eof/{size}.bin", content)

                result = self.run_digest_preloaded(path)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, expected_output(content))

    @requires_readfail_preload
    def test_injected_fault_only_affects_the_target_file(self):
        target = self.write_file("iso/target.bin",
                                 make_content(2 * CHUNK_SIZE))
        other = self.write_file("iso/other.bin",
                                make_content(CHUNK_SIZE + 7))
        env = self._preload_env(
            READFAIL_PRELOAD,
            SEALMARK_READFAIL_PATH=str(target),
            SEALMARK_READFAIL_AFTER="10",
        )
        result = subprocess.run(
            [SEALMARK_BIN, "digest", str(other)],
            capture_output=True,
            env=env,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout,
                         expected_output(make_content(CHUNK_SIZE + 7)))

    # -- interrupted reads (EINTR) then recovery -------------------------
    #
    # read() on a regular file may return -1/EINTR when a signal arrives
    # before any data is transferred; the file position is unchanged and
    # the next read sees the same bytes. The digest must still cover the
    # file's complete raw bytes from start to finish -- never the digest of
    # the prefix read so far -- and must come out byte-identical to an
    # uninterrupted run of the same file. The eintr injector replays a
    # scripted schedule of interrupts/short reads and reports how many
    # interrupts it actually injected; every test asserts those counters so
    # the condition under test is proven to have occurred.

    def assert_interrupted_digest_matches(self, path, content, schedule):
        """Digest of `path` under the interrupt `schedule` must equal the
        digest of an uninterrupted run of the same file (and of hashlib),
        with the schedule's interrupts proven to have actually fired."""
        expected_eintr = schedule.split(",").count("E")
        schedule_len = len(schedule.split(","))

        # Control: the same file with no injector involved at all.
        normal = self.run_digest(str(path))
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(normal.stderr, b"")
        self.assertEqual(normal.stdout, expected_output(content))

        result, eintr_count, target_reads, consumed = (
            self.run_digest_with_eintr(path, schedule)
        )

        # The scripted interrupts really happened and the schedule was
        # replayed in full before EOF -- otherwise this test proves nothing.
        self.assertEqual(eintr_count, expected_eintr)
        self.assertEqual(consumed, schedule_len)
        self.assertGreaterEqual(target_reads, schedule_len)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertRegex(result.stdout, OUTPUT_RE)
        # The complete raw bytes, start to finish -- checked against an
        # independent SHA-256, not merely against another sealmark run.
        self.assertEqual(result.stdout, expected_output(content))
        # ... and byte-identical to the uninterrupted run of the same file.
        self.assertEqual(result.stdout, normal.stdout)
        # The operation must not rewrite the file it digests.
        self.assertEqual(path.read_bytes(), content)

    @requires_eintr_preload
    def test_eintr_on_the_very_first_read_still_yields_full_digest(self):
        # The interrupt arrives before a single byte has been read; the
        # file crosses a chunk boundary so several reads follow the retry.
        content = make_content(CHUNK_SIZE + 7)
        path = self.write_file("eintr/first-read 中断.bin", content)

        self.assert_interrupted_digest_matches(path, content, "E")

    @requires_eintr_preload
    def test_eintr_after_partial_content_still_yields_full_digest(self):
        # Some bytes are already delivered (a short read), then the next
        # read is interrupted; the digest must still run to the real EOF,
        # not stop at -- or restart from -- the interruption point.
        content = make_content(2 * CHUNK_SIZE + 13)
        path = self.write_file("eintr/mid-stream 文档.bin", content)

        # The content genuinely is the binary case: NUL bytes, line feeds
        # and high bytes, spread over more than one chunk.
        self.assertIn(b"\x00", content)
        self.assertIn(b"\n", content)
        self.assertTrue(any(byte > 0x7F for byte in content))
        self.assertGreater(len(content), CHUNK_SIZE)

        self.assert_interrupted_digest_matches(path, content, "S1000,E")

    @requires_eintr_preload
    def test_consecutive_eintrs_then_recovery_yields_full_digest(self):
        # Several interrupts in a row, mid-stream, before reads resume:
        # the result is the full file's SHA-256, not the prefix read so far.
        content = make_content(3 * CHUNK_SIZE + 5)
        path = self.write_file("eintr/consecutive.bin", content)

        self.assert_interrupted_digest_matches(path, content, "S4096,E,E,E")

    @requires_eintr_preload
    def test_short_reads_around_interrupts_are_not_mistaken_for_eof(self):
        # A read returning fewer bytes than requested -- including a single
        # byte -- is not EOF while content remains. Short reads before,
        # after and between interrupts must all be accumulated, and the
        # final tail of the file must be included exactly once.
        content = make_content(CHUNK_SIZE + 300)
        path = self.write_file("eintr/short-reads.bin", content)

        self.assert_interrupted_digest_matches(
            path, content, "S1,E,S7,S64,E,S8192"
        )

    @requires_eintr_preload
    def test_empty_file_with_interrupted_first_read_has_empty_digest(self):
        # Even for an empty file, an interrupt on the first read is
        # retried; the following normal EOF yields the standard empty
        # digest, not a read failure.
        path = self.write_file("eintr/empty.bin", b"")

        result, eintr_count, _, consumed = self.run_digest_with_eintr(
            path, "E"
        )

        self.assertEqual(eintr_count, 1)
        self.assertEqual(consumed, 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout, f"sha256:{EMPTY_FILE_SHA256}\n".encode("ascii")
        )
        self.assertEqual(path.read_bytes(), b"")

    @requires_eintr_preload
    def test_eintr_recovery_then_genuine_read_error_fails(self):
        # Interrupts are retried, but a genuine I/O error once reads have
        # resumed is still a read failure -- even though partial content
        # was already delivered successfully. No prefix digest and no
        # success output may be produced.
        content = make_content(2 * CHUNK_SIZE + 17)
        path = self.write_file("eintr/then-eio.bin", content)

        # Control first: without the final EIO the very same interruption
        # schedule recovers and digests the complete file.
        healthy, eintr_count, _, _ = self.run_digest_with_eintr(
            path, "S500,E"
        )
        self.assertEqual(eintr_count, 1)
        self.assertEqual(healthy.returncode, 0, healthy.stderr)
        self.assertEqual(healthy.stdout, expected_output(content))

        result, eintr_count, _, consumed = self.run_digest_with_eintr(
            path, "S500,E,F"
        )

        # The interrupt fired and was survived; the subsequent genuine
        # error is what failed the run.
        self.assertEqual(eintr_count, 1)
        self.assertEqual(consumed, 3)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        stderr = result.stderr
        self.assertTrue(stderr.endswith(b"\n"))
        # A read failure (not an open or usage failure) naming the path
        # exactly as passed; no digest or success line anywhere.
        self.assertIn(b"read", stderr.lower())
        self.assertNotIn(b"Usage", stderr)
        self.assertIn(os.fsencode(str(path)), stderr)
        self.assertNotIn(b"sha256:", stderr)
        self.assertEqual(path.read_bytes(), content)

    @requires_eintr_preload
    def test_eintr_injector_only_affects_the_target_file(self):
        target = self.write_file("eintr-iso/target.bin",
                                 make_content(CHUNK_SIZE + 7))
        other = self.write_file("eintr-iso/other.bin",
                                make_content(CHUNK_SIZE + 7))
        stats_fd, stats_path = tempfile.mkstemp(
            prefix="eintr-stats-", dir=self.tmp
        )
        os.close(stats_fd)
        env = self._preload_env(
            EINTR_PRELOAD,
            SEALMARK_EINTR_PATH=str(target),
            SEALMARK_EINTR_SCHEDULE="E,E",
            SEALMARK_EINTR_STATS=stats_path,
        )
        result = subprocess.run(
            [SEALMARK_BIN, "digest", str(other)],
            capture_output=True,
            env=env,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout,
                         expected_output(make_content(CHUNK_SIZE + 7)))
        # No interrupt was injected: the scheduled directives stayed
        # unconsumed because the target file was never read.
        counters = Path(stats_path).read_text(encoding="ascii").split()
        self.assertEqual(int(counters[0]), 0)

    # -- usage failures (exit code 2) ------------------------------------

    def assertUsageError(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage", result.stderr)
        self.assertIn(b"digest", result.stderr)

    def test_missing_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("digest"))

    def test_empty_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("digest", ""))

    def test_extra_argument_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        self.assertUsageError(self.run_sealmark("digest", str(path), "extra"))

    def test_unknown_command_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("frobnicate", "x"))

    def test_no_arguments_is_usage_error(self):
        self.assertUsageError(self.run_sealmark())

    # -- pre-existing feature kept compatible ----------------------------

    def test_version_output(self):
        result = self.run_sealmark("--version")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"sealmark 0.1.0\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
