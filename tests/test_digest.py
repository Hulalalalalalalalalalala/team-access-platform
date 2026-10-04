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
* missing or empty path argument (and other usage errors): exit code 2
  with the usage text on stderr.

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

# Must match the read buffer size in src/main.cpp.
CHUNK_SIZE = 64 * 1024

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")

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
