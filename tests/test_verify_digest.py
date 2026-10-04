#!/usr/bin/env python3
"""Regression tests for ``sealmark verify-digest``.

The verify-digest contract under test (see README):

* match:   exit code 0, empty stderr, stdout is exactly ``match\\n``;
* mismatch: exit code 3, empty stderr, stdout is exactly ``mismatch\\n``;
* the compared digest is the standard SHA-256 of the file's complete raw
  bytes -- renaming/moving the file does not matter, empty files work, and
  binary/NUL/whitespace bytes all count;
* the expected digest must be exactly ``sha256:`` plus 64 lowercase hex
  digits -- missing prefix, uppercase, other algorithm names, surrounding
  whitespace, trailing content and wrong lengths are all usage errors;
* usage errors (missing/extra/empty arguments, malformed digest, even when
  the path is also bad): exit code 2, empty stdout, usage text on stderr
  mentioning the new command -- never reported as a mismatch;
* unreadable / missing / non-regular file or digest-computation failure:
  exit code 1, empty stdout, stderr names the path, and no success output.

All test content and paths are created inside a fresh temporary directory.
The executable path comes from $SEALMARK_BIN (wired up by CTest).
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

# Must match the read buffer size in src/main.cpp.
CHUNK_SIZE = 64 * 1024

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")

EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Bytes naive text-oriented handling tends to drop, translate or strip.
_HEAD = (
    b"\x00"
    b"\n\r\n"
    b"\xef\xbb\xbf"      # UTF-8 BOM
    b"\xff\xfe"          # UTF-16 LE BOM
    b"\xfe\xff"          # UTF-16 BE BOM
    + bytes(range(256))
)
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


def digest_of(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


class SealmarkVerifyDigestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SEALMARK_BIN:
            raise RuntimeError(
                "SEALMARK_BIN is not set; point it at the sealmark executable"
            )
        if not Path(SEALMARK_BIN).is_file():
            raise RuntimeError(f"SEALMARK_BIN does not point to a file: {SEALMARK_BIN}")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sealmark-verify-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_sealmark(self, *args):
        return subprocess.run([SEALMARK_BIN, *args], capture_output=True)

    def run_verify(self, path_arg, digest_arg):
        return self.run_sealmark("verify-digest", path_arg, digest_arg)

    def write_file(self, relative_path, content):
        path = self.tmp / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    # -- match -----------------------------------------------------------

    def assertMatch(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"match\n")
        self.assertEqual(result.stderr, b"")

    def assertMismatch(self, result):
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"mismatch\n")
        self.assertEqual(result.stderr, b"")

    def test_match_for_independent_sha256_across_chunk_boundaries(self):
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
                self.assertMatch(self.run_verify(str(path), digest_of(content)))

    def test_empty_file_matches_standard_empty_digest(self):
        path = self.write_file("empty.dat", b"")
        self.assertMatch(self.run_verify(str(path), f"sha256:{EMPTY_FILE_SHA256}"))

    def test_digest_command_output_line_is_accepted_as_expected_digest(self):
        # The expected digest is literally the line `digest` prints, with
        # only its terminating newline removed.
        content = make_content(CHUNK_SIZE + 37)
        path = self.write_file("line/from-digest.bin", content)

        digest_result = self.run_sealmark("digest", str(path))
        self.assertEqual(digest_result.returncode, 0, digest_result.stderr)
        self.assertTrue(digest_result.stdout.endswith(b"\n"))
        recorded_line = digest_result.stdout[:-1].decode("ascii")

        self.assertMatch(self.run_verify(str(path), recorded_line))

    def test_renamed_and_moved_file_with_same_content_matches(self):
        content = make_content(CHUNK_SIZE + 37)
        original = self.write_file("old name/原文件.bin", content)
        moved = self.tmp / "another 目录" / "renamed copy.pdf"
        moved.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(original), str(moved))

        self.assertMatch(self.run_verify(str(moved), digest_of(content)))

    def test_binary_and_whitespace_bytes_participate(self):
        content = make_content(CHUNK_SIZE) + b"\x00"
        path = self.write_file("straddle/nul-tail.bin", content)
        self.assertMatch(self.run_verify(str(path), digest_of(content)))

    # -- mismatch --------------------------------------------------------

    def test_one_byte_change_gives_mismatch_exit_code_3(self):
        content = make_content(CHUNK_SIZE + 5)
        path = self.write_file("changed.bin", content)

        self.assertMismatch(self.run_verify(str(path), digest_of(content + b"x")))

    def test_last_hex_digit_flipped_gives_mismatch(self):
        # A well-formed digest that differs in a single hex character.
        content = b"hello"
        path = self.write_file("hello.txt", content)
        good = digest_of(content)
        flipped = good[:-1] + ("0" if good[-1] != "0" else "1")
        self.assertNotEqual(flipped, good)

        self.assertMismatch(self.run_verify(str(path), flipped))

    def test_empty_file_digest_does_not_match_nonempty_file(self):
        path = self.write_file("nonempty.txt", b"x")
        self.assertMismatch(self.run_verify(str(path), f"sha256:{EMPTY_FILE_SHA256}"))

    # -- usage errors (exit code 2) -------------------------------------

    def assertUsageError(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage", result.stderr)
        self.assertIn(b"verify-digest", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def test_missing_arguments_are_usage_errors(self):
        self.assertUsageError(self.run_sealmark("verify-digest"))
        path = self.write_file("x.bin", b"x")
        self.assertUsageError(self.run_sealmark("verify-digest", str(path)))

    def test_extra_argument_is_usage_error(self):
        path = self.write_file("x.bin", b"x")
        self.assertUsageError(
            self.run_sealmark(
                "verify-digest", str(path), f"sha256:{EMPTY_FILE_SHA256}", "extra"
            )
        )

    def test_empty_path_is_usage_error(self):
        self.assertUsageError(
            self.run_sealmark("verify-digest", "", f"sha256:{EMPTY_FILE_SHA256}")
        )

    def test_empty_digest_is_usage_error(self):
        path = self.write_file("x.bin", b"x")
        self.assertUsageError(self.run_sealmark("verify-digest", str(path), ""))

    def test_malformed_digests_are_usage_errors(self):
        path = self.write_file("x.bin", b"x")
        good = f"sha256:{EMPTY_FILE_SHA256}"
        bad_digests = [
            good[len("sha256:"):],              # prefix omitted
            "SHA256:" + good[len("sha256:"):],  # uppercase prefix
            "sha256:" + good[len("sha256:"):].upper(),  # uppercase hex
            "sha1:" + "a" * 40,                 # other algorithm name
            "sha256:" + good[len("sha256:"):-1],   # one hex digit short
            good + "0",                         # trailing hex digit
            " " + good,                         # leading whitespace
            good + " ",                         # trailing whitespace
            good + "\n",                        # trailing newline
            "sha256:" + "g" * 64,               # non-hex characters
            "sha256:" + "A" * 64,
            "sha256:" + ("0" * 63),
            "sha256:" + ("0" * 65),
            good.replace("sha256:", "sha256 :"),
            "sha256:" + ("0" * 32) + " " + ("0" * 31),
        ]
        for bad in bad_digests:
            with self.subTest(bad=bad):
                self.assertUsageError(self.run_verify(str(path), bad))

    def test_bad_path_and_bad_digest_reports_usage_error_first(self):
        # Argument problems take priority: this must not become exit 1 or
        # exit 3 just because the path does not exist.
        missing = self.tmp / "no such file.bin"
        self.assertFalse(missing.exists())

        self.assertUsageError(self.run_verify(str(missing), "not-a-digest"))

    def test_empty_path_with_bad_digest_is_usage_error(self):
        self.assertUsageError(self.run_verify("", "nope"))

    # -- file failures (exit code 1) ------------------------------------

    def assertFileFailure(self, result, path):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(path)), result.stderr)
        self.assertNotIn(b"mismatch", result.stderr)
        self.assertNotIn(b"match", result.stderr)

    def test_nonexistent_path_fails_with_exit_code_1(self):
        missing = self.tmp / "目录" / "missing file.bin"
        result = self.run_verify(str(missing), f"sha256:{EMPTY_FILE_SHA256}")
        self.assertFileFailure(result, missing)

    def test_directory_fails_with_exit_code_1(self):
        directory = self.tmp / "a directory"
        directory.mkdir()
        result = self.run_verify(str(directory), f"sha256:{EMPTY_FILE_SHA256}")
        self.assertFileFailure(result, directory)

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses file permission bits",
    )
    def test_unreadable_file_fails_with_exit_code_1(self):
        path = self.write_file("secret.bin", b"cannot read me")
        path.chmod(0o000)
        self.addCleanup(lambda: path.chmod(0o644))

        result = self.run_verify(str(path), digest_of(b"cannot read me"))
        self.assertFileFailure(result, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
