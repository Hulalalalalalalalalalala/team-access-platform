#!/usr/bin/env python3
"""Regression tests for ``sealmark verify-digest``.

The verify-digest contract under test (see README):

* match: the file's SHA-256 equals the expected digest argument -- stdout is
  exactly ``match\\n``, stderr empty, exit code 0;
* mismatch: the file was read and hashed successfully but the digests differ
  -- stdout is exactly ``mismatch\\n``, stderr empty, exit code 3;
* the compared bytes are the file's complete raw bytes (same rules as
  ``digest``), so renaming/moving identical content still matches and an
  empty file verifies;
* the expected digest must be exactly ``sha256:`` plus 64 lowercase hex
  digits -- missing arguments, extra arguments, an empty path, an omitted
  prefix, uppercase letters, another algorithm name, embedded/extra
  whitespace (including a trailing newline) or trailing content are usage
  errors: empty stdout, the usage text (mentioning verify-digest) on stderr,
  exit code 2. Argument problems take precedence over file problems;
* a missing path, a non-regular file or an unreadable file: empty stdout, a
  stderr message containing the path, exit code 1 -- never ``mismatch`` and
  never a success result.

The expected digest is meant to be a line previously produced by
``sealmark digest``; the end-to-end round trip is exercised here as well.

All test content and paths are created inside a fresh temporary directory.
The path to the sealmark executable is taken from $SEALMARK_BIN.
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
        return subprocess.run(
            [SEALMARK_BIN, *args],
            capture_output=True,
        )

    def run_verify(self, path_arg, digest_arg):
        return self.run_sealmark("verify-digest", path_arg, digest_arg)

    def write_file(self, relative_path, content):
        path = self.tmp / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def assertMatch(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"match\n")
        self.assertEqual(result.stderr, b"")

    def assertMismatch(self, result):
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stdout, b"mismatch\n")
        self.assertEqual(result.stderr, b"")

    def assertUsageError(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage", result.stderr)
        self.assertIn(b"verify-digest", result.stderr)

    # -- match -----------------------------------------------------------

    def test_match_across_sizes_including_empty_and_chunk_boundaries(self):
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

                result = self.run_verify(str(path), digest_of(content))

                self.assertMatch(result)

    def test_empty_file_matches_known_empty_digest(self):
        path = self.write_file("empty.dat", b"")

        result = self.run_verify(str(path), f"sha256:{EMPTY_FILE_SHA256}")

        self.assertMatch(result)

    def test_digest_command_output_line_verifies_directly(self):
        # End-to-end: the exact line ``digest`` prints (minus its line ending)
        # is accepted verbatim as the expected-digest argument.
        content = make_content(2 * CHUNK_SIZE + 13)
        path = self.write_file("roundtrip.bin", content)

        digest_result = self.run_sealmark("digest", str(path))
        self.assertEqual(digest_result.returncode, 0, digest_result.stderr)
        recorded_line = digest_result.stdout.decode("ascii")
        self.assertTrue(recorded_line.endswith("\n"))
        recorded = recorded_line.rstrip("\n")

        self.assertMatch(self.run_verify(str(path), recorded))

    def test_renamed_and_moved_copy_of_same_bytes_matches(self):
        content = make_content(CHUNK_SIZE + 37)
        original = self.write_file("dir a/original name.bin", content)
        moved = self.tmp / "目录" / "报告 副本.pdf"
        moved.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(original), str(moved))

        self.assertMatch(self.run_verify(str(moved), digest_of(content)))

    def test_raw_bytes_participate_including_nul_at_boundary(self):
        content = make_content(CHUNK_SIZE) + b"\x00"
        path = self.write_file("straddle/nul-tail.bin", content)

        self.assertMatch(self.run_verify(str(path), digest_of(content)))

    # -- mismatch --------------------------------------------------------

    def test_changed_content_is_mismatch_exit_code_3(self):
        base = make_content(3 * CHUNK_SIZE + 5)
        changed = base[:-1] + bytes([base[-1] ^ 0xA5])
        self.assertNotEqual(base, changed)
        path = self.write_file("changed.bin", changed)

        self.assertMismatch(self.run_verify(str(path), digest_of(base)))

    def test_one_byte_change_mismatches(self):
        path = self.write_file("one.bin", b"a")

        self.assertMismatch(
            self.run_verify(str(path), digest_of(b"b"))
        )

    def test_empty_file_mismatches_any_nonempty_digest(self):
        path = self.write_file("empty.dat", b"")

        self.assertMismatch(self.run_verify(str(path), digest_of(b"x")))

    def test_nonempty_file_mismatches_empty_content_digest(self):
        path = self.write_file("nonempty.dat", b"x")

        self.assertMismatch(
            self.run_verify(str(path), f"sha256:{EMPTY_FILE_SHA256}")
        )

    # -- usage errors (exit code 2) --------------------------------------

    def test_missing_digest_argument_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        self.assertUsageError(self.run_sealmark("verify-digest", str(path)))

    def test_missing_both_arguments_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("verify-digest"))

    def test_extra_argument_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        self.assertUsageError(
            self.run_sealmark(
                "verify-digest", str(path), digest_of(b"hello"), "extra"
            )
        )

    def test_empty_path_is_usage_error(self):
        self.assertUsageError(
            self.run_sealmark("verify-digest", "", digest_of(b""))
        )

    def test_empty_digest_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        self.assertUsageError(self.run_sealmark("verify-digest", str(path), ""))

    def test_digest_without_prefix_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        bare = digest_of(b"hello")[len("sha256:"):]
        self.assertUsageError(self.run_verify(str(path), bare))

    def test_uppercase_hex_is_usage_error(self):
        path = self.write_file("x.bin", b"hello")
        good = digest_of(b"hello")
        self.assertUsageError(self.run_verify(str(path), good.upper()))
        self.assertUsageError(
            self.run_verify(str(path), "sha256:" + good[len("sha256:"):].upper())
        )

    def test_other_algorithm_names_are_usage_errors(self):
        path = self.write_file("x.bin", b"hello")
        hex64 = digest_of(b"hello")[len("sha256:"):]
        for bad in (
            f"sha1:{hex64}",
            f"md5:{hex64}",
            f"SHA256:{hex64}",
            f"sha-256:{hex64}",
            f"sha512:{hex64}",
        ):
            with self.subTest(bad=bad):
                self.assertUsageError(self.run_verify(str(path), bad))

    def test_extra_whitespace_and_trailing_content_are_usage_errors(self):
        path = self.write_file("x.bin", b"hello")
        good = digest_of(b"hello")
        for bad in (
            " " + good,
            good + " ",
            "\t" + good,
            good + "\t",
            good + "\n",   # a line ending must not be part of the argument
            "\n" + good,
            good + "x",
            good[:-1],     # 63 hex digits
            good + "0",    # 65 hex digits
            good[:-1] + "g",  # non-hex character
            "sha256:" + ("0" * 63),
            "sha256:" + ("0" * 65),
            "sha256:",
        ):
            with self.subTest(bad=bad):
                self.assertUsageError(self.run_verify(str(path), bad))

    def test_usage_error_takes_precedence_over_missing_file(self):
        missing = self.tmp / "does not exist.bin"
        self.assertFalse(missing.exists())

        # Bad digest format AND bad path: must be the usage error, never a
        # file error or a mismatch.
        result = self.run_verify(str(missing), "not-a-digest")
        self.assertUsageError(result)

    def test_usage_error_takes_precedence_over_directory(self):
        directory = self.tmp / "a directory"
        directory.mkdir()

        result = self.run_verify(str(directory), "sha256:xyz")
        self.assertUsageError(result)

    # -- file failures (exit code 1) -------------------------------------

    def test_nonexistent_path_fails_with_exit_code_1(self):
        missing = self.tmp / "目录" / "missing file.bin"
        self.assertFalse(missing.exists())

        result = self.run_verify(str(missing), digest_of(b""))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(missing)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        self.assertNotIn(b"mismatch", result.stderr)
        self.assertNotIn(b"match", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def test_directory_fails_with_exit_code_1(self):
        directory = self.tmp / "a directory"
        directory.mkdir()

        result = self.run_verify(str(directory), digest_of(b""))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(directory)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        self.assertNotIn(b"mismatch", result.stderr)

    # -- pre-existing features kept compatible ---------------------------

    def test_version_unchanged(self):
        result = self.run_sealmark("--version")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"sealmark 0.1.0\n")

    def test_digest_still_works(self):
        content = make_content(CHUNK_SIZE + 7)
        path = self.write_file("digest/kept.bin", content)

        result = self.run_sealmark("digest", str(path))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout, (digest_of(content) + "\n").encode("ascii")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
