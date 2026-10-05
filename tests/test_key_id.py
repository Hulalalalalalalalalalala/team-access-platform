#!/usr/bin/env python3
"""Regression tests for ``sealmark key-id``.

The key-id contract under test (see README):

* the input is a regular file holding exactly one PEM ``PUBLIC KEY`` block
  wrapping a SubjectPublicKeyInfo public key (RSA and Ed25519 covered here);
* the fingerprint is the SHA-256 of the key's SubjectPublicKeyInfo DER
  encoding -- the algorithm identifier and the public key value, never the
  file name, path, or PEM text layout;
* success: exit code 0, empty stderr, stdout is exactly one line
  ``spki-sha256:<64 lowercase hex digits>`` terminated by a single newline;
* LF vs CRLF line endings, different legal base64 line wrapping, leading or
  trailing ASCII whitespace, and renaming or moving the file all leave the
  fingerprint unchanged;
* anything but one public-key block -- an empty file, truncated or corrupt
  base64/DER, multiple blocks, non-whitespace content around the block,
  private keys, certificates, or other public-key wrappers (PKCS#1) -- is
  rejected with exit code 1, empty stdout, and a stderr message naming the
  path as passed; no partial fingerprint is ever printed;
* missing path / directory: exit code 1 with the path in stderr;
* a mid-read failure after a successful open: exit code 1 (via the same
  LD_PRELOAD fault injector the digest tests use);
* missing or empty path argument (and other usage errors): exit code 2 with
  usage text mentioning ``key-id`` on stderr.

The expected fingerprints are known answers checked against OpenSSL
(``openssl pkey -pubin -outform DER | sha256sum``) and recomputed here with
hashlib over the independently base64-decoded DER, so the test does not
merely compare sealmark against itself.

All test content and paths are created by the tests themselves inside a
fresh temporary directory. The path to the sealmark executable is taken
from $SEALMARK_BIN (wired up by CTest via the CMakeLists.txt add_test
entry).
"""

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")

# Path to the LD_PRELOAD fault injector built by CMake (Linux only).
READFAIL_PRELOAD = os.environ.get("SEALMARK_READFAIL_PRELOAD")

requires_readfail_preload = unittest.skipUnless(
    READFAIL_PRELOAD and Path(READFAIL_PRELOAD).is_file(),
    "SEALMARK_READFAIL_PRELOAD is unavailable; mid-read failure cannot be "
    "injected on this platform",
)

OUTPUT_RE = re.compile(rb"\Aspki-sha256:[0-9a-f]{64}\n\Z")

RSA_PUBLIC_PEM = """\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIbLxPSSXwTYniBHh6O7
wbeYSLlTZwWeRls8VY5XNIodIS/Rok1TkAQ8B8hsF9dZg+1ftyPSLkfA8EEqQmfq
Qm73RHPTcIpTChacC9SyGmBPYUsstF1I/R8fJJ30mq85yZi5I4UjUwo1Xk2nUbDd
xQkmMhYCm+VrqmlsP0YRPvNWx0SsHF0PyzmGODVgLI0WkjV++8P7TZ32+lGcfuJ6
37CtDS328rLvCR+epwKBtLLxVdU6WgRbAfzDBwnl9ACbO/DyZ0eqd8MgMGwDm0og
NfOQ1T5+uvmDL0fWd9Lkhs1cppOw36DHIyzlnUZr5E2Y1ZfGoiZMHfyaqD5V0Or1
vQIDAQAB
-----END PUBLIC KEY-----
"""

ED25519_PUBLIC_PEM = """\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+QTgGfZovw0wnlKgWt39iLh7A+3X4X2GpNqN2qjDrx8=
-----END PUBLIC KEY-----
"""

# Known answers: SHA-256 of the SubjectPublicKeyInfo DER, computed with
# ``openssl pkey -pubin -outform DER | sha256sum``.
RSA_SPKI_SHA256 = "76418149c2503b263fe066c0c777d79c79cf2ee840381b68868f7a25172171c1"
ED25519_SPKI_SHA256 = "68bcc4608c51a886c7dd33e9a6656781a1d4edec6a334bae5d687a9e9bee7fac"

# A PKCS#1 RSA public key ("BEGIN RSA PUBLIC KEY"): a different public-key
# wrapper around the same RSA key, which key-id must reject.
RSA_PKCS1_PUBLIC_PEM = """\
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArIbLxPSSXwTYniBHh6O7wbeYSLlTZwWeRls8VY5XNIodIS/Rok1T
kAQ8B8hsF9dZg+1ftyPSLkfA8EEqQmfqQm73RHPTcIpTChacC9SyGmBPYUsstF1I
/R8fJJ30mq85yZi5I4UjUwo1Xk2nUbDdxQkmMhYCm+VrqmlsP0YRPvNWx0SsHF0P
yzmGODVgLI0WkjV++8P7TZ32+lGcfuJ637CtDS328rLvCR+epwKBtLLxVdU6WgRb
AfzDBwnl9ACbO/DyZ0eqd8MgMGwDm0ogNfOQ1T5+uvmDL0fWd9Lkhs1cppOw36DH
IyzlnUZr5E2Y1ZfGoiZMHfyaqD5V0Or1vQIDAQAB
-----END RSA PUBLIC KEY-----
"""


def pem_der(pem_text):
    """Independently decode the base64 body of a one-block PEM string."""
    lines = pem_text.strip().splitlines()
    assert lines[0].startswith("-----BEGIN ") and lines[-1].startswith("-----END ")
    return base64.b64decode("".join(lines[1:-1]), validate=True)


def expected_output(pem_text):
    digest = hashlib.sha256(pem_der(pem_text)).hexdigest()
    return f"spki-sha256:{digest}\n".encode("ascii")


def rewrap_pem(pem_text, width, newline="\n", prefix=b"", suffix=b""):
    """Re-encode a PEM string with a different base64 line width, line
    ending, and optional surrounding ASCII whitespace."""
    der = pem_der(pem_text)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + width] for i in range(0, len(b64), width)]
    out = newline.join(["-----BEGIN PUBLIC KEY-----", *lines,
                        "-----END PUBLIC KEY-----", ""])
    return prefix + out.encode("ascii") + suffix


class SealmarkKeyIdTest(unittest.TestCase):
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

    def run_key_id(self, path_arg):
        return self.run_sealmark("key-id", path_arg)

    def write_file(self, relative_path, content):
        path = self.tmp / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            content = content.encode("ascii")
        path.write_bytes(content)
        return path

    # -- success ---------------------------------------------------------

    def test_rsa_and_ed25519_known_answer_fingerprints(self):
        cases = [
            ("rsa.pem", RSA_PUBLIC_PEM, RSA_SPKI_SHA256),
            ("ed25519.pem", ED25519_PUBLIC_PEM, ED25519_SPKI_SHA256),
        ]
        for name, pem, known_answer in cases:
            with self.subTest(name=name):
                path = self.write_file(name, pem)

                result = self.run_key_id(str(path))

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                # Exact wire contract: one line, trailing newline, nothing else.
                self.assertRegex(result.stdout, OUTPUT_RE)
                self.assertEqual(len(result.stdout), len("spki-sha256:") + 64 + 1)
                # Known-answer check against OpenSSL's SPKI DER SHA-256...
                self.assertEqual(
                    result.stdout, f"spki-sha256:{known_answer}\n".encode("ascii")
                )
                # ...and against an independent hashlib computation over the
                # base64-decoded DER.
                self.assertEqual(result.stdout, expected_output(pem))

    def test_distinct_keys_have_distinct_fingerprints(self):
        rsa_path = self.write_file("a.pem", RSA_PUBLIC_PEM)
        ed_path = self.write_file("b.pem", ED25519_PUBLIC_PEM)

        rsa_result = self.run_key_id(str(rsa_path))
        ed_result = self.run_key_id(str(ed_path))

        self.assertEqual(rsa_result.returncode, 0, rsa_result.stderr)
        self.assertEqual(ed_result.returncode, 0, ed_result.stderr)
        self.assertNotEqual(rsa_result.stdout, ed_result.stdout)

    def test_pem_layout_does_not_change_fingerprint(self):
        reference = expected_output(RSA_PUBLIC_PEM)
        variants = {
            # CRLF line endings throughout.
            "crlf.pem": RSA_PUBLIC_PEM.replace("\n", "\r\n").encode("ascii"),
            # Legal base64 re-wrapped at 16 and 100 columns, and one
            # unbroken base64 line.
            "wrap16.pem": rewrap_pem(RSA_PUBLIC_PEM, 16),
            "wrap100.pem": rewrap_pem(RSA_PUBLIC_PEM, 100),
            "oneline.pem": rewrap_pem(RSA_PUBLIC_PEM, 1 << 20),
            # Blank lines and other ASCII whitespace inside the base64 body.
            "airy.pem": rewrap_pem(RSA_PUBLIC_PEM, 32, newline="\n\n"),
            # ASCII whitespace (spaces, tabs, blank lines) around the block.
            "padded.pem": rewrap_pem(
                RSA_PUBLIC_PEM, 64, prefix=b" \t \n\n", suffix=b"\n \t\n"
            ),
            # CRLF re-wrap with surrounding whitespace combined.
            "mixed.pem": rewrap_pem(
                RSA_PUBLIC_PEM, 24, newline="\r\n", prefix=b"\n", suffix=b"\r\n"
            ),
        }
        for name, content in variants.items():
            with self.subTest(name=name):
                path = self.write_file(name, content)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, reference)

    def test_same_key_fingerprints_identically_under_various_names(self):
        names = [
            "plain.pem",
            "nested/dir/key.pub",
            "with space/public key.pem",
            "目录/公钥 副本.pem",
        ]
        outputs = set()
        for name in names:
            with self.subTest(name=name):
                path = self.write_file(Path(name), RSA_PUBLIC_PEM)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout, expected_output(RSA_PUBLIC_PEM))
                outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)

    def test_input_file_is_not_modified(self):
        path = self.write_file("untouched.pem", RSA_PUBLIC_PEM)
        before = path.read_bytes()

        result = self.run_key_id(str(path))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), before)

    # -- invalid key content (exit code 1) --------------------------------

    def assertInvalidContent(self, name, content):
        path = self.write_file(name, content)
        result = self.run_key_id(str(path))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.stderr, b"")
        self.assertTrue(result.stderr.endswith(b"\n"))
        self.assertIn(os.fsencode(str(path)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        # No partial fingerprint may leak onto either stream.
        self.assertNotIn(b"spki-sha256:", result.stderr)

    def test_empty_file_is_invalid(self):
        self.assertInvalidContent("empty.pem", b"")

    def test_whitespace_only_file_is_invalid(self):
        self.assertInvalidContent("blank.pem", b" \t\n\r\n \n")

    def test_two_public_key_blocks_are_invalid(self):
        self.assertInvalidContent(
            "two.pem", RSA_PUBLIC_PEM + "\n" + ED25519_PUBLIC_PEM
        )

    def test_same_block_twice_is_invalid(self):
        self.assertInvalidContent("twice.pem", RSA_PUBLIC_PEM + RSA_PUBLIC_PEM)

    def test_content_before_block_is_invalid(self):
        self.assertInvalidContent("prefix.pem", "junk\n" + RSA_PUBLIC_PEM)

    def test_content_after_block_is_invalid(self):
        self.assertInvalidContent("suffix.pem", RSA_PUBLIC_PEM + "junk\n")

    def test_private_key_is_invalid(self):
        body = base64.b64encode(pem_der(RSA_PUBLIC_PEM)).decode("ascii")
        private_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            + textwrap.fill(body, 64)
            + "\n-----END PRIVATE KEY-----\n"
        )
        self.assertInvalidContent("private.pem", private_pem)

    def test_rsa_private_key_label_is_invalid(self):
        body = base64.b64encode(pem_der(RSA_PUBLIC_PEM)).decode("ascii")
        private_pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + textwrap.fill(body, 64)
            + "\n-----END RSA PRIVATE KEY-----\n"
        )
        self.assertInvalidContent("rsa-private.pem", private_pem)

    def test_certificate_is_invalid(self):
        # A certificate-shaped block: same base64 payload, CERTIFICATE label.
        body = base64.b64encode(pem_der(ED25519_PUBLIC_PEM)).decode("ascii")
        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + textwrap.fill(body, 64)
            + "\n-----END CERTIFICATE-----\n"
        )
        self.assertInvalidContent("cert.pem", cert_pem)

    def test_pkcs1_public_key_wrapper_is_invalid(self):
        # "BEGIN RSA PUBLIC KEY" is a different public-key format (PKCS#1),
        # not a SubjectPublicKeyInfo "PUBLIC KEY" block.
        self.assertInvalidContent("pkcs1.pem", RSA_PKCS1_PUBLIC_PEM)

    def test_truncated_pem_is_invalid(self):
        self.assertInvalidContent(
            "truncated.pem", RSA_PUBLIC_PEM[: len(RSA_PUBLIC_PEM) // 2]
        )

    def test_missing_end_marker_is_invalid(self):
        self.assertInvalidContent(
            "no-end.pem", RSA_PUBLIC_PEM.rsplit("-----END", 1)[0]
        )

    def test_missing_begin_marker_is_invalid(self):
        self.assertInvalidContent(
            "no-begin.pem", RSA_PUBLIC_PEM.split("\n", 1)[1]
        )

    def test_corrupt_base64_is_invalid(self):
        corrupted = RSA_PUBLIC_PEM.replace("MIIB", "M!IB", 1)
        self.assertNotEqual(corrupted, RSA_PUBLIC_PEM)
        self.assertInvalidContent("corrupt.pem", corrupted)

    def test_base64_of_garbage_is_invalid(self):
        garbage_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + textwrap.fill(base64.b64encode(b"not a key at all").decode("ascii"), 64)
            + "\n-----END PUBLIC KEY-----\n"
        )
        self.assertInvalidContent("garbage.pem", garbage_pem)

    def test_truncated_der_is_invalid(self):
        der = pem_der(ED25519_PUBLIC_PEM)
        truncated = der[: len(der) - 4]
        truncated_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + textwrap.fill(base64.b64encode(truncated).decode("ascii"), 64)
            + "\n-----END PUBLIC KEY-----\n"
        )
        self.assertInvalidContent("truncated-der.pem", truncated_pem)

    def test_der_with_trailing_garbage_is_invalid(self):
        der = pem_der(ED25519_PUBLIC_PEM) + b"\x00\x00"
        padded_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + textwrap.fill(base64.b64encode(der).decode("ascii"), 64)
            + "\n-----END PUBLIC KEY-----\n"
        )
        self.assertInvalidContent("trailing-der.pem", padded_pem)

    # -- path failures (exit code 1) --------------------------------------

    def test_nonexistent_path_fails_with_exit_code_1(self):
        missing = self.tmp / "目录" / "missing key.pem"
        self.assertFalse(missing.exists())

        result = self.run_key_id(str(missing))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(missing)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def test_directory_fails_with_exit_code_1(self):
        directory = self.tmp / "a directory"
        directory.mkdir()

        result = self.run_key_id(str(directory))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(directory)), result.stderr)
        self.assertNotIn(b"Usage", result.stderr)

    # -- read failure after a successful open (exit code 1) ---------------

    @requires_readfail_preload
    def test_read_error_after_partial_content_fails_with_exit_code_1(self):
        path = self.write_file("readfail/key.pem", RSA_PUBLIC_PEM)

        # Control first: without the fault the same file fingerprints fine.
        healthy = self.run_key_id(str(path))
        self.assertEqual(healthy.returncode, 0, healthy.stderr)
        self.assertEqual(healthy.stdout, expected_output(RSA_PUBLIC_PEM))

        env = dict(os.environ)
        preload = READFAIL_PRELOAD
        if env.get("LD_PRELOAD"):
            preload = preload + ":" + env["LD_PRELOAD"]
        env["LD_PRELOAD"] = preload
        env["SEALMARK_READFAIL_PATH"] = str(path)
        env["SEALMARK_READFAIL_AFTER"] = "10"
        result = subprocess.run(
            [SEALMARK_BIN, "key-id", str(path)],
            capture_output=True,
            env=env,
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"read", result.stderr.lower())
        self.assertNotIn(b"Usage", result.stderr)
        self.assertIn(os.fsencode(str(path)), result.stderr)

    # -- usage failures (exit code 2) -------------------------------------

    def assertUsageError(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage", result.stderr)
        self.assertIn(b"key-id", result.stderr)

    def test_missing_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("key-id"))

    def test_empty_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("key-id", ""))

    def test_extra_argument_is_usage_error(self):
        path = self.write_file("x.pem", RSA_PUBLIC_PEM)
        self.assertUsageError(self.run_sealmark("key-id", str(path), "extra"))

    # -- pre-existing entry points kept compatible -------------------------

    def test_version_output(self):
        result = self.run_sealmark("--version")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"sealmark 0.1.0\n")

    def test_digest_still_uses_raw_bytes(self):
        # key-id and digest answer different questions: the PEM text layout
        # that leaves the fingerprint unchanged still changes the digest.
        plain = self.write_file("plain.pem", RSA_PUBLIC_PEM)
        crlf = self.write_file("crlf.pem", RSA_PUBLIC_PEM.replace("\n", "\r\n"))

        plain_result = self.run_sealmark("digest", str(plain))
        crlf_result = self.run_sealmark("digest", str(crlf))

        self.assertEqual(plain_result.returncode, 0, plain_result.stderr)
        self.assertEqual(crlf_result.returncode, 0, crlf_result.stderr)
        self.assertNotEqual(plain_result.stdout, crlf_result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
