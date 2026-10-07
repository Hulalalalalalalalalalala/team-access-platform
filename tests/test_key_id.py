#!/usr/bin/env python3
"""Regression tests for ``sealmark key-id``.

The key-id contract under test (see README):

* success: exit code 0, empty stderr, stdout is exactly one line
  ``spki-sha256:<64 lowercase hex digits>`` terminated by a single newline;
* the fingerprint is the SHA-256 of the SubjectPublicKeyInfo DER carried by
  the PEM block -- the public-key algorithm identifier and public key value
  are included; file name, path and the PEM text layout are not;
* at least RSA and Ed25519 SubjectPublicKeyInfo public keys are supported
  (EC P-256 is covered as well);
* the same key produces the same fingerprint under LF or CRLF line endings,
  any legal base64 line wrapping, no trailing newline, or trailing ASCII
  whitespace glued directly to the END marker with no line feed at all, and
  after the file is moved or renamed -- even when large amounts of
  surrounding ASCII whitespace carry the block through several 64 KiB read
  passes, with the begin marker, base64 data, end marker, the first bytes of
  the glued trailing whitespace and the two bytes of each CRLF straddling
  read boundaries;
* legal surrounding ASCII whitespace added to a scale far larger than the
  key itself -- before the block, after it, or on both sides -- leaves the
  fingerprint unchanged and does not grow the memory the process itself
  uses to handle the input. The parser streams fixed-size read passes and
  discards whitespace byte by byte, so the query's peak resident set size
  with tens of MiB of surrounding whitespace must stay within a fixed
  tolerance of the same key queried from an ordinary small file; the bound
  is about the whitespace only, not the (key-size-dependent) DER payload,
  and is checked for both RSA and Ed25519, with the fingerprint pinned to
  hashlib over the SubjectPublicKeyInfo DER rather than to a second
  sealmark run;
* the same memory bound holds on the failure paths that must keep checking
  to EOF: a complete block followed by a long run of legal whitespace with
  a single non-whitespace byte only at the very end, and a file that is
  whitespace and nothing else, both fail as invalid public key files
  (exit 1, empty stdout, the input path on stderr, no fingerprint) without
  the whitespace run being accumulated;
* the fingerprint is independently recomputed here with hashlib over the DER
  obtained from the cryptography package, and one Ed25519 case is pinned to a
  known answer;
* the file must contain exactly one PEM block wrapped in the literal
  ``PUBLIC KEY`` label, with only ASCII whitespace before or after it. Empty
  files, damaged/truncated encodings, non-canonical base64, more than one key,
  stray non-whitespace bytes (even several read passes beyond the block),
  truncation leaving a marker or the base64 body unfinished at a read
  boundary, private keys, certificates and other public-key wrappers (e.g.
  PKCS#1 ``RSA PUBLIC KEY``) all fail;
* the correct markers, legal base64 and a complete outer SEQUENCE are not
  enough -- the decoded payload must itself be canonical SubjectPublicKeyInfo
  DER covering every byte. A block whose *internal* encoding uses a
  non-minimal (BER) length, whose RSA modulus/exponent INTEGER carries a
  superfluous leading zero, or whose inner field declares a length different
  from its actual content is rejected even though those bytes still name a
  real public key: the command never normalizes the encoding and then
  fingerprints the result. The single sign-protecting leading zero that a
  positive INTEGER with its high bit set must carry is required by DER and
  stays valid -- it must not be swept up in the rejection;
* missing path / directory / unreadable input / invalid key content: exit
  code 1 with empty stdout and a stderr message containing the path -- the
  command never falls back to a file digest and never prints a partial
  fingerprint;
* missing/empty/extra arguments: exit code 2, empty stdout, usage text on
  stderr mentioning ``key-id``.

The read-failure cases reuse the LD_PRELOAD fault injector shared with the
other suites ($SEALMARK_READFAIL_PRELOAD): a regular file opens fine and
read() then fails with EIO after an exact number of delivered bytes. The
read-interruption cases reuse the second shared injector
($SEALMARK_EINTR_PRELOAD): reads of one chosen file return a chosen number of
consecutive EINTR results at a chosen byte position -- optionally combined
with clipped short reads and a later genuine EIO -- and the injector writes a
counters report so each test can prove the interrupts genuinely happened
rather than passing on an unstaged condition. The bounded-memory cases use a
fourth C helper ($SEALMARK_RUSAGE_WRAP, a plain executable, not an injector):
it forks, execs sealmark, reaps it with wait4() and reports the child's own
peak resident set size (ru_maxrss) -- the same clean per-child signal
/usr/bin/time -v reports, which a Python driver cannot read about its own
grandchild without its own footprint contaminating the result. The
injector-based tests skip when their injector is unavailable and the
bounded-memory tests skip when the reporter is unavailable. Key material and
all files are generated by the tests themselves inside a fresh temporary
directory.
"""

import base64
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

import nonregular_input as nri

# Must match the read buffer size in src/main.cpp.
CHUNK_SIZE = 64 * 1024

SEALMARK_BIN = os.environ.get("SEALMARK_BIN")
READFAIL_PRELOAD = os.environ.get("SEALMARK_READFAIL_PRELOAD")

requires_readfail_preload = unittest.skipUnless(
    READFAIL_PRELOAD and Path(READFAIL_PRELOAD).is_file(),
    "SEALMARK_READFAIL_PRELOAD is unavailable; mid-read failure cannot be "
    "injected on this platform",
)

# Path to the LD_PRELOAD EINTR/short-read injector built by CMake (Linux only).
EINTR_PRELOAD = os.environ.get("SEALMARK_EINTR_PRELOAD")

requires_eintr_preload = unittest.skipUnless(
    EINTR_PRELOAD and Path(EINTR_PRELOAD).is_file(),
    "SEALMARK_EINTR_PRELOAD is unavailable; read interruption cannot be "
    "injected on this platform",
)

# Path to the per-child rusage reporter built by CMake (Linux only). It is a
# plain executable, not an LD_PRELOAD: it runs sealmark as a forked child and
# reports wait4()'s ru_maxrss so the bounded-memory regressions measure the
# sealmark process itself, uncontaminated by this Python driver.
RUSAGE_WRAP = os.environ.get("SEALMARK_RUSAGE_WRAP")

requires_rusage_wrap = unittest.skipUnless(
    RUSAGE_WRAP and Path(RUSAGE_WRAP).is_file(),
    "SEALMARK_RUSAGE_WRAP is unavailable; the sealmark child's peak resident "
    "set size cannot be measured on this platform",
)

OUTPUT_RE = re.compile(rb"\Aspki-sha256:[0-9a-f]{64}\n\Z")

# SubjectPublicKeyInfo DER of the Ed25519 public key derived from the
# all-zero 32-byte private scalar, pinned so the wire value itself is
# regression-tested (not just self-consistency between runs).
ED25519_ZERO_SPKI_DER = bytes.fromhex(
    "302a300506032b65700321003b6a27bcceb6a42d62a3a8d02a6f0d7365321577"
    "1de243a63ac048a18b59da29"
)
ED25519_ZERO_FINGERPRINT = (
    "spki-sha256:339e2ff917630507b6a423b5ce084e285d1fa65d93b3e27a6195d3bbebc9ae23"
)

BEGIN = b"-----BEGIN PUBLIC KEY-----"
END = b"-----END PUBLIC KEY-----"


def spki_der(pub):
    return pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint_of_der(der):
    return "spki-sha256:" + hashlib.sha256(der).hexdigest()


def wrap_public_pem(der, width=64, newline=b"\n", final_newline=True,
                    begin=BEGIN, end=END):
    """Build a PUBLIC KEY PEM with explicit control over its text layout."""
    encoded = base64.b64encode(der)
    lines = [encoded[i:i + width] for i in range(0, len(encoded), width)]
    out = begin + newline + newline.join(lines) + newline + end
    if final_newline:
        out += newline
    return out


def pem_public_payload(pem_bytes):
    """Decode the base64 payload of a PUBLIC KEY PEM back to raw bytes."""
    lines = pem_bytes.splitlines()
    inner = b"".join(
        line for line in lines
        if not line.startswith(b"-----")
    )
    return base64.b64decode(inner, validate=True)


# --- DER / TLV surgery -------------------------------------------------------
#
# The inner-DER tests keep the PEM framing, base64 and outer SPKI structure
# intact while corrupting only the *internal* encoding. A minimal TLV parser
# locates fields without reinterpreting them, and the builders below emit DER
# length octets explicitly so a deliberately non-minimal length can be
# produced (the high-level serializers only ever emit canonical DER).

INTEGER_TAG = 0x02
BIT_STRING_TAG = 0x03
SEQUENCE_TAG = 0x30


def encode_length(length):
    """Minimal DER length octets for `length` (short or long form)."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_tlv(tag, content):
    return bytes([tag]) + encode_length(len(content)) + content


def nonminimal_length(length):
    """Non-minimal (BER-legal, DER-illegal) length octets for `length`:

    a value that fits in short form is forced into one long-form byte, and a
    long-form value gets one extra leading zero byte (count bumped by one).
    """
    if length < 0x80:
        return bytes([0x81, length])
    minimal = length.to_bytes((length.bit_length() + 7) // 8, "big")
    body = b"\x00" + minimal
    return bytes([0x80 | len(body)]) + body


def parse_tlv(buf, offset):
    """Parse one TLV at `offset`; return its boundaries and parsed length."""
    tag = buf[offset]
    first = buf[offset + 1]
    if first < 0x80:
        length = first
        content_start = offset + 2
    else:
        count = first & 0x7F
        length = int.from_bytes(
            buf[offset + 2:offset + 2 + count], "big"
        )
        content_start = offset + 2 + count
    return {
        "tag": tag,
        "start": offset,
        "content_start": content_start,
        "content_end": content_start + length,
        "end": content_start + length,
        "length": length,
    }


def split_spki(der):
    """Split a SubjectPublicKeyInfo DER into its two inner top-level fields.

    Returns (algid_tlv, bitstring_tlv), each the raw tag-length-value bytes.
    """
    outer = parse_tlv(der, 0)
    algid = parse_tlv(der, outer["content_start"])
    bitstring = parse_tlv(der, algid["end"])
    assert bitstring["end"] == outer["content_end"], "unexpected trailing bytes"
    return der[algid["start"]:algid["end"]], der[bitstring["start"]:
                                                 bitstring["end"]]


def split_rsa_public_key(der):
    """Split an RSA SPKI DER into (algid_tlv, n_int_tlv, e_int_tlv)."""
    algid, bitstring = split_spki(der)
    bs = parse_tlv(bitstring, 0)
    assert bs["tag"] == BIT_STRING_TAG
    # BIT STRING content starts with the unused-bits count byte (must be 0).
    assert bitstring[bs["content_start"]] == 0
    inner = bitstring[bs["content_start"] + 1:bs["content_end"]]
    rsk = parse_tlv(inner, 0)
    assert rsk["tag"] == SEQUENCE_TAG
    n_tlv = parse_tlv(inner, rsk["content_start"])
    e_tlv = parse_tlv(inner, n_tlv["end"])
    assert n_tlv["tag"] == INTEGER_TAG
    assert e_tlv["tag"] == INTEGER_TAG
    assert e_tlv["end"] == rsk["content_end"]
    return (
        algid,
        inner[n_tlv["start"]:n_tlv["end"]],
        inner[e_tlv["start"]:e_tlv["end"]],
    )


def tlv_content(tlv):
    """Content bytes of a canonical TLV."""
    info = parse_tlv(tlv, 0)
    return tlv[info["content_start"]:info["content_end"]]


def set_tlv_length_octets(tlv, length_octets):
    """Re-emit one TLV keeping tag and content but with new length octets.

    The input TLV is canonical, so its parsed span matches its real content;
    only the length header is swapped (to a non-minimal encoding or a wrong
    declared value). Nesting callers rewrap their parent, so an outer frame
    can stay byte-consistent even when an inner field lies about its length.
    """
    info = parse_tlv(tlv, 0)
    return (tlv[:1] + length_octets
            + tlv[info["content_start"]:info["content_end"]])


def set_integer_content(int_tlv, content):
    """Re-emit an INTEGER TLV with different (but same-valued) content."""
    return int_tlv[:1] + encode_length(len(content)) + content


def spki_from_fields(algid_tlv, bitstring_tlv):
    return encode_tlv(SEQUENCE_TAG, algid_tlv + bitstring_tlv)


def rsa_spki_from_parts(algid_tlv, n_int_tlv, e_int_tlv):
    """Rebuild an RSA SubjectPublicKeyInfo from its three inner TLVs."""
    rsa_public_key = encode_tlv(SEQUENCE_TAG, n_int_tlv + e_int_tlv)
    bitstring = encode_tlv(BIT_STRING_TAG, b"\x00" + rsa_public_key)
    return spki_from_fields(algid_tlv, bitstring)


# Every ASCII whitespace byte accepted around the PEM block (must match
# isAsciiSpace in src/main.cpp): space, tab, LF, vertical tab, form feed, CR.
AROUND_BLOCK_WHITESPACE = b" \t\n\x0b\x0c\r"


def ascii_whitespace(length):
    """Build a `length`-byte run using all six legal surrounding whitespace
    bytes, cycling deterministically (no randomness so a failing offset is
    reproducible)."""
    pattern = AROUND_BLOCK_WHITESPACE
    return pattern * (length // len(pattern)) + pattern[:length % len(pattern)]


class SealmarkKeyIdTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SEALMARK_BIN:
            raise RuntimeError(
                "SEALMARK_BIN is not set; point it at the sealmark executable"
            )
        if not Path(SEALMARK_BIN).is_file():
            raise RuntimeError(f"SEALMARK_BIN does not point to a file: {SEALMARK_BIN}")

        cls.rsa_priv = rsa.generate_private_key(public_exponent=65537,
                                                key_size=2048)
        cls.rsa_pub = cls.rsa_priv.public_key()
        cls.rsa_der = spki_der(cls.rsa_pub)
        cls.rsa_pem = cls.rsa_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # A second RSA key whose modulus uses the full key width, so its most
        # significant bit is set and the canonical INTEGER content must carry
        # the single leading 0x00 that keeps the value positive. Regenerate in
        # the (vanishingly unlikely) event a random modulus came up short.
        cls.rsa_hi_priv = rsa.generate_private_key(public_exponent=65537,
                                                   key_size=2048)
        while cls.rsa_hi_priv.private_numbers().public_numbers.n.bit_length() \
                != 2048:
            cls.rsa_hi_priv = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
        cls.rsa_hi_pub = cls.rsa_hi_priv.public_key()
        cls.rsa_hi_der = spki_der(cls.rsa_hi_pub)
        cls.rsa_hi_pem = cls.rsa_hi_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        cls.ed_priv = ed25519.Ed25519PrivateKey.generate()
        cls.ed_pub = cls.ed_priv.public_key()
        cls.ed_der = spki_der(cls.ed_pub)
        cls.ed_pem = cls.ed_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        cls.other_ed_priv = ed25519.Ed25519PrivateKey.generate()
        cls.other_ed_der = spki_der(cls.other_ed_priv.public_key())

        cls.ec_priv = ec.generate_private_key(ec.SECP256R1())
        cls.ec_der = spki_der(cls.ec_priv.public_key())

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sealmark-keyid-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.rusage_report_count = 0

    def run_sealmark(self, *args):
        return subprocess.run([SEALMARK_BIN, *args], capture_output=True)

    def run_key_id(self, path_arg):
        return self.run_sealmark("key-id", path_arg)

    def write_file(self, relative_path, content):
        path = self.tmp / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def assertFingerprintOk(self, result, der):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertRegex(result.stdout, OUTPUT_RE)
        self.assertEqual(len(result.stdout), len("spki-sha256:") + 64 + 1)
        self.assertEqual(
            result.stdout,
            (fingerprint_of_der(der) + "\n").encode("ascii"),
        )

    def assertRejected(self, result, path):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(path)), result.stderr)
        self.assertNotIn(b"spki-sha256", result.stderr)
        self.assertNotIn(b"Usage", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def assertInvalidPublicKey(self, result, path):
        """A structurally present PEM whose *content* is not a canonical SPKI.

        Like assertRejected but also pins the "public-key content invalid"
        wording, so an inner-encoding failure is never misreported as a file
        access/read problem -- and the path is still present.
        """
        self.assertRejected(result, path)
        self.assertIn(
            b"does not contain a single valid PEM-encoded "
            b"SubjectPublicKeyInfo public key",
            result.stderr,
        )

    # -- success ---------------------------------------------------------

    def test_rsa_fingerprint_is_sha256_of_spki_der(self):
        path = self.write_file("rsa.pub", self.rsa_pem)
        self.assertFingerprintOk(self.run_key_id(str(path)), self.rsa_der)

    def test_ed25519_fingerprint_is_sha256_of_spki_der(self):
        path = self.write_file("ed25519.pub", self.ed_pem)
        self.assertFingerprintOk(self.run_key_id(str(path)), self.ed_der)

    def test_ec_p256_fingerprint_is_sha256_of_spki_der(self):
        pem = self.ec_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path = self.write_file("ec.pub", pem)
        self.assertFingerprintOk(self.run_key_id(str(path)), self.ec_der)

    def test_ed25519_known_answer(self):
        zero_priv = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x00" * 32)
        zero_pub = zero_priv.public_key()
        self.assertEqual(spki_der(zero_pub), ED25519_ZERO_SPKI_DER)
        path = self.write_file(
            "zero-ed.pub",
            zero_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

        result = self.run_key_id(str(path))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            result.stdout, (ED25519_ZERO_FINGERPRINT + "\n").encode("ascii")
        )

    def test_lf_crlf_and_any_base64_wrapping_give_same_fingerprint(self):
        expected = fingerprint_of_der(self.rsa_der)
        variants = {
            "lf64.pub": wrap_public_pem(self.rsa_der, 64, b"\n"),
            "crlf64.pub": wrap_public_pem(self.rsa_der, 64, b"\r\n"),
            "lf1.pub": wrap_public_pem(self.rsa_der, 1, b"\n"),
            "crlf4.pub": wrap_public_pem(self.rsa_der, 4, b"\r\n"),
            "lf73.pub": wrap_public_pem(self.rsa_der, 73, b"\n"),
            "single_line.pub": wrap_public_pem(
                self.rsa_der, len(base64.b64encode(self.rsa_der)), b"\n"
            ),
            "no_final_newline.pub":
                wrap_public_pem(self.rsa_der, 64, b"\n", final_newline=False),
            "crlf_no_final_newline.pub":
                wrap_public_pem(self.rsa_der, 64, b"\r\n", final_newline=False),
        }
        seen = set()
        for name, content in variants.items():
            with self.subTest(name=name):
                path = self.write_file(Path("wrap", name), content)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(
                    result.stdout, (expected + "\n").encode("ascii")
                )
                seen.add(result.stdout)
        # All layouts of the same key collapse to one fingerprint.
        self.assertEqual(seen, {(expected + "\n").encode("ascii")})

    def test_ascii_whitespace_around_block_is_ignored(self):
        expected = fingerprint_of_der(self.ed_der)
        ws = b" \t\r\n\x0b\x0c"
        variants = [
            ws + self.ed_pem,
            self.ed_pem + ws,
            ws + self.ed_pem + ws,
            b"\n" + self.ed_pem,
            self.ed_pem.replace(b"\n", b"\r\n") + b"\n",
        ]
        for i, content in enumerate(variants):
            with self.subTest(variant=i):
                path = self.write_file(f"ws/{i}.pub", content)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(
                    result.stdout, (expected + "\n").encode("ascii")
                )

    def test_whitespace_glued_directly_to_end_marker_is_ignored(self):
        # A complete END marker needs no line feed at all: any ASCII
        # whitespace byte may follow its final '-' immediately -- a lone
        # space, a CR then a tab, vertical tab/form feed -- and EOF may
        # follow right away or after arbitrarily many such bytes. The
        # fingerprint is the same as with the conventional trailing LF.
        expected = fingerprint_of_der(self.ed_der)
        block = wrap_public_pem(self.ed_der, 64, b"\n", final_newline=False)
        self.assertFalse(block.endswith((b"\n", b"\r")))
        block_crlf = wrap_public_pem(
            self.ed_der, 64, b"\r\n", final_newline=False
        )
        tails = [
            b" ", b"\t", b"\r", b"\n", b"\x0b", b"\x0c",
            b"\r\t", b"\x0b\x0c ", AROUND_BLOCK_WHITESPACE,
            b" " + AROUND_BLOCK_WHITESPACE * 100,
            b"\r\n " + AROUND_BLOCK_WHITESPACE,
        ]
        variants = [block + tail for tail in tails]
        variants += [block_crlf + b" ", block_crlf + b"\r\t   "]
        for i, content in enumerate(variants):
            with self.subTest(variant=i):
                path = self.write_file(f"glued/{i}.pub", content)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(
                    result.stdout, (expected + "\n").encode("ascii")
                )

    def test_move_and_rename_do_not_change_fingerprint(self):
        names = [
            "key.pub",
            "nested/dir/public key.pub",
            "目录/公钥 副本.pub",
            "deep/deeper/key 0.tmp",
        ]
        outputs = set()
        for name in names:
            with self.subTest(name=name):
                path = self.write_file(Path(name), self.ed_pem)
                result = self.run_key_id(str(path))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)
        self.assertEqual(
            outputs.pop(),
            (fingerprint_of_der(self.ed_der) + "\n").encode("ascii"),
        )

    def test_different_keys_have_different_fingerprints(self):
        self.assertNotEqual(self.ed_der, self.other_ed_der)
        p1 = self.write_file("a.pub", self.ed_pem)
        p2 = self.write_file(
            "b.pub",
            self.other_ed_priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        r1 = self.run_key_id(str(p1))
        r2 = self.run_key_id(str(p2))
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertNotEqual(r1.stdout, r2.stdout)
        self.assertEqual(
            r1.stdout,
            (fingerprint_of_der(self.ed_der) + "\n").encode("ascii"),
        )
        self.assertEqual(
            r2.stdout,
            (fingerprint_of_der(self.other_ed_der) + "\n").encode("ascii"),
        )

    def test_input_file_is_not_modified(self):
        path = self.write_file("rsa.pub", self.rsa_pem)
        before = path.stat()
        content_before = path.read_bytes()
        result = self.run_key_id(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), content_before)
        self.assertEqual(path.stat().st_size, before.st_size)

    # -- multiple read passes / chunk-boundary regression ----------------
    #
    # The file is delivered to the parser in fixed CHUNK_SIZE-byte passes, so
    # every parser state must survive a boundary between passes. A PEM block
    # is short, so surrounding ASCII whitespace is used to push individual
    # block bytes across those boundaries; the padding itself never enters the
    # fingerprint. These tests pin that behavior for both RSA and Ed25519.

    def _assert_fingerprint_for_content(self, content, der, name):
        self.assertGreater(
            len(content), CHUNK_SIZE,
            "test setup must force more than one read pass",
        )
        path = self.write_file(name, content)
        self.assertFingerprintOk(self.run_key_id(str(path)), der)

    def test_large_whitespace_padding_forces_multiple_read_passes(self):
        for key_name, der, pem in (
            ("rsa", self.rsa_der, self.rsa_pem),
            ("ed25519", self.ed_der, self.ed_pem),
        ):
            variants = {
                "pad-both.pub":
                    ascii_whitespace(CHUNK_SIZE + 17) + pem
                    + ascii_whitespace(2 * CHUNK_SIZE + 101),
                "pad-before.pub":
                    ascii_whitespace(2 * CHUNK_SIZE - 1) + pem,
                "pad-after.pub":
                    pem + ascii_whitespace(3 * CHUNK_SIZE + 5),
                "pad-crlf.pub":
                    ascii_whitespace(CHUNK_SIZE - 1)
                    + pem.replace(b"\n", b"\r\n")
                    + ascii_whitespace(CHUNK_SIZE + 1),
            }
            for suffix, content in variants.items():
                with self.subTest(key=key_name, variant=suffix):
                    self._assert_fingerprint_for_content(
                        content, der, f"multi/{key_name}/{suffix}"
                    )

    def test_each_whitespace_kind_alone_pads_across_reads(self):
        # All six legal surrounding whitespace bytes, each on its own and in
        # a run long enough to span several passes, before and after the
        # block.
        for byte in b" \t\r\n\x0b\x0c":
            padding = bytes([byte]) * (CHUNK_SIZE + 13)
            content = padding + self.ed_pem + padding
            with self.subTest(byte=byte):
                self._assert_fingerprint_for_content(
                    content, self.ed_der, f"multi/ws-{byte:#04x}.pub"
                )

    def test_boundary_swept_across_begin_marker(self):
        # For every k the boundary between the first two reads falls right
        # after the k-th byte of the BEGIN marker (k == 0: immediately before
        # it; k == len(BEGIN): between the complete marker and its newline).
        for k in range(len(BEGIN) + 1):
            with self.subTest(k=k):
                content = (
                    ascii_whitespace(CHUNK_SIZE - k) + self.rsa_pem
                    + ascii_whitespace(CHUNK_SIZE)
                )
                self._assert_fingerprint_for_content(
                    content, self.rsa_der, f"multi/begin-sweep/{k}.pub"
                )

    def test_boundary_swept_across_whole_block_lf_and_crlf(self):
        # Exhaustive sweep: every byte position of both the LF and CRLF block
        # layouts becomes the first byte of a later read pass, with trailing
        # whitespace crossing yet another boundary. In particular this lands
        # the CR and the LF of every CRLF pair in different passes.
        for ending_name, newline in (("lf", b"\n"), ("crlf", b"\r\n")):
            block = wrap_public_pem(self.rsa_der, 64, newline)
            for offset in range(len(block) + 1):
                with self.subTest(ending=ending_name, offset=offset):
                    content = (
                        ascii_whitespace(CHUNK_SIZE - offset) + block
                        + ascii_whitespace(CHUNK_SIZE + 1)
                    )
                    self._assert_fingerprint_for_content(
                        content, self.rsa_der,
                        f"multi/sweep/{ending_name}/{offset}.pub",
                    )

    def test_each_crlf_pair_is_split_between_read_passes(self):
        # Targeted version of the CRLF guarantee: for every CR in the block,
        # that CR is the final byte of one pass and its LF the first byte of
        # the next (header line, each base64 line, and the END line).
        block = wrap_public_pem(self.ed_der, 16, b"\r\n")
        cr_positions = [i for i, c in enumerate(block) if c == ord("\r")]
        self.assertTrue(cr_positions)
        for cr_pos in cr_positions:
            with self.subTest(cr_pos=cr_pos):
                content = (
                    ascii_whitespace(CHUNK_SIZE - cr_pos - 1) + block
                    + ascii_whitespace(CHUNK_SIZE)
                )
                self._assert_fingerprint_for_content(
                    content, self.ed_der,
                    f"multi/crlf-split/{cr_pos}.pub",
                )

    def test_alternative_base64_wrapping_spans_read_passes(self):
        encoded_len = len(base64.b64encode(self.rsa_der))
        layouts = (
            (1, b"\n"), (4, b"\r\n"), (16, b"\n"), (64, b"\r\n"),
            (73, b"\n"), (encoded_len, b"\n"),
        )
        # Offsets chosen to put a quantum start, a quantum middle and a line
        # boundary on either side of a read boundary.
        offsets = (0, 1, 2, 3, 4, 5, 7, 15, 16, 31, 63, 64, 65, 100)
        for width, newline in layouts:
            block = wrap_public_pem(self.rsa_der, width, newline)
            for offset in offsets:
                if offset > len(block):
                    continue
                with self.subTest(width=width, newline=newline, offset=offset):
                    content = (
                        ascii_whitespace(CHUNK_SIZE - offset) + block
                        + ascii_whitespace(CHUNK_SIZE)
                    )
                    self._assert_fingerprint_for_content(
                        content, self.rsa_der,
                        f"multi/wrap/{width}-{offset}.pub",
                    )

    def test_complete_end_marker_at_eof_without_newline_is_valid(self):
        # Normal completion versus truncation: a fully matched END marker is
        # valid exactly at EOF with no trailing newline, including when its
        # last bytes are delivered by a second read pass. A legal trailing
        # newline or surrounding whitespace must give the same fingerprint.
        block = wrap_public_pem(self.rsa_der, 64, b"\n", final_newline=False)
        block_with_newline = wrap_public_pem(
            self.rsa_der, 64, b"\n", final_newline=True
        )
        length = len(block)
        variants = {
            # Final '-' of END is the first byte of the second pass and EOF
            # immediately follows -- a complete marker ending the file.
            "end-final-byte-in-second-pass.pub":
                ascii_whitespace(CHUNK_SIZE - length + 1) + block,
            # Same block, but the legal trailing newline is what the second
            # pass delivers; fingerprint must be identical.
            "newline-in-second-pass.pub":
                ascii_whitespace(CHUNK_SIZE - length) + block_with_newline,
            # END marker itself straddles the boundary (3 bytes in the first
            # pass, 21 in the second), EOF right after its last byte.
            "end-split-then-eof.pub":
                ascii_whitespace(CHUNK_SIZE - length + 21) + block,
            # END straddles the boundary, then its newline and a postamble
            # long enough to reach a third pass.
            "end-split-then-whitespace.pub":
                ascii_whitespace(CHUNK_SIZE - length + 21)
                + block_with_newline + ascii_whitespace(CHUNK_SIZE + 7),
        }
        for name, content in variants.items():
            with self.subTest(variant=name):
                self._assert_fingerprint_for_content(
                    content, self.rsa_der, f"multi/eof/{name}"
                )

    def test_glued_trailing_whitespace_survives_read_boundaries(self):
        # The END marker and the whitespace glued directly to it may be split
        # between read passes in every alignment: the boundary sweeps from
        # several bytes before the marker completes (marker straddles) through
        # several trailing bytes after it. The first byte past the complete
        # marker is deliberately a space, so the old "must start with a line
        # feed" rule rejected the splits that delivered that space in a later
        # pass. Trailing whitespace spanning further passes adds no state
        # beyond the fixed-size parser.
        block = wrap_public_pem(self.rsa_der, 64, b"\n", final_newline=False)
        tail = b" \t\r" + ascii_whitespace(CHUNK_SIZE + 7)
        for delta in range(-(len(END) + 1), 9):
            with self.subTest(delta=delta):
                # delta < 0: the first pass ends -delta bytes before the END
                # marker completes; delta >= 0: delta trailing bytes land in
                # the first pass.
                content = (
                    ascii_whitespace(CHUNK_SIZE - len(block) - delta)
                    + block + tail
                )
                self._assert_fingerprint_for_content(
                    content, self.rsa_der, f"multi/glued/{delta}.pub"
                )

    def test_non_whitespace_after_glued_whitespace_run_is_rejected(self):
        # Once the complete END marker is followed by whitespace, the parser
        # must keep classifying bytes to EOF: a stray byte or a second key is
        # rejected whether it follows the marker directly or a long whitespace
        # run, including when the marker/whitespace join straddles a boundary.
        block = wrap_public_pem(self.ed_der, 64, b"\n", final_newline=False)
        for stray in (b"x", b" extra\n", self.rsa_pem, BEGIN + b"\n"):
            for gap in (0, 1, 3, CHUNK_SIZE - 1, CHUNK_SIZE,
                        2 * CHUNK_SIZE + 71):
                with self.subTest(stray=stray[:8], gap=gap):
                    content = block + b" " + ascii_whitespace(gap) + stray
                    path = self.write_file(
                        f"multi/glued-stray/{gap}.pub", content
                    )
                    self.assertRejected(self.run_key_id(str(path)), path)

    def test_second_key_far_beyond_first_block_is_rejected(self):
        # The parser must keep checking all the way to EOF: the second key
        # only appears several read passes after the first block completed, so
        # accepting after the first END would print a fingerprint first.
        far = 3 * CHUNK_SIZE + 123
        variants = (
            self.rsa_pem + ascii_whitespace(far) + self.ed_pem,
            self.rsa_pem + ascii_whitespace(far) + self.ed_pem
            + ascii_whitespace(CHUNK_SIZE),
            self.rsa_pem + ascii_whitespace(2 * CHUNK_SIZE)
            + BEGIN + b"\n",
            ascii_whitespace(CHUNK_SIZE) + b"X"
            + ascii_whitespace(CHUNK_SIZE) + self.rsa_pem,
        )
        for i, content in enumerate(variants):
            with self.subTest(variant=i):
                path = self.write_file(f"multi/far/{i}.pub", content)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_stray_byte_far_after_block_is_rejected(self):
        for stray in (b"X", b".", b"\x00", b"\xff"):
            variants = (
                self.ed_pem + ascii_whitespace(2 * CHUNK_SIZE + 71) + stray,
                self.ed_pem + ascii_whitespace(2 * CHUNK_SIZE) + stray
                + ascii_whitespace(CHUNK_SIZE),
            )
            for i, content in enumerate(variants):
                with self.subTest(stray=stray, variant=i):
                    path = self.write_file(
                        f"multi/stray/{stray[0]:#04x}-{i}.pub", content
                    )
                    self.assertRejected(self.run_key_id(str(path)), path)

    def test_truncated_begin_marker_near_read_boundary_is_rejected(self):
        # "Near a boundary" in two distinct ways: the cut lands exactly as a
        # read pass ends (second_bytes == 0), or marker bytes are split across
        # passes and the file ends mid-marker inside the following pass. A
        # complete marker with its newline cut (including CRLF cut after CR)
        # is unfinished in the same sense.
        cases = []
        for cut in (1, 5, 10, 18, len(BEGIN) - 1, len(BEGIN)):
            for in_first_pass in (0, 1, cut // 2, cut):
                cases.append(
                    ascii_whitespace(CHUNK_SIZE - in_first_pass) + BEGIN[:cut]
                )
        # Whole marker in the first pass, CR at the first byte of the second
        # pass with its LF cut: a CRLF header split, then truncated.
        cases.append(
            ascii_whitespace(CHUNK_SIZE - len(BEGIN) - 1) + BEGIN + b"\r"
        )
        for i, content in enumerate(cases):
            with self.subTest(case=i, length=len(content)):
                path = self.write_file(f"multi/trunc-begin/{i}.pub", content)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_truncated_end_marker_near_read_boundary_is_rejected(self):
        prefix = self.rsa_pem[:self.rsa_pem.index(END)]
        cases = []
        for cut in (1, 5, 10, len(END) - 1):
            for in_first_pass in (0, 1, 3, cut):
                if in_first_pass > cut:
                    continue
                # in_first_pass END bytes arrive in the pass that already
                # carries the whole body prefix; the other cut - in_first_pass
                # bytes arrive in the next pass, then the file ends.
                cases.append(
                    ascii_whitespace(
                        CHUNK_SIZE - len(prefix) - in_first_pass
                    )
                    + prefix + END[:cut]
                )
        for i, content in enumerate(cases):
            with self.subTest(case=i, length=len(content)):
                path = self.write_file(f"multi/trunc-end/{i}.pub", content)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_truncated_base64_body_near_read_boundary_is_rejected(self):
        encoded = base64.b64encode(self.rsa_der)
        heads = []
        # Dangling final quantum (1-3 base64 chars), no END line: EOF while
        # body data is expected, split right at the boundary.
        for tail in (1, 2, 3):
            head = BEGIN + b"\n" + encoded[:64 + tail]
            heads.append(head)
        # Body ends on a quantum boundary but the END line never arrives.
        heads.append(BEGIN + b"\n" + encoded)
        # A body line ending in CR whose LF is cut by EOF.
        heads.append(BEGIN + b"\n" + encoded[:64] + b"\r")
        # Quantum-complete lines up to an unfinished last quantum followed by
        # an END line: the marker is found, but the base64 stream did not end
        # on a quantum boundary.
        heads.append(BEGIN + b"\n" + encoded[:-1] + b"\n" + END + b"\n")
        for i, head in enumerate(heads):
            with self.subTest(case=i):
                content = ascii_whitespace(CHUNK_SIZE - (len(head) - 1)) + head
                path = self.write_file(f"multi/trunc-body/{i}.pub", content)
                self.assertRejected(self.run_key_id(str(path)), path)

    # -- bounded memory despite large surrounding whitespace ------------
    #
    # The functional tests above prove that large amounts of surrounding
    # ASCII whitespace do not change the *output*; the tests here prove the
    # other half of the contract: the memory the process itself uses to
    # handle the input does not grow with that whitespace. A regression that
    # accumulated the whole file (or the preamble/postamble run, or the
    # bytes after a completed block) before deciding would still print the
    # correct fingerprint and pass every output-based test above, so the
    # fingerprint alone cannot guard this property.
    #
    # The sealmark child's *peak resident set size* is measured by the
    # rusage helper (wait4()'s ru_maxrss: the sealmark process only, not
    # this Python driver) and compared against the same query on an
    # ordinary small file holding the very same key. The decoded
    # SubjectPublicKeyInfo is allowed to depend on the key itself, which is
    # why every comparison uses that key's own un-padded run as the
    # baseline -- key size and surrounding-whitespace size are kept
    # separate. The tolerance is intentionally tight: on this program a
    # whole-file accumulation shows up as roughly 2 KiB of peak RSS per
    # KiB of padding, so even the smaller padding below overshoots the cap
    # by tens of MiB, while the streaming parser measures within ~0.2 MiB
    # of baseline regardless of padding.

    # Surrounding-whitespace run lengths for the memory checks: far larger
    # than the (sub-KiB-to-KiB) PEM blocks, spanning hundreds of read
    # passes. Two sizes are used so a growth trend cannot hide behind a
    # single measurement; both must stay within tolerance of baseline.
    MEMORY_PAD_SIZES = (8 * 1024 * 1024, 32 * 1024 * 1024)

    # Fixed allowance over the small-file baseline for allocator/reporting
    # jitter. It is a small constant, deliberately not a fraction of the
    # padding size: the baseline plus this allowance is the same no matter
    # how many MiB of whitespace surround the block.
    MEMORY_TOLERANCE_KB = 4096

    def _read_rusage_report(self, report):
        # Like the EINTR counters report, a missing report must fail the
        # test rather than let an unmeasured run pass silently.
        self.assertTrue(
            report.is_file(),
            f"rusage_wrap wrote no report to {report}; the measurement "
            "helper did not take effect",
        )
        fields = {}
        for line in report.read_text().splitlines():
            key, sep, value = line.partition("=")
            self.assertTrue(sep, f"malformed rusage report line: {line!r}")
            fields[key] = int(value)
        return fields

    def run_key_id_measured(self, path):
        """Run key-id on `path` under the rusage reporter.

        Returns (completed-process, fields); fields carries maxrss_kb and
        the child's exit_status. The wrapper exits with the child's own
        exit code, and the two must agree -- otherwise the reported RSS
        would describe a different run than the one whose output is
        asserted on.
        """
        self.rusage_report_count += 1
        report = self.tmp / "rusage" / f"{self.rusage_report_count}.report"
        report.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [RUSAGE_WRAP, str(report), SEALMARK_BIN, "key-id", str(path)],
            capture_output=True,
        )
        fields = self._read_rusage_report(report)
        self.assertIn("maxrss_kb", fields)
        self.assertGreater(fields["maxrss_kb"], 0)
        self.assertIn("exit_status", fields)
        self.assertEqual(fields["exit_status"], result.returncode)
        return result, fields

    def baseline_maxrss_kb(self, content, valid):
        """Peak RSS (KiB, max of several runs) for a small input of the
        same success/failure class as the padded case it is compared
        against."""
        path = self.write_file("rusage/baseline.pub", content)
        peak = 0
        for _ in range(3):
            result, fields = self.run_key_id_measured(path)
            if valid:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertRejected(result, path)
            peak = max(peak, fields["maxrss_kb"])
        return peak

    @requires_rusage_wrap
    def test_large_surrounding_whitespace_does_not_grow_memory(self):
        for key_name, der, pem in (
            ("rsa", self.rsa_der, self.rsa_pem),
            ("ed25519", self.ed_der, self.ed_pem),
        ):
            with self.subTest(key=key_name):
                # Baseline: the same key in an ordinary small file, no
                # surrounding whitespace beyond the PEM's own layout.
                baseline_kb = self.baseline_maxrss_kb(pem, valid=True)
                expected = (
                    fingerprint_of_der(der) + "\n"
                ).encode("ascii")
                # Independent anchor: the expected line is the SHA-256 of
                # the SPKI DER from the cryptography package, not another
                # sealmark output. The un-padded run must agree with it.
                plain = self.run_key_id(
                    self.write_file(f"rusage/{key_name}-plain.pub", pem)
                )
                self.assertEqual(plain.stdout, expected)

                placements = {
                    "before": lambda n: ascii_whitespace(n) + pem,
                    "after": lambda n: pem + ascii_whitespace(n),
                    "both":
                        lambda n: ascii_whitespace(n // 2) + pem
                        + ascii_whitespace(n - n // 2),
                }
                for pad_size in self.MEMORY_PAD_SIZES:
                    # The whitespace genuinely dwarfs the public key.
                    self.assertGreater(pad_size, len(pem) * 1000)
                    for placement, build in placements.items():
                        with self.subTest(
                            placement=placement, pad_size=pad_size
                        ):
                            content = build(pad_size)
                            path = self.write_file(
                                f"rusage/{key_name}/{placement}-"
                                f"{pad_size}.pub", content
                            )
                            result, fields = self.run_key_id_measured(path)

                            # The padding changes nothing about identity:
                            # exactly one line, exit 0, empty stderr, same
                            # independently computed fingerprint as the
                            # un-padded key.
                            self.assertEqual(
                                result.returncode, 0, result.stderr
                            )
                            self.assertEqual(result.stderr, b"")
                            self.assertRegex(result.stdout, OUTPUT_RE)
                            self.assertEqual(result.stdout, expected)
                            self.assertEqual(result.stdout, plain.stdout)

                            # The guard itself: peak RSS stays within a
                            # fixed constant of the small-file baseline,
                            # at every padding size and placement.
                            self.assertLessEqual(
                                fields["maxrss_kb"],
                                baseline_kb + self.MEMORY_TOLERANCE_KB,
                                f"peak RSS {fields['maxrss_kb']} KiB for "
                                f"{pad_size} bytes of surrounding "
                                f"whitespace exceeds baseline "
                                f"{baseline_kb} KiB + "
                                f"{self.MEMORY_TOLERANCE_KB} KiB; input "
                                "handling appears to accumulate the "
                                "whitespace/file instead of streaming it",
                            )
                            # The query only reads the file.
                            self.assertEqual(path.read_bytes(), content)

    @requires_rusage_wrap
    def test_long_whitespace_runs_on_failure_paths_do_not_grow_memory(self):
        # Two failure paths must keep checking to EOF without accumulating
        # the run: a complete block followed by legal whitespace and then a
        # single non-whitespace byte only at the very end, and a file made
        # of whitespace and nothing else. Both are the same failure class
        # as their small counterparts: exit 1, empty stdout, the input path
        # on stderr, no fingerprint printed early.
        wsonly_small = ascii_whitespace(256)
        wsonly_baseline = self.baseline_maxrss_kb(
            wsonly_small, valid=False
        )

        for key_name, pem in (
            ("rsa", self.rsa_pem), ("ed25519", self.ed_pem),
        ):
            # Baseline of the same failure class and the same key, so the
            # allowance covers jitter only, never the (key-dependent) work
            # of handling the block itself.
            stray_baseline = self.baseline_maxrss_kb(
                pem + ascii_whitespace(64) + b"X", valid=False
            )
            for pad_size in self.MEMORY_PAD_SIZES:
                with self.subTest(case="stray-at-eof", key=key_name,
                                  pad_size=pad_size):
                    # The non-whitespace byte is the file's final byte, so
                    # exit code 1 proves the parser walked the whole
                    # whitespace run instead of accepting after the block.
                    content = pem + ascii_whitespace(pad_size) + b"X"
                    path = self.write_file(
                        f"rusage/stray/{key_name}-{pad_size}.pub", content
                    )
                    result, fields = self.run_key_id_measured(path)
                    self.assertRejected(result, path)
                    self.assertLessEqual(
                        fields["maxrss_kb"],
                        stray_baseline + self.MEMORY_TOLERANCE_KB,
                        f"peak RSS {fields['maxrss_kb']} KiB grew with a "
                        f"{pad_size}-byte postamble; post-block bytes are "
                        "being accumulated instead of streamed to EOF",
                    )
                    self.assertEqual(path.read_bytes(), content)

        for pad_size in self.MEMORY_PAD_SIZES:
            with self.subTest(case="whitespace-only", pad_size=pad_size):
                content = ascii_whitespace(pad_size)
                path = self.write_file(
                    f"rusage/wsonly/{pad_size}.pub", content
                )
                result, fields = self.run_key_id_measured(path)
                self.assertRejected(result, path)
                self.assertLessEqual(
                    fields["maxrss_kb"],
                    wsonly_baseline + self.MEMORY_TOLERANCE_KB,
                    f"peak RSS {fields['maxrss_kb']} KiB grew for a "
                    f"{pad_size}-byte whitespace-only file; the "
                    "whitespace run is being accumulated",
                )
                self.assertEqual(path.read_bytes(), content)

    # -- invalid content (exit code 1) -----------------------------------

    def test_empty_file_is_rejected(self):
        path = self.write_file("empty.pub", b"")
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_whitespace_only_file_is_rejected(self):
        path = self.write_file("ws.pub", b" \t\r\n\x0b\x0c   \n")
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_truncated_files_are_rejected(self):
        # Cuts at every interesting length: first bytes, mid header, payload
        # at various depths, missing END line.
        cut_points = [
            1,
            5,
            len(BEGIN),
            len(BEGIN) + 1,
            len(self.rsa_pem) // 3,
            len(self.rsa_pem) // 2,
            self.rsa_pem.index(END) - 1,
        ]
        for cut in cut_points:
            with self.subTest(cut=cut):
                path = self.write_file(f"trunc/{cut}.pub", self.rsa_pem[:cut])
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_non_base64_character_in_payload_is_rejected(self):
        damaged = bytearray(self.rsa_pem)
        idx = self.rsa_pem.index(b"M")
        damaged[idx] = ord("!")
        path = self.write_file("badchar.pub", bytes(damaged))
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_base64_length_not_multiple_of_four_is_rejected(self):
        # Delete one payload character while keeping both boundary lines.
        body = self.rsa_pem.splitlines()
        payload = b"".join(body[1:-1])
        broken_payload = payload[:len(payload) // 2] + payload[len(payload) // 2 + 1:]
        content = BEGIN + b"\n" + broken_payload + b"\n" + END + b"\n"
        self.assertEqual(len(payload) % 4, 0)
        self.assertNotEqual(len(broken_payload) % 4, 0)
        path = self.write_file("badlen.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_noncanonical_padding_bits_are_rejected(self):
        encoded = base64.b64encode(self.ed_der)
        self.assertTrue(encoded.endswith(b"="))
        # Flip a low bit of the data character immediately before padding;
        # structurally well-formed base64 whose unused padding bits are set.
        broken = encoded[:-2] + bytes([encoded[-2] ^ 1]) + encoded[-1:]
        content = BEGIN + b"\n" + broken + b"\n" + END + b"\n"
        path = self.write_file("padbits.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_padding_before_final_quantum_is_rejected(self):
        encoded = bytearray(base64.b64encode(self.rsa_der))
        # Put '=' at position 2 of a quantum well inside the stream.
        self.assertEqual(10 % 4, 2)
        encoded[10] = ord("=")
        content = BEGIN + b"\n" + bytes(encoded) + b"\n" + END + b"\n"
        path = self.write_file("midpad.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_two_public_keys_are_rejected(self):
        path = self.write_file("two.pub", self.rsa_pem + self.ed_pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_second_block_after_end_is_rejected(self):
        trailing = self.rsa_pem + b"-----BEGIN PUBLIC KEY-----\n"
        path = self.write_file("second.pub", trailing)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_trailing_non_whitespace_is_rejected(self):
        for extra in (b"extra\n", b"x", b"\n-----\n", b"sha256:abcd\n"):
            with self.subTest(extra=extra):
                path = self.write_file("x.pub", self.rsa_pem + extra)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_leading_non_whitespace_is_rejected(self):
        for prefix in (b"junk\n", b"x" + self.rsa_pem, b"0" + self.rsa_pem):
            with self.subTest(prefix=prefix[:8]):
                path = self.write_file("x.pub", prefix)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_utf8_bom_is_rejected(self):
        path = self.write_file("bom.pub", b"\xef\xbb\xbf" + self.rsa_pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_non_ascii_byte_after_block_is_rejected(self):
        path = self.write_file("hi.pub", self.rsa_pem + b"\xff\n")
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_non_whitespace_glued_to_end_marker_is_rejected(self):
        # Whitespace relaxation starts only AFTER the complete marker: text
        # glued to its final '-' with no whitespace between is still invalid,
        # as is a truncated or internally misspelled marker followed by the
        # whitespace a complete marker would have accepted.
        block = wrap_public_pem(self.ed_der, 64, b"\n", final_newline=False)
        contents = [
            block + b"x",
            block + b" extra\n",
            block + b"-----",
            block + b" ",  # placeholder, replaced below with truncated marker
        ]
        contents[3] = block[: -len(END)] + END[:-1] + b" "
        contents.append(block[: -len(END)] + END[:-3] + b"   ")
        contents.append(
            block.replace(END, b"-----END  PUBLIC KEY-----", 1) + b" "
        )
        for i, content in enumerate(contents):
            with self.subTest(case=i):
                path = self.write_file(f"glued-bad/{i}.pub", content)
                self.assertRejected(self.run_key_id(str(path)), path)

    def test_text_on_end_line_is_rejected(self):
        content = self.rsa_pem.replace(END + b"\n", END + b" extra\n")
        path = self.write_file("endline.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_space_inside_payload_line_is_rejected(self):
        encoded = base64.b64encode(self.rsa_der)
        broken = encoded[:10] + b" " + encoded[10:]
        content = BEGIN + b"\n" + broken + b"\n" + END + b"\n"
        path = self.write_file("wspayload.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_blank_line_inside_block_is_rejected(self):
        encoded = base64.b64encode(self.rsa_der)
        head, tail = encoded[:64], encoded[64:]
        content = BEGIN + b"\n" + head + b"\n\n" + tail + b"\n" + END + b"\n"
        path = self.write_file("blank.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_begin_end_label_mismatch_is_rejected(self):
        content = self.rsa_pem.replace(
            END, b"-----END RSA PUBLIC KEY-----", 1
        )
        path = self.write_file("mismatch.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_other_begin_label_is_rejected(self):
        # Correct END marker but a different BEGIN label.
        content = self.rsa_pem.replace(
            BEGIN, b"-----BEGIN RSA PUBLIC KEY-----", 1
        )
        path = self.write_file("otherlabel.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_cr_only_line_endings_are_rejected(self):
        # Neither LF nor CRLF: bare CRs are not legal line separators here.
        content = self.rsa_pem.replace(b"\n", b"\r")
        path = self.write_file("cronly.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_pkcs8_private_key_is_rejected(self):
        pem = self.rsa_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.assertIn(b"PRIVATE KEY", pem)
        path = self.write_file("priv.pem", pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_pkcs1_rsa_private_key_is_rejected(self):
        pem = self.rsa_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        self.assertIn(b"RSA PRIVATE KEY", pem)
        path = self.write_file("rsa-priv.pem", pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_pkcs1_rsa_public_key_wrapper_is_rejected(self):
        # A valid RSA public key, but in the PKCS#1 wrapper rather than the
        # required SubjectPublicKeyInfo: fingerprinting it is forbidden.
        pem = self.rsa_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1,
        )
        self.assertIn(b"RSA PUBLIC KEY", pem)
        path = self.write_file("rsapkcs1.pub", pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_ec_private_key_is_rejected(self):
        pem = self.ec_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        self.assertIn(b"EC PRIVATE KEY", pem)
        path = self.write_file("ec-priv.pem", pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_certificate_is_rejected(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.rsa_pub)
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(self.rsa_priv, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        self.assertIn(b"CERTIFICATE", pem)
        path = self.write_file("cert.pem", pem)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_valid_key_with_garbage_appended_inside_encoding_rejected(self):
        # A second, incomplete PUBLIC KEY block glued before the END line.
        encoded = base64.b64encode(self.rsa_der)
        head, tail = encoded[:64], encoded[64:]
        content = (BEGIN + b"\n" + head + b"\n" + BEGIN + b"\n" + tail +
                   b"\n" + END + b"\n")
        path = self.write_file("nested.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_random_binary_is_rejected(self):
        path = self.write_file("rand.bin", bytes(range(256)) * 4)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_noncanonical_ber_length_is_rejected(self):
        # Ed25519 SPKI DER is short enough for a one-byte (short-form) outer
        # length; rewrite it as the non-minimal BER long form. The bytes still
        # parse as BER in many libraries but are not valid DER.
        self.assertEqual(self.ed_der[0], 0x30)
        self.assertLess(self.ed_der[1], 0x80)
        ber = bytes([0x30, 0x81, self.ed_der[1]]) + self.ed_der[2:]
        content = wrap_public_pem(ber)
        path = self.write_file("ber.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    def test_trailing_bytes_after_der_are_rejected(self):
        # Valid SPKI followed by one extra byte inside the same PEM payload.
        broken_der = self.ed_der + b"\x00"
        content = wrap_public_pem(broken_der)
        path = self.write_file("trailing-der.pub", content)
        self.assertRejected(self.run_key_id(str(path)), path)

    # -- non-canonical INNER DER (exit code 1) ---------------------------
    #
    # The files in this section all pass the outer checks: the literal PUBLIC
    # KEY markers are correct, the payload is legal canonical base64, and the
    # decoded bytes start with a complete outer SubjectPublicKeyInfo SEQUENCE
    # whose declared length covers exactly the bytes present. What is wrong is
    # the *internal* DER: a non-minimal (BER) length, a superfluous leading
    # zero on an RSA INTEGER, or an inner field whose declared length does not
    # match its content. Such bytes can still name a real public key (the
    # crypto library can parse them), but key-id must refuse to normalize and
    # fingerprint them. run_inner_invalid() asserts those outer preconditions
    # before asserting the rejection, so a case here can never silently be
    # failing for the wrong (e.g. truncated-base64) reason.

    def run_inner_invalid(self, relative_path, der):
        outer = parse_tlv(der, 0)
        self.assertEqual(der[0], SEQUENCE_TAG, "payload must be a SEQUENCE")
        self.assertEqual(
            outer["content_end"], len(der),
            "outer SPKI frame must be complete and cover exactly the bytes",
        )
        pem_bytes = wrap_public_pem(der)
        self.assertEqual(
            pem_public_payload(pem_bytes), der,
            "the inner bytes must be carried verbatim by legal base64",
        )
        path = self.write_file(relative_path, pem_bytes)
        result = self.run_key_id(str(path))
        self.assertInvalidPublicKey(result, path)
        return path, result

    def test_rsa_modulus_required_sign_protecting_zero_is_accepted(self):
        # Distinct from a superfluous zero: a 2048-bit modulus has its top bit
        # set, so DER REQUIRES one leading 0x00 to keep the INTEGER positive.
        # That canonical key must succeed -- the rejection of abnormal
        # encodings must not sweep up this mandatory padding.
        _algid, n_int, _e_int = split_rsa_public_key(self.rsa_hi_der)
        n_content = tlv_content(n_int)
        self.assertEqual(n_content[0], 0x00)
        self.assertTrue(n_content[1] & 0x80, "the single 0x00 must be needed")
        self.assertEqual(len(n_content), 257)
        path = self.write_file("rsa-hi.pub", self.rsa_hi_pem)
        self.assertFingerprintOk(self.run_key_id(str(path)), self.rsa_hi_der)

    def test_same_canonical_der_text_layout_never_changes_fingerprint(self):
        # Text-only changes to ONE identical DER (base64 wrapping, LF vs CRLF,
        # trailing newline) must collapse to one fingerprint for both
        # algorithms; they must never be confused with a change to the inner
        # binary encoding.
        encoded_len = {
            name: len(base64.b64encode(der))
            for name, der in
            (("rsa", self.rsa_hi_der), ("ed25519", self.ed_der))
        }
        for name, der in (("rsa", self.rsa_hi_der), ("ed25519", self.ed_der)):
            expected = (fingerprint_of_der(der) + "\n").encode("ascii")
            layouts = {
                "lf64": wrap_public_pem(der, 64, b"\n"),
                "crlf64": wrap_public_pem(der, 64, b"\r\n"),
                "lf16": wrap_public_pem(der, 16, b"\n"),
                "crlf1": wrap_public_pem(der, 1, b"\r\n"),
                "single-line": wrap_public_pem(
                    der, encoded_len[name], b"\n"
                ),
                "lf-no-final-newline":
                    wrap_public_pem(der, 64, b"\n", final_newline=False),
                "crlf-no-final-newline":
                    wrap_public_pem(der, 64, b"\r\n", final_newline=False),
            }
            for layout, content in layouts.items():
                with self.subTest(key=name, layout=layout):
                    path = self.write_file(f"layout/{name}/{layout}.pub",
                                           content)
                    result = self.run_key_id(str(path))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(result.stdout, expected)

    def test_nonminimal_inner_lengths_are_rejected(self):
        r_algid, r_n, r_e = split_rsa_public_key(self.rsa_der)
        _, r_bs = split_spki(self.rsa_der)
        r_rsa_public_key = encode_tlv(SEQUENCE_TAG, r_n + r_e)

        cases = {
            # RSA, at every length-bearing inner node (outer stays minimal).
            "rsa-algorithm-identifier": spki_from_fields(
                set_tlv_length_octets(
                    r_algid, nonminimal_length(len(tlv_content(r_algid)))
                ),
                r_bs,
            ),
            "rsa-bit-string": spki_from_fields(
                r_algid,
                set_tlv_length_octets(
                    r_bs, nonminimal_length(len(tlv_content(r_bs)))
                ),
            ),
            "rsa-rsapublickey-sequence": spki_from_fields(
                r_algid,
                encode_tlv(
                    BIT_STRING_TAG,
                    b"\x00" + set_tlv_length_octets(
                        r_rsa_public_key,
                        nonminimal_length(
                            len(tlv_content(r_rsa_public_key))
                        ),
                    ),
                ),
            ),
            "rsa-modulus-integer": rsa_spki_from_parts(
                r_algid,
                set_tlv_length_octets(
                    r_n, nonminimal_length(len(tlv_content(r_n)))
                ),
                r_e,
            ),
            "rsa-exponent-integer": rsa_spki_from_parts(
                r_algid,
                r_n,
                set_tlv_length_octets(
                    r_e, nonminimal_length(len(tlv_content(r_e)))
                ),
            ),
        }

        e_algid, e_bs = split_spki(self.ed_der)
        cases.update({
            "ed25519-algorithm-identifier": spki_from_fields(
                set_tlv_length_octets(
                    e_algid, nonminimal_length(len(tlv_content(e_algid)))
                ),
                e_bs,
            ),
            "ed25519-bit-string": spki_from_fields(
                e_algid,
                set_tlv_length_octets(
                    e_bs, nonminimal_length(len(tlv_content(e_bs)))
                ),
            ),
        })

        for label, der in cases.items():
            with self.subTest(case=label):
                self.run_inner_invalid(f"nonmin-len/{label}.pub", der)

    def test_superfluous_leading_zeros_on_rsa_integers_are_rejected(self):
        # Built from the high-bit-modulus key: its modulus already carries the
        # one REQUIRED 0x00, so an additional zero is unambiguously
        # superfluous. The exponent (0x010001) has its high bit clear and no
        # padding at all. Either extra zero names the same integer/key but is
        # non-canonical DER and must be rejected, never re-encoded first.
        algid, n_int, e_int = split_rsa_public_key(self.rsa_hi_der)
        n_content = tlv_content(n_int)
        e_content = tlv_content(e_int)
        # The modulus already carries exactly the one zero that DER requires
        # (top bit set), so any further zero is strictly superfluous; the
        # exponent's top bit is clear and it carries no such zero at all.
        self.assertEqual(n_content[0], 0x00)
        self.assertTrue(n_content[1] & 0x80)
        self.assertEqual(e_content, (65537).to_bytes(3, "big"))
        self.assertFalse(e_content[0] & 0x80)

        cases = {
            "modulus-one-extra-zero": rsa_spki_from_parts(
                algid, set_integer_content(n_int, b"\x00" + n_content), e_int
            ),
            "modulus-two-extra-zeros": rsa_spki_from_parts(
                algid,
                set_integer_content(n_int, b"\x00\x00" + n_content),
                e_int,
            ),
            "exponent-extra-zero": rsa_spki_from_parts(
                algid, n_int, set_integer_content(e_int, b"\x00" + e_content)
            ),
        }
        for label, der in cases.items():
            with self.subTest(case=label):
                self.run_inner_invalid(f"leading-zero/{label}.pub", der)

    def test_inner_declared_length_mismatch_complete_outer_is_rejected(self):
        # The outer SPKI SEQUENCE length (and the BIT STRING's, in the nested
        # RSA case) is recomputed to match the bytes present exactly, so the
        # outer encapsulation is whole; only an inner field lies about its own
        # length. A complete-looking outer frame must not be accepted.
        r_algid, r_n, r_e = split_rsa_public_key(self.rsa_der)
        _, r_bs = split_spki(self.rsa_der)
        r_rsa_public_key = encode_tlv(SEQUENCE_TAG, r_n + r_e)

        cases = {}
        for delta in (1, -1, 128):
            cases[f"rsa-algorithm-identifier{delta:+d}"] = spki_from_fields(
                set_tlv_length_octets(
                    r_algid,
                    encode_length(len(tlv_content(r_algid)) + delta),
                ),
                r_bs,
            )

        e_algid, e_bs = split_spki(self.ed_der)
        for delta in (1, -1, 32):
            cases[f"ed25519-bit-string{delta:+d}"] = spki_from_fields(
                e_algid,
                set_tlv_length_octets(
                    e_bs, encode_length(len(tlv_content(e_bs)) + delta)
                ),
            )

        for delta in (1, -1, 5):
            lying_rsk = set_tlv_length_octets(
                r_rsa_public_key,
                encode_length(len(tlv_content(r_rsa_public_key)) + delta),
            )
            cases[f"rsa-rsapublickey-sequence{delta:+d}"] = spki_from_fields(
                r_algid, encode_tlv(BIT_STRING_TAG, b"\x00" + lying_rsk)
            )

        for label, der in cases.items():
            with self.subTest(case=label):
                self.run_inner_invalid(f"len-mismatch/{label}.pub", der)

    def test_invalid_inner_der_is_not_fingerprinted_and_file_not_modified(self):
        # End-to-end guard for one case: no partial fingerprint, no fallback to
        # a file digest, and the query only reads the file.
        algid, n_int, e_int = split_rsa_public_key(self.rsa_hi_der)
        bad = rsa_spki_from_parts(
            algid,
            set_integer_content(n_int, b"\x00" + tlv_content(n_int)),
            e_int,
        )
        original = wrap_public_pem(bad)
        path, result = self.run_inner_invalid("readonly/extra-zero.pub", bad)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"sha256:", result.stderr)
        self.assertEqual(path.read_bytes(), original)

    # -- file failures (exit code 1) -------------------------------------

    def test_nonexistent_path_fails_with_exit_code_1(self):
        missing = self.tmp / "目录" / "missing key.pub"
        self.assertFalse(missing.exists())
        result = self.run_key_id(str(missing))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(missing)), result.stderr)

    def test_directory_fails_with_exit_code_1(self):
        directory = self.tmp / "a directory"
        directory.mkdir()
        result = self.run_key_id(str(directory))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(directory)), result.stderr)

    # -- non-regular inputs are judged on the opened object --------------
    #
    # A FIFO (with or without a writer) carrying even a perfectly valid
    # PUBLIC KEY block is rejected with exit code 1 without blocking and can
    # never yield a fingerprint or an "invalid key" verdict; only the object
    # actually opened decides regularity, and symlinks resolving to a regular
    # key file keep working. Shared with the other two suites.

    @nri.requires_nonregular_input
    def test_fifo_and_symlink_inputs_follow_the_single_regular_file_rule(self):
        path = self.write_file("keys 目录/real 公钥.pem", self.rsa_pem)
        nri.run_all(
            self,
            args=lambda p: ["key-id", str(p)],
            regular_path=path,
            expected_stdout=(
                fingerprint_of_der(self.rsa_der) + "\n"
            ).encode("ascii"),
            valid_payload=self.rsa_pem,
            tmp=self.tmp,
        )

    @nri.requires_toctou_preload
    def test_file_swapped_to_fifo_after_check_is_judged_on_opened_object(self):
        # The bytes in the FIFO form a perfectly valid PUBLIC KEY, yet a
        # swapped input is refused with exit 1: no fingerprint, no "invalid
        # key" verdict, and no blocking on the pipe.
        nri.run_toctou_all(
            self,
            args=lambda p: ["key-id", str(p)],
            valid_payload=self.rsa_pem,
            tmp=self.tmp,
        )

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses file permission bits",
    )
    def test_unreadable_file_fails_with_exit_code_1(self):
        path = self.write_file("secret.pub", self.rsa_pem)
        path.chmod(0o000)
        self.addCleanup(lambda: path.chmod(0o644))
        result = self.run_key_id(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(os.fsencode(str(path)), result.stderr)

    # -- read failure after a successful open (exit code 1) -------------

    def _preload_env(self, preload, **extra):
        env = dict(os.environ)
        if env.get("LD_PRELOAD"):
            preload = preload + ":" + env["LD_PRELOAD"]
        env["LD_PRELOAD"] = preload
        env.update(extra)
        return env

    def run_key_id_with_eintr(self, path, report, **knobs):
        """Run key-id with the preloaded EINTR injector armed on `path`.
        Knobs map to the injector's environment: `at` (byte position of the
        first interrupt), `times` (consecutive EINTR results), `short`
        (per-read byte cap) and `eio_after` (byte position of a genuine EIO).
        `report` is the path the injector writes its counters to, so the
        test can prove the staged conditions actually occurred."""
        extra = {"SEALMARK_EINTR_PATH": str(path),
                 "SEALMARK_EINTR_REPORT": str(report)}
        for knob, value in knobs.items():
            extra[f"SEALMARK_EINTR_{knob.upper()}"] = str(value)
        return subprocess.run(
            [SEALMARK_BIN, "key-id", str(path)],
            capture_output=True,
            env=self._preload_env(EINTR_PRELOAD, **extra),
        )

    def read_eintr_report(self, report_path):
        """Parse the injector's counters file. A missing report means the
        preload never took effect, which must fail the test rather than let
        it pass on an unstaged condition."""
        self.assertTrue(
            report_path.is_file(),
            f"EINTR injector wrote no report to {report_path}; "
            "the preload did not take effect",
        )
        fields = {}
        for line in report_path.read_text().splitlines():
            key, sep, value = line.partition("=")
            self.assertTrue(sep, f"malformed report line: {line!r}")
            fields[key] = int(value)
        return fields

    @requires_readfail_preload
    def test_read_error_after_partial_content_fails_with_exit_code_1(self):
        path = self.write_file(
            "readfail/key.pub", wrap_public_pem(self.rsa_der, 64, b"\n")
        )

        # Control: unarmed preload still succeeds.
        healthy = subprocess.run(
            [SEALMARK_BIN, "key-id", str(path)],
            capture_output=True,
            env=self._preload_env(READFAIL_PRELOAD,
                                  SEALMARK_READFAIL_PATH=str(path)),
        )
        self.assertEqual(healthy.returncode, 0, healthy.stderr)

        size = path.stat().st_size
        for after in (1, 100, size // 2, size - 1):
            with self.subTest(after=after):
                result = subprocess.run(
                    [SEALMARK_BIN, "key-id", str(path)],
                    capture_output=True,
                    env=self._preload_env(
                        READFAIL_PRELOAD,
                        SEALMARK_READFAIL_PATH=str(path),
                        SEALMARK_READFAIL_AFTER=str(after),
                    ),
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"read", result.stderr.lower())
                self.assertIn(os.fsencode(str(path)), result.stderr)
                self.assertNotIn(b"spki-sha256", result.stderr)

    # -- read interruption (EINTR) is retried, never fatal or final ------
    #
    # read() may return -1/EINTR without delivering any data, and may return
    # fewer bytes than requested while content remains; both are transient
    # conditions, not EOF and not errors. The key-id result must still be the
    # fingerprint of the complete file's public key -- whether the interrupt
    # arrives before the first byte, after partial content, or several times
    # in a row after a run of short reads -- and must be byte-identical to an
    # uninterrupted run of the same file. The EINTR injector stages this
    # deterministically and writes a counters report; every test here asserts
    # on those counters so a run in which the staged interrupts or short
    # reads never actually happened cannot pass silently.

    @requires_eintr_preload
    def test_eintr_before_first_byte_still_yields_fingerprint(self):
        for key_name, der, pem in (
            ("rsa", self.rsa_der, self.rsa_pem),
            ("ed25519", self.ed_der, self.ed_pem),
        ):
            for times in (1, 3):
                with self.subTest(key=key_name, times=times):
                    path = self.write_file(
                        f"eintr/first-{key_name}-{times}.pub", pem
                    )

                    # Control: the same file without any injection.
                    normal = self.run_key_id(str(path))
                    self.assertEqual(normal.returncode, 0, normal.stderr)

                    report = self.tmp / f"eintr/first-{key_name}-{times}.report"
                    result = self.run_key_id_with_eintr(
                        path, report, at=0, times=times
                    )

                    self.assertFingerprintOk(result, der)
                    self.assertEqual(result.stdout, normal.stdout)

                    fields = self.read_eintr_report(report)
                    # The interrupts genuinely happened, before any byte was
                    # delivered; no short reads and no I/O error occurred.
                    self.assertEqual(fields["eintr"], times)
                    self.assertEqual(fields["eintr_pos"], 0)
                    self.assertEqual(fields["eio"], 0)
                    self.assertEqual(fields["short"], 0)
                    # Every byte of the file was delivered exactly once.
                    self.assertEqual(fields["delivered"], len(pem))
                    # The query only reads the file; it must not rewrite it.
                    self.assertEqual(path.read_bytes(), pem)

    @requires_eintr_preload
    def test_short_reads_then_consecutive_eintrs_still_yield_fingerprint(self):
        # Every read returns at most 7 bytes although more content remains,
        # and once half the file has been delivered three interrupts fire in
        # a row before reading resumes to a normal EOF. A short read or an
        # interrupt mistaken for EOF truncates the parse (the PEM would be
        # unfinished and rejected); a resume that replays or drops bytes
        # corrupts the base64 stream -- both are caught by the known-answer
        # fingerprint comparison and the delivered-byte counter.
        for key_name, der, pem in (
            ("rsa", self.rsa_der, self.rsa_pem),
            ("ed25519", self.ed_der, self.ed_pem),
        ):
            with self.subTest(key=key_name):
                at = len(pem) // 2
                path = self.write_file(f"eintr/short-{key_name}.pub", pem)
                report = self.tmp / f"eintr/short-{key_name}.report"

                result = self.run_key_id_with_eintr(
                    path, report, at=at, times=3, short=7
                )

                self.assertFingerprintOk(result, der)

                fields = self.read_eintr_report(report)
                # The short reads and the three consecutive interrupts
                # genuinely happened, the first of them strictly inside the
                # file (not at its start, not at or past its end).
                self.assertGreater(fields["short"], 0)
                self.assertEqual(fields["eintr"], 3)
                self.assertGreaterEqual(fields["eintr_pos"], at)
                self.assertGreater(fields["eintr_pos"], 0)
                self.assertLess(fields["eintr_pos"], len(pem))
                self.assertEqual(fields["eio"], 0)
                self.assertEqual(fields["delivered"], len(pem))
                self.assertEqual(path.read_bytes(), pem)

    @requires_eintr_preload
    def test_eintr_with_block_structure_split_across_reads(self):
        # The whole-file rules still apply to content delivered after a
        # resume: surrounding ASCII whitespace, the BEGIN/END markers, the
        # base64 body and CRLF line endings may all be split between reads.
        # With the per-read cap below, every marker byte, base64 quantum and
        # CR/LF pair crosses read calls; the padding pushes the block across
        # 64 KiB read passes as well, and two interrupts fire inside it.
        cases = (
            ("rsa-crlf", self.rsa_der, self.rsa_pem.replace(b"\n", b"\r\n"), 1),
            ("ed25519-lf", self.ed_der, self.ed_pem, 5),
        )
        for case_name, der, pem, short in cases:
            with self.subTest(case=case_name):
                content = (
                    ascii_whitespace(CHUNK_SIZE - 1) + pem
                    + ascii_whitespace(CHUNK_SIZE + 1)
                )
                path = self.write_file(f"eintr/split-{case_name}.pub", content)
                report = self.tmp / f"eintr/split-{case_name}.report"

                result = self.run_key_id_with_eintr(
                    path, report, at=CHUNK_SIZE + 3, times=2, short=short
                )

                self.assertFingerprintOk(result, der)

                fields = self.read_eintr_report(report)
                self.assertEqual(fields["eintr"], 2)
                self.assertGreater(fields["short"], 0)
                # The interrupts fired inside the block, which starts
                # CHUNK_SIZE - 1 bytes into the file.
                self.assertGreaterEqual(fields["eintr_pos"], CHUNK_SIZE + 3)
                self.assertEqual(fields["delivered"], len(content))
                self.assertEqual(path.read_bytes(), content)

    @requires_eintr_preload
    def test_eintr_then_non_whitespace_after_block_is_still_rejected(self):
        # An interrupted, resumed read must not end the parse early: having
        # seen the complete END marker before the interrupts is no excuse to
        # stop classifying bytes. The stray non-whitespace byte after the
        # block still makes the input an invalid public key.
        block = self.ed_pem
        content = block + b" " + ascii_whitespace(37) + b"x"
        path = self.write_file("eintr/stray.pub", content)

        # Control: without injection the same file is rejected the same way.
        self.assertInvalidPublicKey(self.run_key_id(str(path)), path)

        report = self.tmp / "eintr/stray.report"
        result = self.run_key_id_with_eintr(
            path, report, at=len(block), times=2, short=9
        )

        self.assertInvalidPublicKey(result, path)

        fields = self.read_eintr_report(report)
        # The interrupts fired only after the complete block had been
        # delivered, yet reading still continued to the very last byte --
        # no fingerprint was printed when the block completed.
        self.assertEqual(fields["eintr"], 2)
        self.assertGreaterEqual(fields["eintr_pos"], len(block))
        self.assertEqual(fields["delivered"], len(content))
        self.assertEqual(path.read_bytes(), content)

    @requires_eintr_preload
    def test_eintr_then_genuine_read_error_is_still_a_read_failure(self):
        # A transient interrupt must not mask a later genuine read error:
        # even though the complete public-key block was already delivered
        # before the failure, the run fails as a read failure -- it is not
        # reported as invalid key content and no fingerprint is printed.
        content = self.rsa_pem + ascii_whitespace(CHUNK_SIZE)
        path = self.write_file("eintr/then-eio.pub", content)
        eio_at = len(self.rsa_pem) + 10  # past the complete block

        # Control: the same interrupts without the I/O error still yield the
        # fingerprint, so the failure below is attributable to the genuine
        # read error, not to the interrupts or the setup.
        ok_report = self.tmp / "eintr/then-eio-control.report"
        ok = self.run_key_id_with_eintr(
            path, ok_report, at=100, times=2, short=64
        )
        self.assertFingerprintOk(ok, self.rsa_der)
        self.assertEqual(self.read_eintr_report(ok_report)["eintr"], 2)

        report = self.tmp / "eintr/then-eio.report"
        result = self.run_key_id_with_eintr(
            path, report, at=100, times=2, short=64, eio_after=eio_at
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"read", result.stderr.lower())
        self.assertIn(os.fsencode(str(path)), result.stderr)
        self.assertNotIn(b"does not contain", result.stderr)
        self.assertNotIn(b"spki-sha256", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

        fields = self.read_eintr_report(report)
        # The interrupts and the genuine error both really happened, and
        # real content past the complete block was delivered before it.
        self.assertEqual(fields["eintr"], 2)
        self.assertGreaterEqual(fields["eio"], 1)
        self.assertGreaterEqual(fields["delivered"], eio_at)
        self.assertEqual(path.read_bytes(), content)

    @requires_eintr_preload
    def test_eintr_preload_loaded_but_unarmed_behaves_like_normal_read(self):
        # The injector is loaded and pointed at the file, but no interrupt,
        # short-read or error knob is set: reads pass straight through and
        # the result is the plain uninterrupted fingerprint. Together with
        # the counter assertions above this keeps the armed tests honest --
        # they can only pass when the staged conditions genuinely occurred.
        for key_name, der, pem in (
            ("rsa", self.rsa_der, self.rsa_pem),
            ("ed25519", self.ed_der, self.ed_pem),
        ):
            with self.subTest(key=key_name):
                path = self.write_file(f"eintr/unarmed/{key_name}.pub", pem)
                report = self.tmp / f"eintr/unarmed/{key_name}.report"

                result = self.run_key_id_with_eintr(path, report)

                self.assertFingerprintOk(result, der)
                fields = self.read_eintr_report(report)
                self.assertEqual(fields["eintr"], 0)
                self.assertEqual(fields["eio"], 0)
                self.assertEqual(fields["short"], 0)
                self.assertEqual(fields["delivered"], len(pem))

    # -- usage errors (exit code 2) --------------------------------------

    def assertUsageError(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage", result.stderr)
        self.assertIn(b"key-id", result.stderr)
        self.assertTrue(result.stderr.endswith(b"\n"))

    def test_missing_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("key-id"))

    def test_empty_path_argument_is_usage_error(self):
        self.assertUsageError(self.run_sealmark("key-id", ""))

    def test_extra_argument_is_usage_error(self):
        path = self.write_file("ed.pub", self.ed_pem)
        self.assertUsageError(
            self.run_sealmark("key-id", str(path), "extra")
        )

    def test_no_arguments_is_usage_error(self):
        result = self.run_sealmark()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")

    # -- pre-existing features kept compatible ---------------------------

    def test_version_output_unchanged(self):
        result = self.run_sealmark("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"sealmark 0.1.0\n")

    def test_digest_still_hashes_raw_bytes_not_parsed_key(self):
        # digest's result must remain the raw-byte digest, which differs from
        # the key fingerprint and changes when the PEM is re-wrapped.
        path = self.write_file("ed.pub", self.ed_pem)
        rewrapped = self.write_file(
            "ed-rewrapped.pub", wrap_public_pem(self.ed_der, 10, b"\r\n")
        )
        d1 = self.run_sealmark("digest", str(path))
        d2 = self.run_sealmark("digest", str(rewrapped))
        k1 = self.run_key_id(str(path))
        self.assertEqual(d1.returncode, 0, d1.stderr)
        self.assertEqual(d2.returncode, 0, d2.stderr)
        self.assertNotEqual(d1.stdout, d2.stdout)  # layout changes raw digest
        self.assertEqual(
            d1.stdout,
            b"sha256:" + hashlib.sha256(self.ed_pem).hexdigest().encode()
            + b"\n",
        )
        self.assertNotEqual(k1.stdout, d1.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
