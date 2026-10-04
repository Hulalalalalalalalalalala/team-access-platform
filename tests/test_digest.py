#!/usr/bin/env python3
"""Regression tests for sealmark's `digest` command.

Drives the built sealmark binary and checks its observable contract:
SHA-256 of the file's complete raw bytes, exact stdout/stderr/exit-code
conventions. All inputs are created by this script in a temporary
directory, so the tests do not depend on the machine's documents or on
the current working directory.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Must match the streaming chunk size in src/main.cpp.
CHUNK = 64 * 1024

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

OUTPUT_RE = re.compile(rb"^sha256:[0-9a-f]{64}\n$")


def deterministic_bytes(length):
    """Deterministic pseudo-random byte content (no reliance on os.urandom)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(b"sealmark-test-" + str(counter).encode()).digest())
        counter += 1
    return bytes(out[:length])


class Failure(Exception):
    pass


def run(binary, *args):
    return subprocess.run(
        [binary, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def check(condition, message):
    if not condition:
        raise Failure(message)


def expect_digest(binary, path, content):
    """Run `sealmark digest <path>` and verify the full success contract."""
    result = run(binary, "digest", path)
    check(result.returncode == 0,
          f"{path!r}: expected exit 0, got {result.returncode} "
          f"(stderr={result.stderr!r})")
    check(result.stderr == b"",
          f"{path!r}: expected empty stderr, got {result.stderr!r}")
    check(OUTPUT_RE.match(result.stdout) is not None,
          f"{path!r}: stdout must be exactly 'sha256:' + 64 lowercase hex "
          f"chars + newline, got {result.stdout!r}")
    expected = "sha256:" + hashlib.sha256(content).hexdigest() + "\n"
    check(result.stdout == expected.encode(),
          f"{path!r}: digest mismatch\n  expected {expected!r}\n"
          f"  got      {result.stdout!r}")


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def test_success_cases(binary, tmp):
    # Smaller than one read chunk.
    small = b"hello sealmark\n"
    write(os.path.join(tmp, "small.bin"), small)
    expect_digest(binary, os.path.join(tmp, "small.bin"), small)

    # Exactly one chunk (boundary: read fills the buffer, next read hits EOF).
    exact = deterministic_bytes(CHUNK)
    write(os.path.join(tmp, "exact-chunk.bin"), exact)
    expect_digest(binary, os.path.join(tmp, "exact-chunk.bin"), exact)

    # One byte past the chunk boundary (catches off-by-one truncation).
    over = deterministic_bytes(CHUNK + 1)
    write(os.path.join(tmp, "over-chunk.bin"), over)
    expect_digest(binary, os.path.join(tmp, "over-chunk.bin"), over)

    # One byte short of the chunk boundary.
    under = deterministic_bytes(CHUNK - 1)
    write(os.path.join(tmp, "under-chunk.bin"), under)
    expect_digest(binary, os.path.join(tmp, "under-chunk.bin"), under)

    # Several full chunks plus a small tail (catches dropped/duplicated
    # trailing reads in the streaming loop).
    multi = deterministic_bytes(3 * CHUNK + 7)
    write(os.path.join(tmp, "multi-chunk.bin"), multi)
    expect_digest(binary, os.path.join(tmp, "multi-chunk.bin"), multi)

    # Binary content: zero bytes, newlines, UTF-8 BOM, non-text bytes.
    # All of it must be hashed verbatim, with no text-mode translation.
    binary_content = (b"\xef\xbb\xbf" + b"line1\r\nline2\n" + b"\x00\x00\x00"
                      + bytes(range(256)) + b"\xff\xfe\x00\x80")
    write(os.path.join(tmp, "binary.bin"), binary_content)
    expect_digest(binary, os.path.join(tmp, "binary.bin"), binary_content)

    # A change in only the final byte must change the digest: the tail
    # bytes are really part of the hashed stream.
    tail_a = deterministic_bytes(CHUNK + 3)
    tail_b = tail_a[:-1] + bytes([tail_a[-1] ^ 0x01])
    write(os.path.join(tmp, "tail-a.bin"), tail_a)
    write(os.path.join(tmp, "tail-b.bin"), tail_b)
    expect_digest(binary, os.path.join(tmp, "tail-a.bin"), tail_a)
    expect_digest(binary, os.path.join(tmp, "tail-b.bin"), tail_b)
    check(hashlib.sha256(tail_a).digest() != hashlib.sha256(tail_b).digest(),
          "test setup error: tail variants must differ")

    # Empty file is valid input and yields the standard empty SHA-256.
    empty = os.path.join(tmp, "empty.bin")
    write(empty, b"")
    expect_digest(binary, empty, b"")
    result = run(binary, "digest", empty)
    check(result.stdout == ("sha256:" + EMPTY_SHA256 + "\n").encode(),
          f"empty file must hash to {EMPTY_SHA256}, got {result.stdout!r}")

    # Same bytes under a different name and directory -> same digest.
    content = deterministic_bytes(1000)
    path_a = os.path.join(tmp, "alpha", "first.bin")
    path_b = os.path.join(tmp, "beta", "second.bin")
    write(path_a, content)
    write(path_b, content)
    expect_digest(binary, path_a, content)
    expect_digest(binary, path_b, content)

    # Paths containing spaces and non-ASCII characters.
    spaced = os.path.join(tmp, "dir with spaces", "my file.bin")
    write(spaced, content)
    expect_digest(binary, spaced, content)
    unicode_path = os.path.join(tmp, "文档", "报告 数据.bin")
    write(unicode_path, content)
    expect_digest(binary, unicode_path, content)


def test_failure_cases(binary, tmp):
    # Nonexistent path: exit 1, empty stdout, stderr names the path.
    missing = os.path.join(tmp, "no-such-file.bin")
    result = run(binary, "digest", missing)
    check(result.returncode == 1,
          f"missing path: expected exit 1, got {result.returncode}")
    check(result.stdout == b"",
          f"missing path: expected empty stdout, got {result.stdout!r}")
    check(missing.encode() in result.stderr,
          f"missing path: stderr must contain the path, got {result.stderr!r}")

    # A directory is not a valid digest input.
    directory = os.path.join(tmp, "a-directory")
    os.makedirs(directory, exist_ok=True)
    result = run(binary, "digest", directory)
    check(result.returncode == 1,
          f"directory: expected exit 1, got {result.returncode}")
    check(result.stdout == b"",
          f"directory: expected empty stdout, got {result.stdout!r}")
    check(directory.encode() in result.stderr,
          f"directory: stderr must contain the path, got {result.stderr!r}")

    # Missing path argument: usage error, exit 2, usage on stderr.
    result = run(binary, "digest")
    check(result.returncode == 2,
          f"no path: expected exit 2, got {result.returncode}")
    check(result.stdout == b"",
          f"no path: expected empty stdout, got {result.stdout!r}")
    check(b"Usage" in result.stderr or b"usage" in result.stderr,
          f"no path: expected usage on stderr, got {result.stderr!r}")

    # Empty path argument: usage error, exit 2.
    result = run(binary, "digest", "")
    check(result.returncode == 2,
          f"empty path: expected exit 2, got {result.returncode}")
    check(result.stdout == b"",
          f"empty path: expected empty stdout, got {result.stdout!r}")
    check(b"Usage" in result.stderr or b"usage" in result.stderr,
          f"empty path: expected usage on stderr, got {result.stderr!r}")


def test_version(binary):
    result = run(binary, "--version")
    check(result.returncode == 0,
          f"--version: expected exit 0, got {result.returncode}")
    check(result.stdout == b"sealmark 0.1.0\n",
          f"--version: unexpected stdout {result.stdout!r}")
    check(result.stderr == b"",
          f"--version: expected empty stderr, got {result.stderr!r}")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-sealmark-binary>", file=sys.stderr)
        return 2
    binary = sys.argv[1]

    tmp = tempfile.mkdtemp(prefix="sealmark-test-")
    try:
        test_success_cases(binary, tmp)
        test_failure_cases(binary, tmp)
        test_version(binary)
    except Failure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("all sealmark digest tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
