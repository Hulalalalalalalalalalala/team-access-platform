#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace {

constexpr size_t kSha256Size = 32;
constexpr std::string_view kDigestPrefix = "sha256:";
constexpr size_t kDigestHexLen = 2 * kSha256Size;  // 64 lowercase hex chars
constexpr std::string_view kSpkiFingerprintPrefix = "spki-sha256:";

constexpr std::string_view kPemBegin = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kPemEnd = "-----END PUBLIC KEY-----";

int printUsage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n"
                 "       sealmark verify-digest <file> <expected-digest>\n"
                 "       sealmark key-id <public-key-file>\n";
    return 2;
}

// ASCII whitespace permitted around the PEM block: the standard C/POSIX set
// of horizontal tab, LF, vertical tab, form feed, CR and space (the bytes for
// which Python's bytes.isspace() is true within ASCII). Everything else --
// including non-ASCII bytes -- is significant content and causes rejection.
bool isAsciiSpace(unsigned char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

// --- Shared regular-file reading ------------------------------------------
//
// digest, verify-digest and key-id all walk the same pipeline: require a
// regular file, open it, then read its complete raw bytes from the start in
// fixed-size passes until normal EOF, treating text and binary content
// identically. The three only differ in what happens to each chunk, which is
// expressed by a ByteSink (see processFileChunks):
//   * digest / verify-digest stream the bytes straight into SHA-256, so their
//     memory use does not grow with the file;
//   * key-id runs a streaming PEM parser over the chunks: the surrounding
//     ASCII whitespace and the base64 text are consumed byte by byte without
//     being retained, and only the decoded SubjectPublicKeyInfo DER is kept,
//     so its memory use tracks the (small) public-key encoding rather than
//     the file size.
// The error reporting for the access, open and read stages lives here once;
// sinks report only their own processing failures.

// Size of every read pass for all three commands.
constexpr size_t kReadChunkSize = 64 * 1024;

// Requires pathArg to name an existing regular file and opens it for raw
// binary reads. The two pre-read failure stages stay distinct: a failure to
// stat/access the path ("cannot access", covering a missing path) and an
// object that is not a regular file, followed by a failure to open it
// ("cannot open"). On failure prints a reason containing pathArg to stderr.
bool openRegularInput(const char* pathArg, std::ifstream& in) {
    namespace fs = std::filesystem;
    const fs::path path(pathArg);

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        if (ec) {
            std::cerr << "sealmark: cannot access '" << pathArg << "': "
                      << ec.message() << '\n';
        } else {
            std::cerr << "sealmark: '" << pathArg
                      << "' is not a regular file\n";
        }
        return false;
    }

    errno = 0;
    in.open(path, std::ios::binary);
    if (!in) {
        const int err = errno;
        std::cerr << "sealmark: cannot open '" << pathArg << "': "
                  << (err != 0 ? std::strerror(err) : "open failed") << '\n';
        return false;
    }
    return true;
}

// Feeds a regular file's complete raw bytes to sink:
//   start()             once, immediately after the file is opened;
//   consume(data, size) for every non-empty chunk, including a final short
//                       one (a zero-length file yields no consume() call);
//   finish()            exactly once, only after a read reaching normal EOF.
// A false return aborts the operation and the sink is responsible for its own
// diagnostic. A final read shorter than the chunk -- including zero bytes on
// an empty file -- after a non-failed read is normal EOF; only a failed read
// (badbit) after some bytes were delivered is a read error, which is reported
// as such and never reaches finish(). Hence a mid-read failure can never
// surface as a digest, a match/mismatch result or a key fingerprint.
template <typename ByteSink>
bool processFileChunks(const char* pathArg, ByteSink& sink) {
    std::ifstream in;
    if (!openRegularInput(pathArg, in)) {
        return false;
    }
    if (!sink.start()) {
        return false;
    }

    std::vector<char> buffer(kReadChunkSize);
    while (true) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 &&
            !sink.consume(buffer.data(), static_cast<size_t>(got))) {
            return false;
        }
        if (in.bad()) {
            // The file was already opened successfully; this is a read-stage
            // failure, never an open error or a content/format problem.
            std::cerr << "sealmark: failed to read '" << pathArg << "'\n";
            return false;
        }
        if (got < static_cast<std::streamsize>(buffer.size())) {
            break;  // normal end of file: a short or empty final read
        }
    }

    return sink.finish();
}

// Streams every chunk through SHA-256 with fixed-size buffers, so memory use
// stays constant regardless of file size. On a processing failure it prints
// the reason (including pathArg) itself; after success hash() holds exactly
// kSha256Size bytes.
class Sha256StreamSink {
public:
    explicit Sha256StreamSink(const char* pathArg) : pathArg_(pathArg) {}

    bool start() {
        ctx_.reset(EVP_MD_CTX_new());
        if (!ctx_ ||
            EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) != 1) {
            fail("SHA-256 initialization failed");
            return false;
        }
        return true;
    }

    bool consume(const char* data, size_t size) {
        if (EVP_DigestUpdate(ctx_.get(), data, size) != 1) {
            fail("SHA-256 computation failed");
            return false;
        }
        return true;
    }

    bool finish() {
        unsigned int hashLen = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), hash_, &hashLen) != 1 ||
            hashLen != kSha256Size) {
            fail("SHA-256 computation failed");
            return false;
        }
        return true;
    }

    const unsigned char* hash() const { return hash_; }

private:
    void fail(const char* what) {
        std::cerr << "sealmark: " << what << " for '" << pathArg_ << "'\n";
    }

    const char* pathArg_;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_{
        nullptr, &EVP_MD_CTX_free};
    unsigned char hash_[kSha256Size] = {};
};

// Streaming parser for the strict single-block PEM structure used by key-id:
//
//   [ASCII ws] -----BEGIN PUBLIC KEY----- LF/CRLF
//   (base64 lines; no blank or whitespace-only lines) ...
//   -----END PUBLIC KEY-----
//   [ASCII ws]
//
// The BEGIN line must end in LF or CRLF, but the END marker needs no line
// terminator at all: once it is fully matched, EOF may follow immediately or
// any number of ASCII whitespace bytes -- the conventional trailing LF or
// CRLF included, but also spaces or tabs glued directly to the marker, with
// no requirement that the first such byte be a line feed.
//
// Bytes are fed straight from the read passes, chunk by chunk, and nothing is
// retained besides the fixed-size parser state and the decoded payload: the
// surrounding whitespace is merely classified and discarded, and each base64
// quantum is decoded the moment its fourth character arrives, so no base64
// text is ever accumulated. Memory use therefore depends on the size of the
// encoded public key itself, not on the amount of whitespace around the block
// or on the file size; no file-size limit is imposed.
//
// Anything outside the grammar above fails deterministically: non-whitespace
// outside the block, more than one block, any other PEM label (private keys,
// certificates, PKCS#1 RSA public keys, ...), malformed or truncated base64.
// finish() additionally verifies that the decoded payload is one complete,
// canonical DER SubjectPublicKeyInfo understood by the crypto library, so
// non-DER BER encodings and trailing bytes are rejected as well.
class PublicKeyPemSink {
public:
    explicit PublicKeyPemSink(const char* pathArg) : pathArg_(pathArg) {}

    bool start() { return true; }

    bool consume(const char* data, size_t size) {
        if (failed_) {
            return false;  // stay failed across the rest of the file
        }
        for (size_t i = 0; i < size; ++i) {
            if (!feed(static_cast<unsigned char>(data[i]))) {
                failed_ = true;
                reportInvalid();
                return false;
            }
        }
        return true;
    }

    bool finish() {
        if (failed_) {
            return false;  // consume() already reported the reason
        }
        bool ok = false;
        switch (phase_) {
            case Phase::kEndMarker:
                // A fully matched END marker needs no trailing whitespace or
                // line feed at EOF; an unfinished match is a truncated marker.
                ok = markerMatched_ == kPemEnd.size();
                break;
            case Phase::kPostamble:
                // Complete marker already followed by at least one whitespace
                // byte; everything remaining was whitespace as well.
                ok = true;
                break;
            case Phase::kPreamble:       // empty or whitespace-only file
            case Phase::kBeginMarker:    // truncated BEGIN line
            case Phase::kBeginCr:        // CR in the header not followed by LF
            case Phase::kBodyLineStart:
            case Phase::kBodyData:
            case Phase::kBodyCr:         // truncated: no END line
                break;
        }
        if (ok) {
            ok = flushQuantumAtEnd() && validateSpkiDer();
        }
        if (!ok) {
            failed_ = true;
            reportInvalid();
        }
        return ok;
    }

    // Valid only after finish() succeeded: the canonical SPKI DER.
    const std::vector<unsigned char>& spkiDer() const { return der_; }

private:
    enum class Phase {
        kPreamble,
        kBeginMarker,
        kBeginCr,
        kBodyLineStart,
        kBodyData,
        kBodyCr,
        kEndMarker,
        kPostamble,
    };

    bool feed(unsigned char c) {
        switch (phase_) {
            case Phase::kPreamble:
                if (isAsciiSpace(c)) {
                    return true;
                }
                if (c == static_cast<unsigned char>(kPemBegin[0])) {
                    markerMatched_ = 1;
                    phase_ = Phase::kBeginMarker;
                    return true;
                }
                return false;

            case Phase::kBeginMarker:
                if (c == '\n') {
                    return markerMatched_ == kPemBegin.size() &&
                           beginComplete();
                }
                if (c == '\r') {
                    if (markerMatched_ != kPemBegin.size()) {
                        return false;
                    }
                    phase_ = Phase::kBeginCr;
                    return true;
                }
                if (markerMatched_ < kPemBegin.size() &&
                    c == static_cast<unsigned char>(kPemBegin[markerMatched_])) {
                    ++markerMatched_;
                    return true;
                }
                return false;

            case Phase::kBeginCr:
                // A CR in the header is only legal as the CR of CRLF.
                return c == '\n' && beginComplete();

            case Phase::kBodyLineStart:
                if (c == '-') {
                    markerMatched_ = 1;
                    phase_ = Phase::kEndMarker;
                    return true;
                }
                if (c == '\n') {
                    return false;  // no blank lines inside the block
                }
                if (isAsciiSpace(c)) {
                    return false;  // whitespace is allowed only around it
                }
                return feedBase64Data(c);

            case Phase::kBodyData:
                if (c == '\n') {
                    if (lineEmpty_) {
                        return false;  // blank or whitespace-only line
                    }
                    lineEmpty_ = true;
                    phase_ = Phase::kBodyLineStart;
                    return true;
                }
                if (c == '\r') {
                    if (lineEmpty_) {
                        return false;
                    }
                    phase_ = Phase::kBodyCr;
                    return true;
                }
                if (isAsciiSpace(c)) {
                    return false;
                }
                return feedBase64Data(c);

            case Phase::kBodyCr:
                // Bare CRs are not line separators: a CR must end with LF.
                if (c != '\n') {
                    return false;
                }
                lineEmpty_ = true;
                phase_ = Phase::kBodyLineStart;
                return true;

            case Phase::kEndMarker:
                // While the marker is still incomplete its bytes must match
                // literally. A complete marker terminates the block outright:
                // LF/CRLF, spaces and tabs are all just postamble whitespace,
                // so the byte right after the final '-' need not be a line
                // feed. Whitespace inside a still-unfinished marker is not
                // part of the literal and fails like any other mismatch.
                if (markerMatched_ == kPemEnd.size()) {
                    if (isAsciiSpace(c)) {
                        return endComplete();
                    }
                    return false;
                }
                if (c == static_cast<unsigned char>(
                        kPemEnd[markerMatched_])) {
                    ++markerMatched_;
                    return true;
                }
                return false;

            case Phase::kPostamble:
                // Everything still in the file must be ASCII whitespace; a
                // second block or any appended text is rejected, not ignored.
                return isAsciiSpace(c);
        }
        return false;
    }

    bool beginComplete() {
        phase_ = Phase::kBodyLineStart;
        lineEmpty_ = true;
        return true;
    }

    bool endComplete() {
        phase_ = Phase::kPostamble;
        return true;
    }

    static int base64Value(unsigned char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    // Feeds one character of a payload line. '-' is deliberately outside the
    // alphabet (it starts the END marker, handled by the caller), so any other
    // PEM boundary fails here rather than being consumed. Decoding is strict
    // and canonical, quantum by quantum; padding is legal only as the
    // conventional "x=" / "xx==" tail of the stream, and its unused bits must
    // be zero. This mirrors the former whole-file decoder exactly.
    bool feedBase64Data(unsigned char c) {
        phase_ = Phase::kBodyData;
        lineEmpty_ = false;

        quantum_[quantumLen_++] = c;
        if (quantumLen_ < 4) {
            return true;  // wait for the rest of the quantum
        }
        quantumLen_ = 0;

        const int a = base64Value(quantum_[0]);
        const int b = base64Value(quantum_[1]);
        if (a < 0 || b < 0) {
            return false;
        }

        const bool pad2 = quantum_[2] == '=';
        const bool pad3 = quantum_[3] == '=';
        if (sawPadding_) {
            return false;  // no complete quantum may follow a padded one
        }

        if (pad2) {
            if (!pad3) {
                return false;  // '=' at position 2 requires one at position 3
            }
            if ((b & 0x0f) != 0) {
                return false;  // non-canonical: unused padding bits must be 0
            }
            der_.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
            sawPadding_ = true;
        } else {
            const int cv = base64Value(quantum_[2]);
            if (cv < 0) {
                return false;
            }
            if (pad3) {
                if ((cv & 0x03) != 0) {
                    return false;  // non-canonical: unused padding bits must be 0
                }
                der_.push_back(
                    static_cast<unsigned char>((a << 2) | (b >> 4)));
                der_.push_back(static_cast<unsigned char>(
                    ((b & 0x0f) << 4) | (cv >> 2)));
                sawPadding_ = true;
            } else {
                const int d = base64Value(quantum_[3]);
                if (d < 0) {
                    return false;
                }
                der_.push_back(
                    static_cast<unsigned char>((a << 2) | (b >> 4)));
                der_.push_back(static_cast<unsigned char>(
                    ((b & 0x0f) << 4) | (cv >> 2)));
                der_.push_back(static_cast<unsigned char>(
                    ((cv & 0x03) << 6) | d));
            }
        }
        return true;
    }

    // At EOF the payload must have ended on a quantum boundary and must
    // decode to at least one byte.
    bool flushQuantumAtEnd() {
        if (quantumLen_ != 0 || der_.empty()) {
            return false;
        }
        return true;
    }

    // Validates that the decoded payload is one complete SubjectPublicKeyInfo
    // DER structure covering every byte, understood by the crypto library, and
    // in canonical encoding. Re-encoding the parsed structure must reproduce
    // the payload byte for byte; that round trip rules out non-DER BER
    // encodings and other representations OpenSSL might otherwise accept. The
    // bytes hashed for the fingerprint are therefore the canonical SPKI DER,
    // so PEM line wrapping and line endings never influence the result.
    bool validateSpkiDer() {
        const unsigned char* p = der_.data();
        const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            d2i_PUBKEY_ex(nullptr, &p, static_cast<long>(der_.size()), nullptr,
                          nullptr),
            &EVP_PKEY_free);
        if (!pkey) {
            return false;
        }
        if (p - der_.data() != static_cast<ptrdiff_t>(der_.size())) {
            return false;  // trailing bytes after the SPKI structure
        }

        const int encLen = i2d_PUBKEY(pkey.get(), nullptr);
        if (encLen <= 0 || static_cast<size_t>(encLen) != der_.size()) {
            return false;
        }
        std::vector<unsigned char> reencoded(static_cast<size_t>(encLen));
        unsigned char* q = reencoded.data();
        if (i2d_PUBKEY(pkey.get(), &q) != encLen || reencoded != der_) {
            return false;  // non-canonical DER
        }
        return true;
    }

    void reportInvalid() const {
        std::cerr << "sealmark: '" << pathArg_
                  << "' does not contain a single valid PEM-encoded "
                     "SubjectPublicKeyInfo public key (PUBLIC KEY)\n";
    }

    Phase phase_ = Phase::kPreamble;
    size_t markerMatched_ = 0;  // prefix length of the marker being matched
    bool lineEmpty_ = true;     // current body line has seen no data yet
    unsigned char quantum_[4] = {};
    size_t quantumLen_ = 0;
    bool sawPadding_ = false;  // a padded (final) quantum already occurred
    bool failed_ = false;
    const char* pathArg_ = nullptr;
    std::vector<unsigned char> der_;
};

// Renders bytes as lowercase hexadecimal with no separators or prefix.
std::string toHexLower(const unsigned char* data, size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * size);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0f]);
    }
    return out;
}

int digestFile(const char* pathArg) {
    Sha256StreamSink sink(pathArg);
    if (!processFileChunks(pathArg, sink)) {
        return 1;
    }

    std::cout << kDigestPrefix
              << toHexLower(sink.hash(), kSha256Size) << '\n';
    return 0;
}

// Accepts only "sha256:" followed by exactly 64 lowercase hexadecimal
// characters: no missing prefix, no uppercase, no other algorithm names,
// no surrounding whitespace or trailing content.
bool isValidExpectedDigest(std::string_view digest) {
    if (digest.size() != kDigestPrefix.size() + kDigestHexLen) {
        return false;
    }
    if (digest.substr(0, kDigestPrefix.size()) != kDigestPrefix) {
        return false;
    }
    for (size_t i = kDigestPrefix.size(); i < digest.size(); ++i) {
        const char c = digest[i];
        const bool isHex =
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!isHex) {
            return false;
        }
    }
    return true;
}

int verifyDigestFile(const char* pathArg, std::string_view expected) {
    Sha256StreamSink sink(pathArg);
    if (!processFileChunks(pathArg, sink)) {
        return 1;
    }

    std::string actual;
    actual.reserve(kDigestPrefix.size() + kDigestHexLen);
    actual.append(kDigestPrefix);
    actual.append(toHexLower(sink.hash(), kSha256Size));

    if (actual == expected) {
        std::cout << "match\n";
        return 0;
    }
    std::cout << "mismatch\n";
    return 3;
}

int keyIdFile(const char* pathArg) {
    PublicKeyPemSink sink(pathArg);
    if (!processFileChunks(pathArg, sink)) {
        return 1;
    }

    const std::vector<unsigned char>& spkiDer = sink.spkiDer();
    unsigned char hash[kSha256Size];
    unsigned int hashLen = 0;
    if (EVP_Digest(spkiDer.data(), spkiDer.size(), hash, &hashLen,
                   EVP_sha256(), nullptr) != 1 ||
        hashLen != kSha256Size) {
        std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg
                  << "'\n";
        return 1;
    }

    std::cout << kSpkiFingerprintPrefix
              << toHexLower(hash, kSha256Size) << '\n';
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "sealmark 0.1.0\n";
        return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "digest") {
        if (argv[2][0] == '\0') {
            return printUsage();
        }
        return digestFile(argv[2]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "key-id") {
        if (argv[2][0] == '\0') {
            return printUsage();
        }
        return keyIdFile(argv[2]);
    }
    if (argc == 4 && std::string_view(argv[1]) == "verify-digest") {
        // Validate every argument before touching the file so that a bad
        // path and a malformed digest together still report a usage error.
        if (argv[2][0] == '\0' || !isValidExpectedDigest(argv[3])) {
            return printUsage();
        }
        return verifyDigestFile(argv[2], argv[3]);
    }
    return printUsage();
}
