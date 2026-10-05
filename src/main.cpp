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

bool isBase64Char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

int base64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Strict canonical base64 decoder: length must be a positive multiple of
// four, '=' may occur only in the final quantum and only as the conventional
// "x=" / "xx==" tail, every other character must be alphabet data. OpenSSL's
// streaming decoder is noticeably lenient, so this is implemented on purpose
// to make truncated or corrupted encodings fail deterministically.
bool decodeBase64(const std::string& in, std::vector<unsigned char>& out) {
    if (in.empty() || in.size() % 4 != 0) {
        return false;
    }
    out.clear();
    out.reserve((in.size() / 4) * 3);

    const size_t quanta = in.size() / 4;
    for (size_t q = 0; q < quanta; ++q) {
        const size_t i = 4 * q;
        const bool last = (q == quanta - 1);
        const int a = base64Value(in[i]);
        const int b = base64Value(in[i + 1]);
        if (a < 0 || b < 0) {
            return false;
        }

        const bool pad2 = in[i + 2] == '=';
        const bool pad3 = in[i + 3] == '=';
        if (!last && (pad2 || pad3)) {
            return false;  // padding anywhere before the final quantum
        }

        if (pad2) {
            if (!pad3) {
                return false;  // '=' at position 2 requires one at position 3
            }
            if ((b & 0x0f) != 0) {
                return false;  // non-canonical: unused padding bits must be 0
            }
            out.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        } else {
            const int c = base64Value(in[i + 2]);
            if (c < 0) {
                return false;
            }
            if (pad3) {
                if ((c & 0x03) != 0) {
                    return false;  // non-canonical: unused padding bits must be 0
                }
                out.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
                out.push_back(
                    static_cast<unsigned char>(((b & 0x0f) << 4) | (c >> 2)));
            } else {
                const int d = base64Value(in[i + 3]);
                if (d < 0) {
                    return false;
                }
                out.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
                out.push_back(
                    static_cast<unsigned char>(((b & 0x0f) << 4) | (c >> 2)));
                out.push_back(
                    static_cast<unsigned char>(((c & 0x03) << 6) | d));
            }
        }
    }
    return true;
}

// Validates that a decoded PEM payload is one complete SubjectPublicKeyInfo
// DER structure covering every byte, understood by the crypto library, and in
// canonical encoding. Re-encoding the parsed structure must reproduce the
// payload byte for byte; that round trip rules out non-DER BER encodings and
// other representations OpenSSL might otherwise accept. The bytes hashed for
// the fingerprint are therefore the canonical SPKI DER, so PEM line wrapping
// and line endings never influence the result.
bool isCanonicalSpkiDer(const std::vector<unsigned char>& payload) {
    const unsigned char* p = payload.data();
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        d2i_PUBKEY_ex(nullptr, &p, static_cast<long>(payload.size()), nullptr,
                      nullptr),
        &EVP_PKEY_free);
    if (!pkey) {
        return false;
    }
    if (p - payload.data() != static_cast<ptrdiff_t>(payload.size())) {
        return false;  // trailing bytes after the SPKI structure
    }

    const int encLen = i2d_PUBKEY(pkey.get(), nullptr);
    if (encLen <= 0 ||
        static_cast<size_t>(encLen) != payload.size()) {
        return false;
    }
    std::vector<unsigned char> reencoded(static_cast<size_t>(encLen));
    unsigned char* q = reencoded.data();
    if (i2d_PUBKEY(pkey.get(), &q) != encLen || reencoded != payload) {
        return false;  // non-canonical DER
    }
    return true;
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
//   * key-id parses the PEM structure incrementally as the bytes arrive,
//     keeping only the base64 payload of the PUBLIC KEY block, so its memory
//     use tracks the size of the key encoding itself and never grows with
//     whitespace around the block.
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

// Incrementally parses the strict single-block PEM structure as the file's
// chunks stream by:
//
//   [ASCII ws] -----BEGIN PUBLIC KEY----- LF/CRLF
//   (base64 lines; no blank or whitespace-only lines) ...
//   -----END PUBLIC KEY----- LF/CRLF
//   [ASCII ws]
//
// Anything else is rejected: non-whitespace outside the block, more than one
// block, any other PEM label (private keys, certificates, PKCS#1 RSA public
// keys, ...), malformed or truncated base64, and payloads that are not one
// canonical SubjectPublicKeyInfo DER structure.
//
// The parser is a byte-at-a-time state machine, so it needs no chunk or line
// boundaries and never holds the raw file: whitespace before and after the
// block is discarded as it is read, marker lines are matched against
// fixed-size buffers bounded by the marker length, and only the base64
// payload itself is accumulated. Memory use therefore tracks the size of the
// key encoding, not the size of the file. The complete base64 text is decoded
// and DER-validated only in finish(), once the END marker and a clean trailer
// have been seen; a mid-read failure aborts before finish() and can never
// produce a fingerprint from partial content.
class PemPublicKeySink {
public:
    explicit PemPublicKeySink(const char* pathArg) : pathArg_(pathArg) {}

    bool start() { return true; }

    bool consume(const char* data, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            if (!feed(static_cast<unsigned char>(data[i]))) {
                return reject();
            }
        }
        return true;
    }

    // Reached only after a read to normal EOF. A trailing CR ends the final
    // line exactly as a CRLF would, and a final line without any newline is
    // still a complete line; then the parse must have reached the trailer
    // (a full BEGIN/payload/END block followed by whitespace only) and the
    // accumulated base64 must decode to one canonical SPKI DER structure.
    bool finish() {
        if (pendingCr_ && !endLine()) {
            return reject();
        }
        pendingCr_ = false;
        if ((state_ == State::kBeginLine || state_ == State::kEndLine) &&
            !endLine()) {
            return reject();
        }
        if (state_ != State::kTrailer) {
            return reject();  // empty, whitespace-only or truncated input
        }

        std::vector<unsigned char> payload;
        if (!decodeBase64(base64_, payload) || payload.empty() ||
            !isCanonicalSpkiDer(payload)) {
            return reject();
        }
        spkiDer_ = std::move(payload);
        return true;
    }

    const std::vector<unsigned char>& spkiDer() const { return spkiDer_; }

private:
    enum class State {
        kPreamble,   // only ASCII whitespace seen so far
        kBeginLine,  // buffering the line that must be the BEGIN marker
        kPayload,    // inside the block, accumulating base64 lines
        kEndLine,    // buffering a '-' led line that must be the END marker
        kTrailer,    // END marker consumed; only ASCII whitespace may follow
    };

    // Feeds one byte to the state machine; false means the input cannot be
    // the required single-PEM-block structure.
    bool feed(unsigned char c) {
        // A CR inside a line is legal only as the last byte before LF; the
        // decision is deferred by one byte so the CR can simply be dropped.
        if (pendingCr_) {
            pendingCr_ = false;
            if (c != '\n') {
                return false;
            }
            return endLine();
        }

        switch (state_) {
        case State::kPreamble:
            if (isAsciiSpace(c)) {
                return true;
            }
            state_ = State::kBeginLine;
            lineBuf_.push_back(static_cast<char>(c));
            return lineBuf_.size() <= kPemBegin.size();

        case State::kBeginLine:
            if (c == '\n') {
                return endLine();
            }
            if (c == '\r') {
                pendingCr_ = true;
                return true;
            }
            lineBuf_.push_back(static_cast<char>(c));
            // Longer than the marker can never match: reject at once instead
            // of letting the buffer grow.
            return lineBuf_.size() <= kPemBegin.size();

        case State::kPayload:
            if (c == '\n') {
                return endLine();
            }
            if (c == '\r') {
                pendingCr_ = true;
                return true;
            }
            if (!lineHasChars_ && c == '-') {
                // A line starting with '-' can only be the END marker; any
                // other PEM boundary fails the comparison in endLine().
                state_ = State::kEndLine;
                lineBuf_.push_back('-');
                return true;
            }
            // A payload line must be pure base64 ('=' included; its placement
            // is validated by decodeBase64). Whitespace, stray bytes and any
            // other character -- including a '-' that is not line-leading --
            // reject the file.
            if (isBase64Char(static_cast<char>(c))) {
                base64_.push_back(static_cast<char>(c));
                lineHasChars_ = true;
                return true;
            }
            return false;

        case State::kEndLine:
            if (c == '\n') {
                return endLine();
            }
            if (c == '\r') {
                pendingCr_ = true;
                return true;
            }
            lineBuf_.push_back(static_cast<char>(c));
            return lineBuf_.size() <= kPemEnd.size();

        case State::kTrailer:
            // Nothing but ASCII whitespace may follow the block through EOF,
            // so a second key or any appended text is rejected, never
            // ignored -- and only after it scans clean does finish() accept.
            return isAsciiSpace(c);
        }
        return false;  // unreachable
    }

    // Handles the end of the current line (LF, CRLF, a CR at EOF, or EOF
    // itself for an unterminated final line).
    bool endLine() {
        switch (state_) {
        case State::kBeginLine:
            if (lineBuf_ != kPemBegin) {
                return false;
            }
            lineBuf_.clear();
            state_ = State::kPayload;
            return true;
        case State::kPayload:
            if (!lineHasChars_) {
                return false;  // no blank or whitespace-only lines inside
            }
            lineHasChars_ = false;
            return true;
        case State::kEndLine:
            if (lineBuf_ != kPemEnd) {
                return false;
            }
            lineBuf_.clear();
            state_ = State::kTrailer;
            return true;
        case State::kPreamble:
        case State::kTrailer:
            return true;  // no line structure is tracked outside the block
        }
        return false;  // unreachable
    }

    bool reject() {
        std::cerr << "sealmark: '" << pathArg_
                  << "' does not contain a single valid PEM-encoded "
                     "SubjectPublicKeyInfo public key (PUBLIC KEY)\n";
        return false;
    }

    const char* pathArg_;
    State state_ = State::kPreamble;
    std::string lineBuf_;     // current marker line, bounded by marker length
    std::string base64_;      // the block's payload, the only growing buffer
    bool lineHasChars_ = false;
    bool pendingCr_ = false;
    std::vector<unsigned char> spkiDer_;
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
    PemPublicKeySink sink(pathArg);
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
