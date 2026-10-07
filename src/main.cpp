#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
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
// digest, verify-digest and key-id all walk the same pipeline: open the
// input, require the object actually opened to be a regular file, then read
// its complete raw bytes from the start in fixed-size passes until normal
// EOF, treating text and binary content identically. The three only differ
// in what happens to each chunk, which is expressed by a ByteSink (see
// processFileChunks):
//   * digest / verify-digest stream the bytes straight into SHA-256, so their
//     memory use does not grow with the file;
//   * key-id runs a streaming PEM parser over the chunks: the surrounding
//     ASCII whitespace and the base64 text are consumed byte by byte without
//     being retained, and only the decoded SubjectPublicKeyInfo DER is kept,
//     so its memory use tracks the (small) public-key encoding rather than
//     the file size.
// The error reporting for the open, file-type and read stages lives here
// once; sinks report only their own processing failures.

// Size of every read pass for all three commands.
constexpr size_t kReadChunkSize = 64 * 1024;

// Opens pathArg and requires the object actually opened -- the final target
// of any symlink chain, examined on the open file descriptor itself -- to be
// a regular file. The descriptor is fstat()ed, not the path: opening and the
// type decision are one and the same object, so there is no window in which a
// path that named a regular file at check time could be swapped for a FIFO or
// other non-regular object before it is opened. A FIFO is opened with
// O_NONBLOCK so the open itself never blocks waiting for the other end; the
// descriptor is closed immediately after fstat() shows it is not regular, so
// a FIFO's data is never read and no FIFO read can ever block. Once a regular
// file is held open, later reads always refer to that same file even if the
// path is renamed or replaced afterwards.
//
// The two pre-read failure stages stay distinct: a failure to open the path
// ("cannot open", covering a path that vanished, a dangling symlink or a
// traversal/permission error) and an object that opened but is not a regular
// file ("is not a regular file"). On failure prints a reason containing
// pathArg to stderr, closes any descriptor it opened and returns -1.
int openRegularInput(const char* pathArg) {
    // O_NONBLOCK keeps an open() on a FIFO without a writer from blocking;
    // it has no effect on regular files. O_CLOEXEC does not change behavior
    // for this process but keeps the descriptor from leaking if a later
    // change ever execs.
    int fd = ::open(pathArg, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        const int err = errno;
        std::cerr << "sealmark: cannot open '" << pathArg << "': "
                  << std::strerror(err) << '\n';
        return -1;
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        const int err = errno;
        std::cerr << "sealmark: cannot open '" << pathArg << "': "
                  << std::strerror(err) << '\n';
        ::close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        std::cerr << "sealmark: '" << pathArg
                  << "' is not a regular file\n";
        ::close(fd);
        return -1;
    }
    return fd;
}

// Closes the descriptor on destruction, so every failure path below -- a
// failed start(), a rejected chunk or a read error -- releases it.
class FdGuard {
public:
    explicit FdGuard(int fd) : fd_(fd) {}
    ~FdGuard() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;

private:
    int fd_;
};

// Feeds a regular file's complete raw bytes to sink:
//   start()             once, immediately after the file is opened;
//   consume(data, size) for every non-empty chunk, including a final short
//                       one (a zero-length file yields no consume() call);
//   finish()            exactly once, only after a read reaching normal EOF.
// A false return aborts the operation and the sink is responsible for its own
// diagnostic. read() on a regular file is allowed to return fewer bytes than
// requested without meaning EOF (an interrupt, a short kernel read, ...), so
// each pass keeps reading until the buffer fills or read() reports zero; only
// a zero return is normal EOF. A read error -- including one after some bytes
// were already delivered -- is reported as such and never reaches finish(), so
// a mid-read failure can never surface as a digest, a match/mismatch result
// or a key fingerprint.
template <typename ByteSink>
bool processFileChunks(const char* pathArg, ByteSink& sink) {
    const int openedFd = openRegularInput(pathArg);
    if (openedFd < 0) {
        return false;
    }
    FdGuard fdGuard(openedFd);
    if (!sink.start()) {
        return false;
    }

    std::vector<char> buffer(kReadChunkSize);
    while (true) {
        size_t filled = 0;
        bool reachedEof = false;
        while (filled < buffer.size()) {
            ssize_t got = 0;
            do {
                got = ::read(openedFd, buffer.data() + filled,
                             buffer.size() - filled);
            } while (got < 0 && errno == EINTR);
            if (got < 0) {
                // The file was already opened successfully; this is a
                // read-stage failure, never an open error or a content/format
                // problem -- even if earlier bytes of this pass were already
                // delivered to the sink.
                std::cerr << "sealmark: failed to read '" << pathArg
                          << "'\n";
                return false;
            }
            if (got == 0) {
                reachedEof = true;  // normal end of file
                break;
            }
            const size_t n = static_cast<size_t>(got);
            if (!sink.consume(buffer.data() + filled, n)) {
                return false;
            }
            filled += n;
        }
        if (reachedEof) {
            break;
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

// --- key-id input handling --------------------------------------------------
//
// The key-id input rules are split into three independent layers, each owning
// exactly one concern and testable in isolation:
//
//   1. StrictBase64Decoder -- the encoding rules for the payload characters:
//      alphabet, quantum assembly, padding placement and canonical unused
//      bits. It knows nothing about PEM markers, lines or whitespace.
//   2. PublicKeyPemParser -- the PEM text rules: surrounding whitespace, the
//      BEGIN/END markers and the line structure of the body. It decides which
//      characters are payload and hands them to the decoder; it never
//      inspects the base64 alphabet or assembles quanta itself.
//   3. isCanonicalSpkiDer -- the DER rules for the decoded payload: one
//      complete, canonical SubjectPublicKeyInfo covering every byte.
//
// PublicKeyPemSink then adapts the parser to the ByteSink interface used by
// processFileChunks and owns the key-id error reporting.

// --- Layer 1: strict canonical Base64 decoding ------------------------------
//
// Incremental decoder for the payload of a PEM block. The rules enforced
// here, and only here:
//   * the alphabet is A-Z a-z 0-9 '+' '/'; every other character is invalid
//     ('-' is deliberately outside the alphabet, so a PEM boundary that
//     reaches the decoder fails here rather than being consumed);
//   * the stream is a whole number of 4-character quanta;
//   * '=' padding is legal only as the conventional "xx==" / "xxx=" tail of
//     the final quantum, no quantum may follow a padded one, and the unused
//     bits of the last data character must be zero -- non-canonical encodings
//     are rejected, never repaired;
//   * the decoded payload is at least one byte.
// Each quantum is decoded the moment its fourth character arrives, so no
// base64 text is ever accumulated; memory use tracks the decoded payload
// only.
class StrictBase64Decoder {
public:
    bool feed(unsigned char c) {
        quantum_[quantumLen_++] = c;
        if (quantumLen_ < 4) {
            return true;  // wait for the rest of the quantum
        }
        quantumLen_ = 0;
        return decodeQuantum();
    }

    // At end of input the stream must have ended on a quantum boundary and
    // must decode to at least one byte.
    bool finish() const {
        return quantumLen_ == 0 && !decoded_.empty();
    }

    // Valid only after finish() succeeded: the decoded payload bytes.
    const std::vector<unsigned char>& decoded() const { return decoded_; }

private:
    static int valueOf(unsigned char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    // Decodes one assembled quantum, enforcing the padding and canonical-bit
    // rules. Decoding is strict and canonical, quantum by quantum.
    bool decodeQuantum() {
        const int a = valueOf(quantum_[0]);
        const int b = valueOf(quantum_[1]);
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
            decoded_.push_back(
                static_cast<unsigned char>((a << 2) | (b >> 4)));
            sawPadding_ = true;
        } else {
            const int cv = valueOf(quantum_[2]);
            if (cv < 0) {
                return false;
            }
            if (pad3) {
                if ((cv & 0x03) != 0) {
                    return false;  // non-canonical: unused padding bits must be 0
                }
                decoded_.push_back(
                    static_cast<unsigned char>((a << 2) | (b >> 4)));
                decoded_.push_back(static_cast<unsigned char>(
                    ((b & 0x0f) << 4) | (cv >> 2)));
                sawPadding_ = true;
            } else {
                const int d = valueOf(quantum_[3]);
                if (d < 0) {
                    return false;
                }
                decoded_.push_back(
                    static_cast<unsigned char>((a << 2) | (b >> 4)));
                decoded_.push_back(static_cast<unsigned char>(
                    ((b & 0x0f) << 4) | (cv >> 2)));
                decoded_.push_back(static_cast<unsigned char>(
                    ((cv & 0x03) << 6) | d));
            }
        }
        return true;
    }

    unsigned char quantum_[4] = {};
    size_t quantumLen_ = 0;
    bool sawPadding_ = false;  // a padded (final) quantum already occurred
    std::vector<unsigned char> decoded_;
};

// --- Layer 2: PEM text structure --------------------------------------------
//
// Streaming parser for the strict single-block PEM structure used by key-id:
//
//   [ASCII ws] -----BEGIN PUBLIC KEY----- LF/CRLF
//   (payload lines; no blank or whitespace-only lines) ...
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
// retained besides the fixed-size parser state and the decoder's payload: the
// surrounding whitespace is merely classified and discarded, and every
// payload character is forwarded to the StrictBase64Decoder the moment it
// arrives. Memory use therefore depends on the size of the encoded public key
// itself, not on the amount of whitespace around the block or on the file
// size; no file-size limit is imposed.
//
// Anything outside the grammar above fails deterministically: non-whitespace
// outside the block, more than one block, any other PEM label (private keys,
// certificates, PKCS#1 RSA public keys, ...). Whether the payload characters
// themselves are well-formed base64 is the decoder's concern, not this
// parser's.
class PublicKeyPemParser {
public:
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
                return feedPayloadChar(c);

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
                return feedPayloadChar(c);

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

    // At end of input the text structure must be complete -- a fully matched
    // END marker, with or without trailing whitespace -- and the payload
    // stream must satisfy the decoder's own end-of-input rules.
    bool finish() const {
        bool structureComplete = false;
        switch (phase_) {
            case Phase::kEndMarker:
                // A fully matched END marker needs no trailing whitespace or
                // line feed at EOF; an unfinished match is a truncated marker.
                structureComplete = markerMatched_ == kPemEnd.size();
                break;
            case Phase::kPostamble:
                // Complete marker already followed by at least one whitespace
                // byte; everything remaining was whitespace as well.
                structureComplete = true;
                break;
            case Phase::kPreamble:       // empty or whitespace-only file
            case Phase::kBeginMarker:    // truncated BEGIN line
            case Phase::kBeginCr:        // CR in the header not followed by LF
            case Phase::kBodyLineStart:
            case Phase::kBodyData:
            case Phase::kBodyCr:         // truncated: no END line
                break;
        }
        return structureComplete && decoder_.finish();
    }

    // Valid only after finish() succeeded: the decoded payload bytes.
    const std::vector<unsigned char>& payload() const {
        return decoder_.decoded();
    }

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

    bool beginComplete() {
        phase_ = Phase::kBodyLineStart;
        lineEmpty_ = true;
        return true;
    }

    bool endComplete() {
        phase_ = Phase::kPostamble;
        return true;
    }

    // Hands one payload character to the decoder. The parser only records its
    // own line state; every encoding rule lives in the decoder.
    bool feedPayloadChar(unsigned char c) {
        phase_ = Phase::kBodyData;
        lineEmpty_ = false;
        return decoder_.feed(c);
    }

    Phase phase_ = Phase::kPreamble;
    size_t markerMatched_ = 0;  // prefix length of the marker being matched
    bool lineEmpty_ = true;     // current body line has seen no data yet
    StrictBase64Decoder decoder_;
};

// --- Layer 3: canonical SubjectPublicKeyInfo DER ----------------------------
//
// Validates that a decoded payload is one complete SubjectPublicKeyInfo DER
// structure covering every byte, understood by the crypto library, and in
// canonical encoding. Re-encoding the parsed structure must reproduce the
// payload byte for byte; that round trip rules out non-DER BER encodings and
// other representations OpenSSL might otherwise accept, without normalizing
// anything first. The bytes hashed for the fingerprint are therefore the
// canonical SPKI DER, so PEM line wrapping and line endings never influence
// the result.
bool isCanonicalSpkiDer(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    const std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        d2i_PUBKEY_ex(nullptr, &p, static_cast<long>(der.size()), nullptr,
                      nullptr),
        &EVP_PKEY_free);
    if (!pkey) {
        return false;
    }
    if (p - der.data() != static_cast<ptrdiff_t>(der.size())) {
        return false;  // trailing bytes after the SPKI structure
    }

    const int encLen = i2d_PUBKEY(pkey.get(), nullptr);
    if (encLen <= 0 || static_cast<size_t>(encLen) != der.size()) {
        return false;
    }
    std::vector<unsigned char> reencoded(static_cast<size_t>(encLen));
    unsigned char* q = reencoded.data();
    if (i2d_PUBKEY(pkey.get(), &q) != encLen || reencoded != der) {
        return false;  // non-canonical DER
    }
    return true;
}

// ByteSink adapter for key-id: feeds the file bytes to the PEM parser chunk
// by chunk, applies the DER validation once the text and encoding layers have
// accepted the input, and reports every content failure in one place.
class PublicKeyPemSink {
public:
    explicit PublicKeyPemSink(const char* pathArg) : pathArg_(pathArg) {}

    bool start() { return true; }

    bool consume(const char* data, size_t size) {
        if (failed_) {
            return false;  // stay failed across the rest of the file
        }
        for (size_t i = 0; i < size; ++i) {
            if (!parser_.feed(static_cast<unsigned char>(data[i]))) {
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
        const bool ok =
            parser_.finish() && isCanonicalSpkiDer(parser_.payload());
        if (!ok) {
            failed_ = true;
            reportInvalid();
        }
        return ok;
    }

    // Valid only after finish() succeeded: the canonical SPKI DER.
    const std::vector<unsigned char>& spkiDer() const {
        return parser_.payload();
    }

private:
    void reportInvalid() const {
        std::cerr << "sealmark: '" << pathArg_
                  << "' does not contain a single valid PEM-encoded "
                     "SubjectPublicKeyInfo public key (PUBLIC KEY)\n";
    }

    PublicKeyPemParser parser_;
    bool failed_ = false;
    const char* pathArg_ = nullptr;
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
