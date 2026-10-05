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

// Size of every read() issued against an input file. The digest commands
// feed one chunk straight into the hash context, so large files cost only
// this much memory; the Python regression suites reference this same value.
constexpr size_t kReadChunkSize = 64 * 1024;

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

std::string_view stripOneCr(std::string_view line) {
    if (!line.empty() && line.back() == '\r') {
        line.remove_suffix(1);
    }
    return line;
}

// Parses the strict single-block PEM structure:
//
//   [ASCII ws] -----BEGIN PUBLIC KEY----- LF/CRLF
//   (base64 lines; no blank or whitespace-only lines) ...
//   -----END PUBLIC KEY----- LF/CRLF
//   [ASCII ws]
//
// Anything else is rejected: non-whitespace outside the block, more than one
// block, any other PEM label (private keys, certificates, PKCS#1 RSA public
// keys, ...), malformed or truncated base64. Returns the decoded payload
// (nominally DER SubjectPublicKeyInfo) on success; structural DER validation
// happens in the caller.
bool parsePublicPem(const std::vector<unsigned char>& raw,
                    std::vector<unsigned char>& payloadOut) {
    const size_t n = raw.size();

    // Preamble: only ASCII whitespace may precede the block.
    size_t pos = 0;
    while (pos < n && isAsciiSpace(raw[pos])) {
        ++pos;
    }
    if (pos == n) {
        return false;  // empty or whitespace-only file
    }

    auto takeLine = [&](size_t start,
                        std::string_view& line) -> size_t {
        size_t end = start;
        while (end < n && raw[end] != '\n') {
            ++end;
        }
        line = std::string_view(
            reinterpret_cast<const char*>(raw.data() + start), end - start);
        return (end < n) ? end + 1 : end;
    };

    std::string_view line;
    pos = takeLine(pos, line);
    // Exactly the BEGIN marker, optionally followed by a single CR (CRLF).
    if (stripOneCr(line) != kPemBegin) {
        return false;
    }

    std::string base64;
    bool sawEnd = false;

    while (pos < n) {
        pos = takeLine(pos, line);
        const std::string_view core = stripOneCr(line);

        if (core == kPemEnd) {
            sawEnd = true;
            break;
        }

        if (core.empty()) {
            return false;  // no blank lines inside the block
        }
        bool onlySpace = true;
        for (char c : core) {
            if (!isAsciiSpace(static_cast<unsigned char>(c))) {
                onlySpace = false;
                break;
            }
        }
        if (onlySpace) {
            return false;  // whitespace is allowed only around the block
        }

        // A payload line must be pure base64. '-' is deliberately not in the
        // alphabet, so any other PEM boundary (a second block, a certificate
        // or private-key label) fails here rather than being consumed.
        for (char c : core) {
            if (!isBase64Char(c)) {
                return false;
            }
        }
        base64.append(core);
    }

    if (!sawEnd) {
        return false;  // truncated: no END line
    }

    // Nothing but ASCII whitespace may follow the block through EOF, so a
    // second key or any appended text is rejected instead of ignored.
    while (pos < n) {
        if (!isAsciiSpace(raw[pos])) {
            return false;
        }
        ++pos;
    }

    return decodeBase64(base64, payloadOut) && !payloadOut.empty();
}

// Validates that the decoded payload is one complete SubjectPublicKeyInfo DER
// structure covering every byte, understood by the crypto library, and in
// canonical encoding. Re-encoding the parsed structure must reproduce the
// payload byte for byte; that round trip rules out non-DER BER encodings and
// other representations OpenSSL might otherwise accept. The bytes hashed for
// the fingerprint are therefore the canonical SPKI DER, so PEM line wrapping
// and line endings never influence the result.
bool extractSpkiDer(const std::vector<unsigned char>& rawBytes,
                    std::vector<unsigned char>& derOut) {
    std::vector<unsigned char> payload;
    if (!parsePublicPem(rawBytes, payload)) {
        return false;
    }

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

    derOut = std::move(payload);
    return true;
}

// Shared file-ingestion path for digest, verify-digest and key-id: verify
// that the argument names a regular file, open it, and stream its complete
// raw bytes from the first byte through EOF in fixed-size kReadChunkSize
// chunks. Each chunk is handed to consume(data, size); the final chunk may
// be shorter than one buffer, and an empty file simply never invokes it.
// Every chunk except the final one is full, so callers that pipe chunks
// straight into a hash context keep memory use independent of file length.
//
// The failure stages stay distinguishable in the diagnostics, each message
// naming pathArg exactly as passed:
//   * the stat/access check itself fails  -> "cannot access ...";
//   * it succeeds but the object is not a regular file
//                                                         -> "is not a regular file";
//   * a confirmed regular file cannot be opened          -> "cannot open ...";
//   * reading fails after a successful open, even once
//     some bytes have been delivered                     -> "failed to read ...".
// A short final read (and immediate EOF on an empty file) is normal success,
// never a read error. Returns true only after the whole file was read and
// every consume call returned true. If consume returns false, streaming
// stops and this returns false without printing a read error -- the caller
// is responsible for describing that processing failure, and either way a
// partially read file means the whole operation failed.
template <typename Consume>
bool streamRegularFile(const char* pathArg, Consume&& consume) {
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
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        const int err = errno;
        std::cerr << "sealmark: cannot open '" << pathArg << "': "
                  << (err != 0 ? std::strerror(err) : "open failed") << '\n';
        return false;
    }

    std::vector<char> buffer(kReadChunkSize);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 &&
            !consume(buffer.data(), static_cast<size_t>(got))) {
            return false;  // processing failure; consume already reported it
        }
    }
    if (in.bad()) {
        std::cerr << "sealmark: failed to read '" << pathArg << "'\n";
        return false;
    }
    return true;
}

int keyIdFile(const char* pathArg) {
    // Parsing a PEM public key fundamentally requires all of its bytes;
    // public keys are small, so unlike the digest commands the chunks are
    // accumulated here rather than streamed through a hash.
    std::vector<unsigned char> raw;
    const bool readOk = streamRegularFile(
        pathArg, [&](const char* data, size_t size) {
            raw.insert(raw.end(), reinterpret_cast<const unsigned char*>(data),
                       reinterpret_cast<const unsigned char*>(data) + size);
            return true;
        });
    if (!readOk) {
        return 1;
    }

    std::vector<unsigned char> spkiDer;
    if (!extractSpkiDer(raw, spkiDer)) {
        std::cerr << "sealmark: '" << pathArg
                  << "' does not contain a single valid PEM-encoded "
                     "SubjectPublicKeyInfo public key (PUBLIC KEY)\n";
        return 1;
    }

    unsigned char hash[kSha256Size];
    unsigned int hashLen = 0;
    if (EVP_Digest(spkiDer.data(), spkiDer.size(), hash, &hashLen,
                   EVP_sha256(), nullptr) != 1 ||
        hashLen != kSha256Size) {
        std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg
                  << "'\n";
        return 1;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::cout << kSpkiFingerprintPrefix;
    for (unsigned char byte : hash) {
        std::cout << kHex[byte >> 4] << kHex[byte & 0x0f];
    }
    std::cout << '\n';
    return 0;
}

// Streams the file's complete raw bytes through SHA-256 in the fixed-size
// chunks provided by streamRegularFile, so memory use stays constant
// regardless of file size. On success fills hashOut with exactly
// kSha256Size bytes and returns true; on failure prints a reason (including
// pathArg) to stderr and returns false. File-access/open/read failures are
// reported by streamRegularFile; only hash-computation failures are handled
// here.
bool hashFile(const char* pathArg, unsigned char hashOut[kSha256Size]) {
    // The context is set up lazily inside the first chunk callback, keeping
    // the original stage order: an access or open failure is reported as
    // such before any hash-initialization error could be mentioned.
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    bool initialized = false;

    const bool readOk = streamRegularFile(
        pathArg, [&](const char* data, size_t size) {
            if (!initialized) {
                if (!ctx ||
                    EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
                    std::cerr
                        << "sealmark: SHA-256 initialization failed for '"
                        << pathArg << "'\n";
                    return false;
                }
                initialized = true;
            }
            if (EVP_DigestUpdate(ctx.get(), data, size) != 1) {
                std::cerr << "sealmark: SHA-256 computation failed for '"
                          << pathArg << "'\n";
                return false;
            }
            return true;
        });
    if (!readOk) {
        return false;
    }

    // Empty file: no chunk ever arrived, so the context is initialized here
    // before finalizing -- the standard empty-content hash is still produced.
    if (!initialized &&
        (!ctx ||
         EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)) {
        std::cerr << "sealmark: SHA-256 initialization failed for '" << pathArg
                  << "'\n";
        return false;
    }

    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hashOut, &hashLen) != 1 ||
        hashLen != kSha256Size) {
        std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg
                  << "'\n";
        return false;
    }
    return true;
}

int digestFile(const char* pathArg) {
    unsigned char hash[kSha256Size];
    if (!hashFile(pathArg, hash)) {
        return 1;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::cout << "sha256:";
    for (unsigned char byte : hash) {
        std::cout << kHex[byte >> 4] << kHex[byte & 0x0f];
    }
    std::cout << '\n';
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
    unsigned char hash[kSha256Size];
    if (!hashFile(pathArg, hash)) {
        return 1;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    char actual[kDigestPrefix.size() + kDigestHexLen];
    std::memcpy(actual, kDigestPrefix.data(), kDigestPrefix.size());
    for (size_t i = 0; i < kSha256Size; ++i) {
        actual[kDigestPrefix.size() + 2 * i] = kHex[hash[i] >> 4];
        actual[kDigestPrefix.size() + 2 * i + 1] = kHex[hash[i] & 0x0f];
    }

    if (std::string_view(actual, sizeof(actual)) == expected) {
        std::cout << "match\n";
        return 0;
    }
    std::cout << "mismatch\n";
    return 3;
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
