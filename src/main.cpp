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

int printUsage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n"
                 "       sealmark verify-digest <file> <expected-digest>\n"
                 "       sealmark key-id <file>\n";
    return 2;
}

// Streams the file's complete raw bytes through SHA-256 using fixed-size
// buffers, so memory use stays constant regardless of file size. On success
// fills hashOut with exactly kSha256Size bytes and returns true; on failure
// prints a reason (including pathArg) to stderr and returns false.
bool hashFile(const char* pathArg, unsigned char hashOut[kSha256Size]) {
    namespace fs = std::filesystem;
    const fs::path path(pathArg);

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        if (ec) {
            std::cerr << "sealmark: cannot access '" << pathArg << "': " << ec.message() << '\n';
        } else {
            std::cerr << "sealmark: '" << pathArg << "' is not a regular file\n";
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

    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                      &EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        std::cerr << "sealmark: SHA-256 initialization failed for '" << pathArg << "'\n";
        return false;
    }

    // Stream the file in fixed-size chunks so memory use stays constant
    // regardless of file size.
    std::vector<char> buffer(64 * 1024);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 &&
            EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(got)) != 1) {
            std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg << "'\n";
            return false;
        }
    }
    if (in.bad()) {
        std::cerr << "sealmark: failed to read '" << pathArg << "'\n";
        return false;
    }

    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hashOut, &hashLen) != 1 ||
        hashLen != kSha256Size) {
        std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg << "'\n";
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

// Reads the complete contents of a regular file into out. On failure prints
// a reason (including pathArg) to stderr and returns false.
bool readFileBytes(const char* pathArg, std::vector<char>& out) {
    namespace fs = std::filesystem;
    const fs::path path(pathArg);

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        if (ec) {
            std::cerr << "sealmark: cannot access '" << pathArg << "': " << ec.message() << '\n';
        } else {
            std::cerr << "sealmark: '" << pathArg << "' is not a regular file\n";
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

    // Read through istream::read (not istreambuf iterators) so that a
    // mid-read error surfaces as badbit instead of an exception escaping
    // the streambuf.
    std::vector<char> buffer(64 * 1024);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            out.insert(out.end(), buffer.data(), buffer.data() + got);
        }
    }
    if (in.bad()) {
        std::cerr << "sealmark: failed to read '" << pathArg << "'\n";
        return false;
    }
    return true;
}

constexpr std::string_view kPemBeginMarker = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kPemEndMarker = "-----END PUBLIC KEY-----";

bool isAsciiWhitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

// Extracts the base64 body of the single PEM public-key block that must make
// up the entire file: only ASCII whitespace may appear before the begin
// marker or after the end marker, so a second block, private keys,
// certificates, or any other surrounding content are all rejected here.
bool extractPemBody(std::string_view content, std::string_view& bodyOut) {
    size_t pos = 0;
    while (pos < content.size() && isAsciiWhitespace(content[pos])) {
        ++pos;
    }
    if (content.substr(pos, kPemBeginMarker.size()) != kPemBeginMarker) {
        return false;
    }
    pos += kPemBeginMarker.size();
    // The begin marker must end its line (LF, optionally preceded by CR).
    if (pos >= content.size()) {
        return false;
    }
    if (content[pos] == '\r') {
        ++pos;
    }
    if (pos >= content.size() || content[pos] != '\n') {
        return false;
    }
    ++pos;

    const size_t end = content.find(kPemEndMarker, pos);
    if (end == std::string_view::npos) {
        return false;
    }
    bodyOut = content.substr(pos, end - pos);
    pos = end + kPemEndMarker.size();
    while (pos < content.size() && isAsciiWhitespace(content[pos])) {
        ++pos;
    }
    return pos == content.size();
}

int base64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decodes a PEM base64 body. Line wrapping is irrelevant: ASCII whitespace
// anywhere in the body is ignored. Everything else must be strict base64
// with correct '=' padding.
bool decodeBase64Body(std::string_view body, std::vector<unsigned char>& out) {
    std::string clean;
    clean.reserve(body.size());
    for (char c : body) {
        if (!isAsciiWhitespace(c)) {
            clean.push_back(c);
        }
    }
    if (clean.empty() || clean.size() % 4 != 0) {
        return false;
    }
    size_t padding = 0;
    if (clean.back() == '=') {
        padding = (clean[clean.size() - 2] == '=') ? 2 : 1;
    }
    for (size_t i = 0; i + padding < clean.size(); ++i) {
        if (base64Value(clean[i]) < 0) {
            return false;
        }
    }

    out.clear();
    out.reserve(clean.size() / 4 * 3);
    for (size_t i = 0; i < clean.size(); i += 4) {
        const bool lastGroup = (i + 4 == clean.size());
        const int v0 = base64Value(clean[i]);
        const int v1 = base64Value(clean[i + 1]);
        const int v2 = base64Value(clean[i + 2]);
        const int v3 = base64Value(clean[i + 3]);
        unsigned int acc;
        int byteCount = 3;
        if (v2 < 0) {
            // "xx==" is only valid as the final group.
            if (!lastGroup || clean[i + 2] != '=' || clean[i + 3] != '=') {
                return false;
            }
            acc = (static_cast<unsigned int>(v0) << 18) |
                  (static_cast<unsigned int>(v1) << 12);
            byteCount = 1;
        } else if (v3 < 0) {
            if (!lastGroup || clean[i + 3] != '=') {
                return false;
            }
            acc = (static_cast<unsigned int>(v0) << 18) |
                  (static_cast<unsigned int>(v1) << 12) |
                  (static_cast<unsigned int>(v2) << 6);
            byteCount = 2;
        } else {
            acc = (static_cast<unsigned int>(v0) << 18) |
                  (static_cast<unsigned int>(v1) << 12) |
                  (static_cast<unsigned int>(v2) << 6) |
                  static_cast<unsigned int>(v3);
        }
        out.push_back(static_cast<unsigned char>((acc >> 16) & 0xff));
        if (byteCount > 1) {
            out.push_back(static_cast<unsigned char>((acc >> 8) & 0xff));
        }
        if (byteCount > 2) {
            out.push_back(static_cast<unsigned char>(acc & 0xff));
        }
    }
    return true;
}

// Checks that der is exactly one DER-encoded SubjectPublicKeyInfo public
// key (RSA and Ed25519 among the supported algorithms), with no trailing
// bytes. PKCS#1 keys, private keys and certificates do not parse as SPKI.
bool isValidSpkiDer(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (key == nullptr) {
        return false;
    }
    const bool consumedAll = (p == der.data() + der.size());
    EVP_PKEY_free(key);
    return consumedAll;
}

int keyIdFile(const char* pathArg) {
    std::vector<char> content;
    if (!readFileBytes(pathArg, content)) {
        return 1;
    }

    std::string_view body;
    std::vector<unsigned char> der;
    if (!extractPemBody(std::string_view(content.data(), content.size()), body) ||
        !decodeBase64Body(body, der) || !isValidSpkiDer(der)) {
        std::cerr << "sealmark: '" << pathArg
                  << "' does not contain a single valid PEM public key\n";
        return 1;
    }

    unsigned char hash[kSha256Size];
    unsigned int hashLen = 0;
    if (EVP_Digest(der.data(), der.size(), hash, &hashLen, EVP_sha256(), nullptr) != 1 ||
        hashLen != kSha256Size) {
        std::cerr << "sealmark: SHA-256 computation failed for '" << pathArg << "'\n";
        return 1;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::cout << "spki-sha256:";
    for (unsigned char byte : hash) {
        std::cout << kHex[byte >> 4] << kHex[byte & 0x0f];
    }
    std::cout << '\n';
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
    if (argc == 4 && std::string_view(argv[1]) == "verify-digest") {
        // Validate every argument before touching the file so that a bad
        // path and a malformed digest together still report a usage error.
        if (argv[2][0] == '\0' || !isValidExpectedDigest(argv[3])) {
            return printUsage();
        }
        return verifyDigestFile(argv[2], argv[3]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "key-id") {
        if (argv[2][0] == '\0') {
            return printUsage();
        }
        return keyIdFile(argv[2]);
    }
    return printUsage();
}
