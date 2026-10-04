#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace {

constexpr size_t kSha256Size = 32;
constexpr std::string_view kDigestPrefix = "sha256:";
constexpr size_t kDigestHexLen = 2 * kSha256Size;  // 64 lowercase hex chars

int printUsage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n"
                 "       sealmark verify-digest <file> <expected-digest>\n";
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
    return printUsage();
}
