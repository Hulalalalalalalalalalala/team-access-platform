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

constexpr std::string_view kDigestPrefix = "sha256:";
constexpr std::size_t kDigestHexLen = 64;

int printUsage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n"
                 "       sealmark verify-digest <file> <expected-digest>\n";
    return 2;
}

// Accepts exactly "sha256:" followed by 64 lowercase hexadecimal characters.
// An omitted prefix, uppercase letters, another algorithm name, surrounding
// whitespace or any trailing content are rejected.
bool isValidDigest(std::string_view digest) {
    if (digest.size() != kDigestPrefix.size() + kDigestHexLen ||
        digest.substr(0, kDigestPrefix.size()) != kDigestPrefix) {
        return false;
    }
    for (char c : digest.substr(kDigestPrefix.size())) {
        const bool isDigit = c >= '0' && c <= '9';
        const bool isLowerHex = c >= 'a' && c <= 'f';
        if (!isDigit && !isLowerHex) {
            return false;
        }
    }
    return true;
}

void encodeHex(const unsigned char* hash, unsigned int len, char* out) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; ++i) {
        out[2 * i] = kHex[hash[i] >> 4];
        out[2 * i + 1] = kHex[hash[i] & 0x0f];
    }
}

// Streams the file's complete raw bytes through SHA-256. On success fills
// hashOut and hashLenOut and returns 0; on failure prints a message that
// contains pathArg to stderr and returns 1. The file is only read, never
// modified, and the fixed-size read buffer keeps memory use constant
// regardless of file size.
int hashFile(const char* pathArg, unsigned char hashOut[EVP_MAX_MD_SIZE],
             unsigned int& hashLenOut) {
    namespace fs = std::filesystem;
    const fs::path path(pathArg);

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        if (ec) {
            std::cerr << "sealmark: cannot access '" << pathArg << "': " << ec.message() << '\n';
        } else {
            std::cerr << "sealmark: '" << pathArg << "' is not a regular file\n";
        }
        return 1;
    }

    errno = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        const int err = errno;
        std::cerr << "sealmark: cannot open '" << pathArg << "': "
                  << (err != 0 ? std::strerror(err) : "open failed") << '\n';
        return 1;
    }

    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                      &EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        std::cerr << "sealmark: SHA-256 initialization failed\n";
        return 1;
    }

    // Stream the file in fixed-size chunks so memory use stays constant
    // regardless of file size.
    std::vector<char> buffer(64 * 1024);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 &&
            EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(got)) != 1) {
            std::cerr << "sealmark: SHA-256 computation failed\n";
            return 1;
        }
    }
    if (in.bad()) {
        std::cerr << "sealmark: failed to read '" << pathArg << "'\n";
        return 1;
    }

    if (EVP_DigestFinal_ex(ctx.get(), hashOut, &hashLenOut) != 1) {
        std::cerr << "sealmark: SHA-256 computation failed\n";
        return 1;
    }
    return 0;
}

int digestFile(const char* pathArg) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    const int result = hashFile(pathArg, hash, hashLen);
    if (result != 0) {
        return result;
    }

    char hex[kDigestHexLen];
    encodeHex(hash, hashLen, hex);
    std::cout << "sha256:";
    std::cout.write(hex, static_cast<std::streamsize>(kDigestHexLen));
    std::cout << '\n';
    return 0;
}

int verifyDigestFile(const char* pathArg, std::string_view expected) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    const int result = hashFile(pathArg, hash, hashLen);
    if (result != 0) {
        return result;
    }

    char actualHex[kDigestHexLen];
    encodeHex(hash, hashLen, actualHex);

    bool match = true;
    for (std::size_t i = 0; i < kDigestHexLen; ++i) {
        if (actualHex[i] != expected[kDigestPrefix.size() + i]) {
            match = false;
        }
    }
    std::cout << (match ? "match" : "mismatch") << '\n';
    return match ? 0 : 3;
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
        const std::string_view expected = argv[3];
        // Validate all arguments before touching the file so that a bad
        // argument is never reported as a content or file error.
        if (argv[2][0] == '\0' || !isValidDigest(expected)) {
            return printUsage();
        }
        return verifyDigestFile(argv[2], expected);
    }
    return printUsage();
}
