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

int printUsage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n";
    return 2;
}

int digestFile(const char* pathArg) {
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

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hashLen) != 1) {
        std::cerr << "sealmark: SHA-256 computation failed\n";
        return 1;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::cout << "sha256:";
    for (unsigned int i = 0; i < hashLen; ++i) {
        std::cout << kHex[hash[i] >> 4] << kHex[hash[i] & 0x0f];
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
    return printUsage();
}
