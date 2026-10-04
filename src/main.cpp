#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include <sys/stat.h>

#include "picosha2.h"

namespace {

void print_usage() {
    std::cerr << "Usage: sealmark --version\n"
                 "       sealmark digest <file>\n";
}

// Computes the SHA-256 digest of the regular file at `path` and prints
// "sha256:<hex>" to stdout. Returns 0 on success, 1 on any failure.
int digest_file(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "sealmark: cannot stat '" << path
                  << "': " << std::strerror(errno) << '\n';
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        std::cerr << "sealmark: '" << path << "' is not a regular file\n";
        return 1;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "sealmark: cannot open '" << path
                  << "': " << std::strerror(errno) << '\n';
        return 1;
    }

    picosha2::hash256_one_by_one hasher;
    char buffer[64 * 1024];
    while (in) {
        in.read(buffer, sizeof(buffer));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            hasher.process(buffer, buffer + got);
        }
    }
    if (in.bad()) {
        std::cerr << "sealmark: failed to read '" << path << "'\n";
        return 1;
    }

    hasher.finish();
    std::cout << "sha256:" << picosha2::get_hash_hex_string(hasher) << '\n';
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "sealmark 0.1.0\n";
        return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "digest" &&
        argv[2][0] != '\0') {
        return digest_file(argv[2]);
    }
    print_usage();
    return 2;
}
