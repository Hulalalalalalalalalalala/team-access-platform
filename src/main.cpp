#include <iostream>
#include <string_view>

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "sealmark 0.1.0\n";
        return 0;
    }
    std::cerr << "Usage: sealmark --version\n";
    return 2;
}
