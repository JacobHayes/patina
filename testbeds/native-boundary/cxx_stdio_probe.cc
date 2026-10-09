// The C++ standard streams over the shim's stdio: libstdc++'s
// stdio_sync_filebuf writes characters with putc (`std::endl`, `put`),
// strings with fwrite, and asks positions with fseeko64/ftello64 (`tellp`).
// `cin` reads glibc's own `stdin` through getc: argv[1] `cin` exercises it.
#include <iostream>
#include <string>

int main(int argc, char **argv) {
    if (argc > 1 && std::string(argv[1]) == "cin") {
        std::cout << "CXX_STDIO_CIN " << std::cin.get() << std::endl;
        return 0;
    }
    std::cout << "CXX_STDIO_ENDL" << std::endl;
    std::cout.put('P');
    std::cout.put('\n');
    std::cout << "CXX_STDIO_TELLP " << std::cout.tellp() << std::endl;
    std::cerr << "CXX_STDIO_CERR" << std::endl;
    std::clog << "CXX_STDIO_CLOG" << std::endl;
    return 0;
}
