// A C++ guest on the dynamically linked libstdc++: the library's own
// constructor (the standard streams, the locale) runs from _dl_init before
// the executable's constructors, calling functions the shim interposes
// (pthread_once). A static object's constructor, a string stream and
// iostream output through the shim's stdio then run under the installed
// runtime. Output is inserted and flushed, never `std::endl` or `put`, whose
// `putc` binds to glibc's rather than the shim's stdio (a known limit).
#include <iostream>
#include <sstream>
#include <string>

namespace {
struct Greeter {
    std::string word;
    Greeter() : word("patina") {}
};
Greeter greeter;
}  // namespace

int main() {
    std::ostringstream text;
    text << greeter.word << '-' << 42;
    std::cout << "CXX_IOSTREAM_RESULT word=" << text.str() << "\n" << std::flush;
    std::cerr << "CXX_IOSTREAM_STDERR ok\n";
    return 0;
}
