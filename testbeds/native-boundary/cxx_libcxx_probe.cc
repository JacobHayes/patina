// A C++ guest over the platform's shared C++ library: its stream calls bind
// into libc++, whose own code calls the host's libc directly.
#include <iostream>

int main() {
    std::cout << "CXX_LIBCXX_RAN" << std::endl;
    return 0;
}
