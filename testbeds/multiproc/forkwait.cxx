#include <cstdlib>
#include <csignal>
#include <iostream>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

// Keep iostream's real DSO initialization and guest frames in this fixture.
extern "C" int multiproc_fixture(const char *) {
    std::cout << "forkwait-cxx: ready" << std::endl;
    for (int test = 0; test < 2; ++test) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) {
            if (test == 0) _exit(37);
            struct rlimit core = {0, 0};
            if (setrlimit(RLIMIT_CORE, &core) != 0) _exit(91);
            std::abort();
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 1;
        if (test == 0 ? !WIFEXITED(status) || WEXITSTATUS(status) != 37
                      : !WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT)
            return 1;
    }
    return 0;
}
