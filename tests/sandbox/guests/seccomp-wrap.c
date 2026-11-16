// Not a guest: runs a command (the launcher) under an allow-all seccomp filter, as a container
// runtime's default profile or systemd's SystemCallFilter= would leave it.
#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct sock_filter f[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {1, f};
    if (argc < 2) return 2;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p)) {
        perror("seccomp");
        return 1;
    }
    execvp(argv[1], argv + 1);
    perror("exec");
    return 1;
}
