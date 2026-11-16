/* sandbox hardening guest: what a process could tell about the state it inherited from whoever started the
 * run (the launcher's descriptors, credentials, session, terminal, persona, limits, signal
 * state, UTS names). One line per value; the run's stdout must not depend on the launcher. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/capability.h>

static void maps_line(void *p) {
    char want[32], l[512];
    snprintf(want, sizeof want, "%lx-", (unsigned long)p);
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { printf("maps err %d\n", errno); return; }
    while (fgets(l, sizeof l, f))
        if (!strncmp(l, want, strlen(want))) { char *s = strchr(l, ' '); printf("maps perms %.4s\n", s ? s + 1 : "?"); }
    fclose(f);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 1 << 16);
    printf("fds");
    for (int fd = 0; fd < 4096; fd++) if (fcntl(fd, F_GETFD) >= 0) printf(" %d", fd);
    printf("\n");
    mode_t um = umask(022); umask(um); printf("umask %o\n", um);
    for (int s = 1; s < 65; s++) {
        struct sigaction sa; memset(&sa, 0, sizeof sa);
        if (sigaction(s, NULL, &sa) == 0 && (sa.sa_handler != SIG_DFL || sa.sa_flags))
            printf("sig %d handler %lx flags %lx\n", s, (unsigned long)sa.sa_handler, (unsigned long)sa.sa_flags);
    }
    sigset_t m; sigprocmask(SIG_BLOCK, NULL, &m); printf("sigmask %lx\n", *(unsigned long *)&m);
    printf("ids pid %d ppid %d uid %d euid %d gid %d egid %d pgrp %d sid %d\n", getpid(), getppid(), getuid(), geteuid(),
           getgid(), getegid(), getpgrp(), getsid(0));
    gid_t gs[64]; int ng = getgroups(64, gs); printf("groups %d", ng);
    for (int i = 0; i < ng; i++) printf(" %d", gs[i]);
    printf("\n");
    struct utsname u; uname(&u);
    printf("uname %s|%s|%s|%s|%s|%s\n", u.sysname, u.nodename, u.release, u.version, u.machine, u.domainname);
    int t = open("/dev/tty", O_RDWR | O_NOCTTY);
    printf("devtty %d errno %d\n", t, t < 0 ? errno : 0);
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2]; memset(d, 0, sizeof d);
    long r = syscall(SYS_capget, &h, d);
    printf("caps r=%ld %x %x %x %x %x %x\n", r, d[0].effective, d[0].permitted, d[0].inheritable, d[1].effective,
           d[1].permitted, d[1].inheritable);
    printf("dumpable %d\n", prctl(PR_GET_DUMPABLE));
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("mmap %p\n", p);
    maps_line(p);
    int local; printf("stack %p brk %p\n", (void *)&local, sbrk(0));
    pid_t c = fork();
    if (c == 0) _exit(7);
    int st = 0; waitpid(c, &st, 0); printf("child status %x\n", st);
    return 0;
}
