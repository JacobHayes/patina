#!/usr/bin/python3 -u
# Exec target: a script whose #! line has an interpreter argument.
import os, sys
print("exe=" + os.readlink("/proc/self/exe"))
print("orig_argv=" + " ".join(sys.orig_argv))
for i, a in enumerate(sys.argv):
    print(f"argv[{i}]={a}")
print("env=" + os.environ.get("EXEC_SHOW_ENV", "(unset)"))
fds = ""
for fd in range(64):
    try:
        os.fstat(fd)
        fds += f"{fd},"
    except OSError:
        pass
print("fds=" + fds)
try:
    os.fstat(3000)
    print("hidden=open")
except OSError as e:
    print(f"hidden=-1,{e.strerror}")
