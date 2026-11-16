#!/usr/bin/env python3
# Exec target as a #!/usr/bin/env python3 script.
import os, sys
print("exe=" + os.readlink("/proc/self/exe"))
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
