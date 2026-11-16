#!/usr/bin/env python3
# Subprocess from CPython: Popen with pipes, communicate, check_output of a shell
# pipeline, run with a return code, and an environment passed through.
import os, subprocess, sys

p = subprocess.Popen(["/usr/bin/sort", "-r"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate(b"".join(b"line %d\n" % i for i in range(500)))
print("popen sort -r:", p.returncode, len(out), out.splitlines()[:3])
out = subprocess.check_output("seq 1 2000 | sort -rn | head -5 | tr '\\n' ' '", shell=True)
print("pipeline:", out)
r = subprocess.run(["/bin/sh", "-c", "echo $PATINA_SUB; exit 3"], capture_output=True, env={"PATINA_SUB": "env-ok", "PATH": "/usr/bin:/bin"})
print("run:", r.returncode, r.stdout)
r = subprocess.run([sys.executable, "-c", "import os; print(os.getpid(), os.getppid())"], capture_output=True, text=True)
print("python child:", r.returncode, r.stdout.strip(), "parent", os.getpid())
try:
    subprocess.check_call(["/bin/false"])
except subprocess.CalledProcessError as e:
    print("check_call false:", e.returncode)
try:
    subprocess.run(["/no/such/program"])
except FileNotFoundError as e:
    print("missing:", e.errno)
print("ok")
