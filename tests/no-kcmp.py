"""Run a command where `kcmp` fails with EPERM, as on a kernel without it or in a container
whose seccomp profile refuses it.

For scripts that check Patina fails closed when the host cannot compare open files: a seccomp
filter (inherited by every process the command starts, Patina's sandbox included) answers
`kcmp` with EPERM and lets every other call through.
Usage: python3 -I tests/no-kcmp.py CMD [ARGS...]
"""

import ctypes
import os
import platform
import struct
import sys

KCMP = {"x86_64": 312, "aarch64": 272}[platform.machine()]
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}[platform.machine()]
RET_ALLOW, RET_ERRNO, RET_KILL = 0x7FFF0000, 0x00050000, 0x80000000
EPERM = 1


def insn(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


LD_W_ABS, JEQ_K, RET_K = 0x20, 0x15, 0x06
prog = b"".join(
    [
        insn(LD_W_ABS, 0, 0, 4),  # seccomp_data.arch
        insn(JEQ_K, 1, 0, AUDIT_ARCH),
        insn(RET_K, 0, 0, RET_KILL),
        insn(LD_W_ABS, 0, 0, 0),  # seccomp_data.nr
        insn(JEQ_K, 0, 1, KCMP),
        insn(RET_K, 0, 0, RET_ERRNO | EPERM),
        insn(RET_K, 0, 0, RET_ALLOW),
    ]
)
buf = ctypes.create_string_buffer(prog)


class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


fp = Fprog(len(prog) // 8, ctypes.addressof(buf))
libc = ctypes.CDLL(None, use_errno=True)
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) or libc.prctl(
    PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fp), 0, 0
):
    sys.exit(f"no-kcmp: seccomp: {os.strerror(ctypes.get_errno())}")
os.execvp(sys.argv[1], sys.argv[1:])
