#!/usr/bin/env python3
"""Native process oracles and strict, named current-gap classification."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUST = {"spawn-wait", "fanout", "pipeline", "buildlike"}
# The expected first unsupported boundary, not the eventual capability this
# fixture will prove. A newly supported boundary requires deliberate migration.
EXPECTED = {
    "spawn-wait": ("runtime", "posix_spawnattr_init"),
    "fanout": ("runtime", "posix_spawnattr_init"),
    "pipeline": ("runtime", "posix_spawnattr_init"),
    "forkwait-c": ("runtime", "fork"),
    "forkwait-cxx": ("audit", "_ZSt4cout"),
    "buildlike": ("runtime", "posix_spawnattr_init"),
    "sigchld": ("runtime", "fork"),
    "failed-exec-enoent": ("runtime", "execvp"),
    "failed-exec-eacces": ("runtime", "execvp"),
    "failed-exec-e2big": ("runtime", "execvp"),
    "early-death": ("runtime", "fork"),
    "atfork-lock": ("runtime", "fork"),
    "fd-sharing": ("runtime", "fork"),
    "last-writer-eof": ("runtime", "fork"),
    "epipe-sigpipe": ("runtime", "fork"),
    "queued-signals": ("audit", "__libc_current_sigrtmin"),
    "shared-futex": ("runtime", "fork"),
}


def classify(status, envelope, expected):
    """Only a failed, attributed boundary is a pending gap; success is drift."""
    if envelope.get("schema") != "patina.result/v1" or status == 0:
        return "unexpected"
    if envelope.get("exit_code") != status:
        return "unexpected"
    kind, name = expected
    if kind == "audit":
        details = envelope.get("finding_details", [])
        if envelope.get("verb") == "audit" and status == 2 and any(
            finding.get("symbol") == name and finding.get("category") == "unknown-import"
            and not finding.get("disposition")
            for finding in details
        ):
            return "pending-gap"
    elif kind == "runtime":
        # The existing process traps carry their door name in captured stderr,
        # but do not yet carry a dedicated refusal class. Read just the symbol
        # token bounded by ':' and ';', paired with the real abort disposition.
        doors = re.findall(r":\s*([A-Za-z_][A-Za-z_0-9]*)\s*;", envelope.get("stderr", ""))
        if (envelope.get("verb") == "run" and not envelope.get("refusal")
                and envelope.get("guest_exit", {}).get("signal") == 6
                and name in doors):
            return "pending-gap"
    return "unexpected"


def selftest():
    for expected in dict.fromkeys(EXPECTED.values()):
        workload = ":".join(expected)
        kind, name = expected
        env = {"schema": "patina.result/v1", "verb": "run", "exit_code": 134}
        if kind == "runtime":
            env.update(stderr=f"boundary: {name}; diagnostic", guest_exit={"signal": 6})
        else:
            env.update(verb="audit", exit_code=2,
                       finding_details=[{"symbol": name, "category": "unknown-import"}])
        status = env["exit_code"]
        assert classify(status, env, expected) == "pending-gap", workload
        assert classify(0, env, expected) == "unexpected", workload
        wrong = copy.deepcopy(env)
        if kind == "runtime":
            wrong["stderr"] = "boundary: a_different_door; diagnostic"
        else:
            wrong["finding_details"][0]["symbol"] = "a_different_door"
        assert classify(status, wrong, expected) == "unexpected", workload
        assert classify(status, {}, expected) == "unexpected", workload
        wrong = copy.deepcopy(env)
        wrong["exit_code"] = 0
        assert classify(status, wrong, expected) == "unexpected", workload
        if kind == "runtime":
            wrong = copy.deepcopy(env)
            wrong["guest_exit"] = {"signal": 11}
            assert classify(status, wrong, expected) == "unexpected", workload
            wrong["guest_exit"] = {"signal": 6}
            wrong["refusal"] = {"class": "runtime_init_failure"}
            assert classify(status, wrong, expected) == "unexpected", workload
    print("multiproc classifier selftest: PASS")


def descendant_handles(parent):
    """Pin this command's descendants, including guests creating new groups."""
    handles = []
    children = Path(f"/proc/{parent}/task/{parent}/children")
    try:
        pids = children.read_text().split()
    except FileNotFoundError:
        return handles
    for pid in pids:
        try:
            handle = os.pidfd_open(int(pid))
        except ProcessLookupError:
            continue
        handles.append(handle)
        handles.extend(descendant_handles(int(pid)))
    return handles


def session_handles(session):
    """Pin members of our session even after reparenting or setpgid."""
    handles = []
    proc = Path('/proc')
    if not proc.is_dir():
        return handles
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        handle = None
        try:
            # comm may contain spaces and ')'; session is field 6 in proc stat.
            if int((entry / 'stat').read_text().rpartition(')')[2].split()[3]) != session:
                continue
            handle = os.pidfd_open(int(entry.name))
            if int((entry / 'stat').read_text().rpartition(')')[2].split()[3]) == session:
                handles.append(handle)
                handle = None
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
        finally:
            if handle is not None:
                os.close(handle)
    return handles


def invoke(args, *, cwd=ROOT, timeout=120):
    process = subprocess.Popen(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Session membership survives leader exit and child setpgid. Descendant
        # handles additionally cover children that started a new session while
        # the leader is still alive. Every remaining capture/reap wait is bounded.
        handles = session_handles(process.pid) + descendant_handles(process.pid)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for handle in handles:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(handle)
        try:
            stdout, stderr = process.communicate(timeout=1)
        except subprocess.TimeoutExpired as error:
            def partial(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            stdout, stderr = partial(error.output), partial(error.stderr)
            process.stdout.close()
            process.stderr.close()
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass  # report failure even if the kernel cannot reap it yet
        raise RuntimeError(f"command timed out: {args}\n{stdout}\n{stderr}") from None
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def command(args, *, cwd=ROOT, timeout=120):
    result = invoke(args, cwd=cwd, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
    return result


def cargo_bins(args):
    output = command(["cargo", *args, "--message-format", "json"]).stdout
    bins = {}
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("reason") == "compiler-artifact" and message.get("executable"):
            bins[message["target"]["name"]] = message["executable"]
    return bins


def run():
    selftest()
    if (os.uname().sysname, os.uname().machine) != ("Linux", "x86_64"):
        print("multiproc: NOT RUN (current pending-gap baseline requires x86_64 Linux)")
        return
    # Honor the check runner's per-rung Cargo isolation. Locate products from
    # compiler artifact messages, never an assumed target/ directory.
    cli = cargo_bins(["build", "--release", "--locked", "-p", "cargo-patina"])["cargo-patina"]
    native = cargo_bins(["build", "--release", "--locked", "--manifest-path",
                         str(HERE / "Cargo.toml"), "--bins"])
    with tempfile.TemporaryDirectory(prefix="patina-multiproc-") as temp:
        out = Path(temp)
        for name, expected in EXPECTED.items():
            binary = native[name]
            command([binary, "--help"])
            args = ([binary] if name in RUST else []) + [str(out / f"native-{name}")]
            native_result = command([binary, *args], timeout=15)
            print(f"{name}: native PASS", flush=True)
            built = out / name
            command([cli, "patina", "build", str(HERE), "--bin", name,
                     "--release", "--output", str(built)])
            args = ([str(built)] if name in RUST else []) + [str(out / f"patina-{name}")]
            argv = [cli, "patina", "run", str(built), "--format", "json", "--", *args]
            result = invoke(argv, timeout=15)
            try:
                envelope = json.loads(result.stdout)
            except ValueError as error:
                raise RuntimeError(f"{name}: no result envelope\n{result.stdout}\n{result.stderr}") from error
            if expected[0] == "audit":
                if (result.returncode != 2 or envelope.get("refusal", {}).get("class")
                        != "native_prerun_audit"):
                    raise RuntimeError(f"{name}: expected the pre-run audit refusal\n{result.stdout}")
                result = invoke([cli, "patina", "audit", str(built), "--format", "json"], timeout=15)
                envelope = json.loads(result.stdout)
            if classify(result.returncode, envelope, expected) != "pending-gap":
                raise RuntimeError(f"{name}: unexpected Patina outcome\n{result.stdout}\n{result.stderr}")
            print(f"{name}: PENDING GAP {expected[0]}:{expected[1]}", flush=True)
            # Native execution succeeded only through the fixture's own oracle.
            # Guest text is shown for humans, not interpreted by the classifier.
            if native_result.stderr:
                print(native_result.stderr, end="")
    print("MULTIPROC_LEGS_RAN native=pass patina=named-pending-gaps")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="prove every fixture's classifier without building")
    options = parser.parse_args()
    try:
        if options.selftest:
            selftest()
            command([sys.executable, '-B', str(HERE / 'test-run.py')])
        else:
            run()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from error
