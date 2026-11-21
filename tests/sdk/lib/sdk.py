"""Helpers of the SDK checks (tests/sdk/*.sh): run a guest natively or under Patina, read its
outcome. Environment from ./check: PATINA, PATINA_GUESTS, RUNS."""
import json
import os
import subprocess
import sys

PATINA = os.environ["PATINA"]
GUESTS = os.environ["PATINA_GUESTS"]
RUNS = os.environ["RUNS"]

# The same script in four languages (tests/guests/sdk).
LANGS = {
    "c": ["/guest/sdk-c"],
    "rust": ["/guest/sdk-rs"],
    "go": ["/guest/sdk-go"],
    "python": ["/usr/bin/python3", "/guest/sdk-py.py"],
}


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def native(cmd, *args):
    """Run a guest on the host: (exit status, stdout, stderr)."""
    host = [c.replace("/guest", GUESTS, 1) if c.startswith("/guest/") else c for c in cmd]
    p = subprocess.run(host + list(args), capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


class Run:
    def __init__(self, out, status=None):
        self.out = out
        # patina's exit status
        self.status = status
        with open(os.path.join(out, "result.json")) as f:
            self.outcome = json.load(f)
        with open(os.path.join(out, "inc-0", "stdout")) as f:
            self.stdout = f.read()
        self.sdk = self.outcome["sdk"]

    @property
    def cls(self):
        return self.outcome["outcome"]

    def site(self, label):
        got = [s for s in self.sdk["sites"] if s["label"] == label]
        if len(got) != 1:
            die(f"{self.out}: {len(got)} sites labelled {label}")
        return got[0]

    def table(self):
        """The site table without source locations (they differ between languages)."""
        return [{k: v for k, v in s.items() if k != "location"} for s in self.sdk["sites"]]


def run(name, seed, cmd, *args, flags=()):
    """`patina run` of `cmd args` into RUNS/name; returns the Run."""
    out = os.path.join(RUNS, name)
    subprocess.run(["rm", "-rf", out], check=True)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    p = subprocess.run(
        [PATINA, "run", "--seed", str(seed), "--out", out, "--mount", GUESTS + ":/guest:copy", *flags, "--", *cmd, *args],
        capture_output=True, text=True, timeout=120)
    if not os.path.exists(os.path.join(out, "result.json")):
        die(f"patina run {' '.join(cmd + list(args))}: no outcome ({p.stderr.strip()[-300:]})")
    r = Run(out, p.returncode)
    # what patina printed
    r.printed = p.stdout
    return r


def report(r):
    """`patina report --format json` of one run directory."""
    p = subprocess.run([PATINA, "report", "--format", "json", r.out], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout)
    except ValueError:
        die(f"patina report {r.out}: exit {p.returncode} ({p.stderr.strip()[-300:]})")


def log_ops(r):
    """The boundary log's records, decoded: one line each."""
    p = subprocess.run([PATINA, "log", "dump", os.path.join(r.out, "inc-0", "boundary.log")],
                       capture_output=True, text=True, check=True)
    return p.stdout.splitlines()
