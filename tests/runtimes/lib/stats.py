"""Per-run numbers for language runtimes from outcome.json and the boundary log.

    python3 stats.py PATINA RUN [RUN...]

Prints one JSON object per run: class, wall_ms, traps, switches, refused, io, rdtsc
emulations, threads and processes created, execs, SIGURG sends (tgkill/tkill with signal 23)
and deliveries, futex traps, traps by class Deny (by name) and Stop.
"""
import collections, json, re, subprocess, sys

patina = sys.argv[1]
line_re = re.compile(r"^seq=\d+ (\w+) slot=\d+ t=\d+ (\S+)(?: \[(\w+)\])? args=\[([^\]]*)\]")
for run in sys.argv[2:]:
    o = json.load(open(run + "/outcome.json"))
    s = {
        "run": run, "class": o["class"], "wall_ms": o.get("wall_ms"), "traps": o.get("traps"),
        "switches": o.get("switches"), "refused": o.get("refused", []), "io": o.get("io", {}),
        "rdtsc": o.get("emulated", {}).get("rdtsc", 0), "faults": o.get("faults_count", 0),
    }
    c = collections.Counter()
    deny = collections.Counter()
    incs = sorted(int(m.group(1)) for m in (re.match(r"inc-(\d+)$", d) for d in __import__("os").listdir(run)) if m)
    for k in incs:
        p = subprocess.Popen([patina, "log", "dump", "%s/inc-%d/boundary.log" % (run, k)], stdout=subprocess.PIPE, text=True)
        for line in p.stdout:
            m = line_re.match(line)
            if not m:
                continue
            kind, name, cls, args = m.groups()
            a = [x.strip() for x in args.split(",")]
            if kind == "sup":
                if name == "Forked":
                    c["threads" if a[3] == "0x0" else "processes"] += 1
                elif name == "VforkStart" and a[1] == "0x0":
                    c["processes"] += 1
                elif name == "Exec":
                    c["execs"] += 1
            elif kind == "trap":
                if name == "futex":
                    c["futex"] += 1
                if name in ("tgkill", "tkill"):
                    sig = a[2] if name == "tgkill" else a[1]
                    if int(sig, 16) == 23:
                        c["sigurg_sent"] += 1
                if cls == "Deny":
                    deny[name] += 1
                if cls == "Stop":
                    c["stop"] += 1
            elif kind == "signal":
                if int(name, 16) == 23:
                    c["sigurg_delivered"] += 1
                c["signals_delivered"] += 1
        p.wait()
    for k in ("threads", "processes", "execs", "futex", "sigurg_sent", "sigurg_delivered", "signals_delivered", "stop"):
        s[k] = c[k]
    s["deny"] = dict(sorted(deny.items()))
    print(json.dumps(s))
