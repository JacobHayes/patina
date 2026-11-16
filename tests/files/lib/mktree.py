# Build the input tree for the coreutils and differential tests (deterministic content).
import os, random, sys

out = sys.argv[1]
rng = random.Random(3)
os.makedirs(out)
for d in ["a", "a/b", "a/b/c", "d", "e/f"]:
    os.makedirs(os.path.join(out, d))
for i in range(20):
    d = ["a", "a/b", "a/b/c", "d", "e/f"][i % 5]
    with open(os.path.join(out, d, f"f{i:02}"), "w") as f:
        f.write("".join(f"line {j} of file {i}\n" for j in range(i * 37)))
os.chmod(os.path.join(out, "a/f00"), 0o600)
os.chmod(os.path.join(out, "d/f03"), 0o755)
os.symlink("b/c/f02", os.path.join(out, "a/link"))
words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india"]
with open(os.path.join(out, "big.txt"), "w") as f:
    n = 0
    while n < 5 << 20:
        l = " ".join(rng.choice(words) for _ in range(rng.randint(1, 8))) + f" {rng.randint(0, 10**9)}\n"
        f.write(l)
        n += len(l)
