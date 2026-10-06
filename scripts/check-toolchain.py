#!/usr/bin/env python3
"""Refuse drift between the authoritative mise Rust lock and its rustup mirror."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def check_pins(root: Path) -> str:
    lock = tomllib.loads((root / "mise.lock").read_text())
    entries = lock["tools"]["rust"]
    if len(entries) != 1:
        raise ValueError("mise.lock must contain exactly one Rust toolchain")
    version = entries[0]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError(f"mise.lock Rust version must be exact, got {version!r}")
    channel = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if version != channel:
        raise ValueError(f"Rust toolchain pin drift: mise.lock={version}, rust-toolchain.toml={channel}")
    return version


def selftest() -> None:
    # Mutate copies: prove either pin can drift without changing live selectors.
    originals = {name: (ROOT / name).read_text() for name in ("mise.lock", "rust-toolchain.toml")}
    version = check_pins(ROOT)
    with tempfile.TemporaryDirectory(prefix="patina-toolchain-selftest-") as directory:
        root = Path(directory)
        for name, source in originals.items():
            (root / name).write_text(source)
        assert check_pins(root) == version
        for name, source in originals.items():
            changed = source.replace(f'"{version}"', '"0.0.0"', 1)
            if changed == source:
                raise ValueError(f"selftest failed to mutate {name}")
            (root / name).write_text(changed)
            try:
                check_pins(root)
            except ValueError as error:
                if "pin drift" not in str(error):
                    raise ValueError(f"wrong mutation failure: {error}") from error
            else:
                raise ValueError(f"selftest accepted planted drift in {name}")
            (root / name).write_text(source)
        (root / "mise.lock").unlink()
        try:
            check_pins(root)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("selftest accepted a missing lockfile")
    print("PASS toolchain pin drift selftest (both planted mutations and missing lock)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="prove planted pin drift fails")
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest()
        else:
            version = check_pins(ROOT)
            compiler = subprocess.check_output(["rustc", "-V"], text=True).split()[1]
            if compiler != version:
                raise ValueError(f"active rustc={compiler}, pinned Rust={version}; run mise run setup")
            print(f"PASS Rust toolchain pins and active compiler agree: {version}")
    except (OSError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL toolchain pin check: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
