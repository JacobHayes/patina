#!/usr/bin/env python3
"""Validate the lint inventory and prepare ast-grep's native fixture suite.

Rule configuration is data, unlike the Rust/C source these lints inspect.
Exceptions live only in policy.json; the shim rule is a template whose single
exception expression is instantiated here for both tests and the real scan.
"""
import json
import os
import re
import sys
import tomllib
from pathlib import Path


def rule_ids(text):
    ids = []
    for document in re.split(r"^---\s*$", text, flags=re.MULTILINE):
        document = document.strip()
        while document.startswith("#"):
            document = document.partition("\n")[2].lstrip()
        if document.startswith("{"):
            ids.append(json.loads(document)["id"])
        else:
            ids.extend(re.findall(r"^id: ([a-z0-9-]+)$", document, re.MULTILINE))
    return ids


def prepare(destination):
    root = Path(__file__).resolve().parent.parent
    # ast-grep deliberately does not follow symlinks. Refuse source links,
    # including module directories, so safe relative module paths cannot hide
    # reachable Rust outside the scan. Build artifacts are never source inputs.
    for tree in (root / "crates", root / "testbeds"):
        for directory, directories, files in os.walk(tree):
            directory = Path(directory)
            manifest = directory / "Cargo.toml"
            implicit_entries = directory.name in ("examples", "tests", "benches") or directory.as_posix().endswith("/src/bin")
            if "target" in directories and implicit_entries and not manifest.is_file():
                raise ValueError(f"source directory cannot hide in excluded target: {directory / 'target'}")
            directories[:] = [name for name in directories if name != "target"]
            for name in directories + [
                name for name in files if name.endswith((".rs", ".c", ".h"))
            ]:
                path = directory / name
                if path.is_symlink():
                    raise ValueError(f"source symlink escapes structural scan: {path}")
            if manifest.is_file():
                validate_manifest(manifest)
    source = root / "scripts/structure"
    policy = json.loads((source / "policy.json").read_text())
    expected = policy["rule_files"]
    actual = {path.name for path in source.rglob("*.yml")}
    if actual != set(expected):
        raise ValueError(f"rule files differ: expected {sorted(expected)}, got {sorted(actual)}")
    rules = destination / "rules"
    tests = destination / "tests"
    rules.mkdir()
    tests.mkdir()
    static_ids = set()
    for name, ids in expected.items():
        text = (source / name).read_text()
        if rule_ids(text) != ids:
            raise ValueError(f"{name}: rule IDs differ from the policy inventory")
        static_ids.update(ids)
        if name == "shim-abi-entry.yml":
            marker = "{{shim_export_exceptions}}"
            if text.count(marker) != 1 or text.count(f"regex: '^({marker})$'") != 1:
                raise ValueError("export exceptions must come only from policy.json")
            exceptions = policy["shim_export_exceptions"]
            if len(exceptions) != len(set(exceptions)) or any(
                not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", name) for name in exceptions
            ):
                raise ValueError("invalid or duplicate export exception")
            text = text.replace(marker, "|".join(exceptions))
        if name == "cli-libc.yml":
            marker = "{{libc_variadic_names}}"
            names = policy["libc_variadics"]
            if text.count(marker) != 4 or len(names) != len(set(names)) or any(
                not re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", value) for value in names
            ):
                raise ValueError("variadic declarations and aliases must use the shared inventory")
            text = text.replace(marker, "|".join(names))
        (rules / name).write_text(text)
    fixtures = root / "scripts/structure-tests"
    actual = {path.stem for path in fixtures.glob("*.yml")}
    if actual != static_ids:
        raise ValueError(f"fixture files differ from rule IDs: {sorted(actual ^ static_ids)}")
    for rule_id in sorted(static_ids):
        fixture = json.loads((fixtures / f"{rule_id}.yml").read_text())
        validate_fixture(rule_id, fixture)
        if rule_id == "shim-abi-entry":
            for name in policy["shim_export_exceptions"]:
                fixture["valid"].append(
                    f'#[unsafe(no_mangle)] pub extern "C" fn {name}() {{ work(); }}'
                )
                fixture["invalid"].append(
                    f'#[unsafe(export_name="other")] pub extern "C" fn {name}() {{ work(); }}'
                )
        (tests / f"{rule_id}.yml").write_text(json.dumps(fixture, indent=2) + "\n")
    return root, rules, tests


def validate_manifest(manifest):
    # Cargo entrypoints are another way to select Rust outside the crate. The
    # manifest is configuration data; module syntax rules cover subsequent edges.
    data = tomllib.loads(manifest.read_text())
    targets = [data.get("lib", {})]
    for kind in ("bin", "test", "example", "bench"):
        targets.extend(data.get(kind, []))
    paths = [target["path"] for target in targets if "path" in target]
    build = data.get("package", {}).get("build")
    if isinstance(build, str):
        paths.append(build)
    for value in paths:
        path = Path(value)
        if path.is_absolute() or any(part in ("..", "target") for part in path.parts) or path.suffix != ".rs" or ":" in value or "\\" in value:
            raise ValueError(f"Cargo source must stay in its linted crate: {manifest}: {value}")


def validate_fixture(rule_id, fixture):
    if fixture.get("id") != rule_id:
        raise ValueError(f"{rule_id}: wrong fixture id")
    for category in ("valid", "invalid"):
        values = fixture.get(category)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            raise ValueError(f"{rule_id}: needs nonempty {category} fixtures")


def main():
    destination = Path(sys.argv[1]).resolve()
    root, rules, tests = prepare(destination)
    generated = destination / "generated.yml"
    ids = rule_ids(generated.read_text())
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("generated C rules are empty or duplicated")
    generated_tests = destination / "generated-tests"
    actual = {path.stem for path in generated_tests.glob("*.yml")}
    if actual != set(ids):
        raise ValueError(f"generated fixture/rule inventory differs: {sorted(actual ^ set(ids))}")
    for rule_id in ids:
        validate_fixture(rule_id, json.loads((generated_tests / f"{rule_id}.yml").read_text()))
    generated.rename(rules / "generated.yml")
    config = {"ruleDirs": [str(rules)], "testConfigs": [
        {"testDir": str(tests)}, {"testDir": str(generated_tests)}
    ]}
    (destination / "sgconfig.yml").write_text(json.dumps(config, indent=2) + "\n")
    print(f"structure: {len(ids) + sum(map(len, json.loads((root / 'scripts/structure/policy.json').read_text())['rule_files'].values()))} rules have passing and failing fixtures")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, IndexError) as error:
        sys.exit(f"check-structure: {error}")
