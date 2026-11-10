"""Freeze Python modules into a blob the Patina Python launcher imports.

Run by `patina build --python` with the interpreter it built, so the
bytecode is that interpreter's. Two shapes:

    freeze.py --stdlib OUT ROOT...
    freeze.py --app PATH OUT [ROOT...]

`--stdlib` freezes every module under the roots except CPython's own test
suite; the code names its file `<frozen NAME>`, as CPython's frozen modules
do. `--app` freezes PATH (a script, run as its module, or a directory, run as
its `__main__`) and what importing finds on a path of PATH's directory (for a
directory application) and each extra ROOT (a site-packages directory, say),
as Python's path finder resolves `sys.path`, and carries their sources so a
traceback shows the lines. An extension module (compiled code) refuses the
build: the interpreter is linked statically and loads none.

The blob: b"PATINAPYFROZEN2\\0", then little-endian u32-prefixed fields: the
main module's name (empty for the stdlib), the modules (name, a package
byte, marshalled code) and the sources (file name, text).
"""

import marshal
import os
import struct
import sys
import tokenize

MAGIC = b"PATINAPYFROZEN2\0"
# CPython's test suite and the frozen-import test modules.
STDLIB_TESTS = {"test", "__phello__", "__hello__"}
EXTENSIONS = (".so", ".pyd", ".dylib")


def fail(message):
    sys.stderr.write(f"error: {message}\n")
    raise SystemExit(2)


class Blob:
    def __init__(self):
        self.modules = {}
        self.sources = []
        self.skipped = 0

    def add(self, name, path, package, filename, keep_source):
        if name in self.modules:
            return
        with open(path, "rb") as handle:
            source = handle.read()
        try:
            code = compile(source, filename, "exec", dont_inherit=True)
        except SyntaxError as error:
            fail(f"{path}: {error}")
        self.modules[name] = (package, marshal.dumps(code))
        if keep_source:
            # As the compiler read it (its encoding declaration honoured),
            # carried as UTF-8 for linecache.
            with tokenize.open(path) as handle:
                self.sources.append((filename, handle.read().encode()))

    def add_namespace(self, name, filename):
        if name not in self.modules:
            code = compile(b"", filename, "exec", dont_inherit=True)
            self.modules[name] = (True, marshal.dumps(code))

    def resolve(self, prefix, path, stdlib):
        """Freeze what importing each name under `path` (a package's
        `__path__`, or the roots) finds, as the path finder finds it: in
        each entry in turn a regular package, else a module, else a
        namespace portion; a namespace package only when no entry has a
        package or module of the name, its portions every such entry."""
        names = set()
        for entry in path:
            for file in os.listdir(entry):
                stem, dot, suffix = file.rpartition(".")
                if os.path.isdir(os.path.join(entry, file)):
                    # A bytecode cache is no package, though it could import
                    # as a namespace.
                    if file == "__pycache__":
                        continue
                    stem = file
                elif not dot or suffix != "py" or stem == "__init__":
                    continue
                if stem.isidentifier() and not (stdlib and not prefix and stem in STDLIB_TESTS):
                    names.add(stem)
        for stem in sorted(names):
            name = prefix + stem
            portions = []
            for entry in path:
                directory = os.path.join(entry, stem)
                init = os.path.join(directory, "__init__.py")
                if os.path.isfile(init):
                    self.add(name, init, True, self.filename(name, entry, init, stdlib), not stdlib)
                    self.resolve(name + ".", [directory], stdlib)
                    break
                module = os.path.join(entry, stem + ".py")
                if os.path.isfile(module):
                    self.add(name, module, False, self.filename(name, entry, module, stdlib), not stdlib)
                    break
                if os.path.isdir(directory):
                    portions.append(directory)
            else:
                if portions and not stdlib:
                    self.add_namespace(name, name.replace(".", os.sep))
                    self.resolve(name + ".", portions, stdlib)

    def filename(self, name, entry, path, stdlib):
        if stdlib:
            return f"<frozen {name}>"
        return os.path.relpath(path, self.roots[entry])

    def survey(self, root):
        """Refuse an extension module anywhere under `root`, and count the
        files beside the modules that are not frozen."""
        for directory, subdirectories, files in os.walk(root):
            subdirectories.sort()
            for file in sorted(files):
                path = os.path.join(directory, file)
                if file.endswith(EXTENSIONS):
                    fail(
                        f"{path} is an extension module: a Patina Python guest links "
                        "CPython statically and loads no compiled modules"
                    )
                if not file.endswith((".py", ".pyc", ".pth")):
                    self.skipped += 1

    def freeze(self, roots, stdlib):
        # Each directory a module can be found in, mapped to the root its
        # file names are relative to.
        self.roots = {}
        for root in roots:
            for directory, subdirectories, _ in os.walk(root):
                self.roots.setdefault(directory, root)
            if not stdlib:
                self.survey(root)
        self.resolve("", list(roots), stdlib)

    def write(self, out, main):
        def field(data):
            return struct.pack("<I", len(data)) + data

        blob = bytearray(MAGIC) + field(main.encode())
        blob += struct.pack("<I", len(self.modules))
        for name, (package, code) in self.modules.items():
            blob += field(name.encode()) + bytes([package]) + field(code)
        blob += struct.pack("<I", len(self.sources))
        for filename, source in self.sources:
            blob += field(filename.encode()) + field(source)
        with open(out, "wb") as handle:
            handle.write(blob)


def main(argv):
    blob = Blob()
    if argv[:1] == ["--stdlib"] and len(argv) >= 3:
        out, roots = argv[1], argv[2:]
        blob.freeze(roots, True)
        blob.write(out, "")
        return
    if argv[:1] == ["--app"] and len(argv) >= 3:
        app, out, roots = argv[1], argv[2], argv[3:]
        if os.path.isdir(app):
            if not os.path.isfile(os.path.join(app, "__main__.py")):
                fail(f"{app} has no __main__.py to run")
            # The directory is the first entry of the path, as `python DIR`
            # makes it.
            roots = [app] + roots
            main_name = "__main__"
        elif app.endswith(".py") and os.path.isfile(app):
            main_name = os.path.basename(app)[:-3]
            blob.add(main_name, app, False, os.path.basename(app), True)
        else:
            fail(f"{app} is neither a .py script nor a directory")
        for root in argv[3:]:
            if not os.path.isdir(root):
                fail(f"--python-path {root} is not a directory")
        blob.freeze(roots, False)
        if blob.skipped:
            sys.stderr.write(
                f"note: {blob.skipped} file(s) beside the application's modules are not "
                "frozen; a Python guest reads no package data\n"
            )
        blob.write(out, main_name)
        return
    fail("usage: freeze.py --stdlib OUT ROOT... | freeze.py --app PATH OUT [ROOT...]")


main(sys.argv[1:])
