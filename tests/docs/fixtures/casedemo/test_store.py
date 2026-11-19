"""A store that appends `key=value` lines to a file. Its bug: count() counts the empty piece
after the last newline."""
import os
import tempfile
import unittest


class KV:
    def __init__(self, path):
        self.path = path

    def put(self, key, value):
        with open(self.path, "a") as f:
            f.write(f"{key}={value}\n")

    def get(self, key):
        with open(self.path) as f:
            found = [line.split("=", 1)[1].strip() for line in f if line.startswith(key + "=")]
        return found[-1] if found else None

    def count(self):
        with open(self.path) as f:
            return len(f.read().split("\n"))


class Store(unittest.TestCase):
    def setUp(self):
        self.store = KV(os.path.join(tempfile.mkdtemp(), "store"))

    def test_write(self):
        self.store.put("a", 1)
        self.assertEqual(self.store.get("a"), "1")

    def test_counter(self):
        self.store.put("a", 1)
        self.store.put("b", 2)
        self.assertEqual(self.store.count(), 2)
