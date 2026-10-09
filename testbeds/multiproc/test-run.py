#!/usr/bin/env python3
"""Behavioral detectors for bounded cleanup of an owned command session."""
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name('run.py')
spec = importlib.util.spec_from_file_location('multiproc', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CleanupTests(unittest.TestCase):
    def test_final_capture_drain_has_a_deadline(self):
        # Class pairing: every capture wait, including cleanup, is bounded.
        with patch.object(runner.subprocess, 'Popen') as popen, \
                patch.object(runner, 'descendant_handles', return_value=[]), \
                patch.object(runner.os, 'killpg'):
            process = popen.return_value
            process.pid = -1  # no real session belongs to this mocked process
            def communicate(*, timeout=None):
                self.assertIsNotNone(timeout)
                raise subprocess.TimeoutExpired('planted capture holder', timeout)
            process.communicate.side_effect = communicate
            with self.assertRaises(RuntimeError):
                runner.invoke(['planted'], timeout=.01)

    @unittest.skipUnless(sys.platform == 'linux', 'owned-session cleanup uses Linux pidfds')
    def test_orphan_in_another_group_is_killed_and_capture_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'orphan.json'
            guest = '''import json,os,signal,sys
r,w=os.pipe()
child=os.fork()
if child==0:
 os.setpgid(0,0)
 os.close(r)
 os.write(w,b"r")
 while True: signal.pause()
os.close(w)
os.read(r,1)
with open(sys.argv[1]+".new","w") as f: json.dump(child,f)
os.replace(sys.argv[1]+".new",sys.argv[1])
os._exit(0)
'''
            harness = '''import importlib.util,sys
spec=importlib.util.spec_from_file_location("mp",sys.argv[1])
mp=importlib.util.module_from_spec(spec);spec.loader.exec_module(mp)
try: mp.invoke([sys.executable,"-c",sys.argv[2],sys.argv[3]],timeout=.3)
except RuntimeError: sys.exit(0)
sys.exit(7)
'''
            process = subprocess.Popen([sys.executable, '-B', '-c', harness, str(SCRIPT),
                                        guest, str(receipt)], start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            handle = None
            try:
                deadline = time.monotonic() + 2
                while not receipt.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                handle = os.pidfd_open(json.loads(receipt.read_text()))
                process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0)
                readable, _, _ = select.select([handle], [], [], 1)
                self.assertTrue(readable)  # the orphan exited, rather than just losing capture
            finally:
                if handle is not None:
                    try: signal.pidfd_send_signal(handle, signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.close(handle)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=2)


if __name__ == '__main__':
    unittest.main()
