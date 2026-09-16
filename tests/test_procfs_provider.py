import os
import shutil
import unittest
from unittest.mock import patch
from backend.procfs_provider import ProcfsProvider

class TestProcfsProvider(unittest.TestCase):
    def setUp(self):
        self.fixture_dir = os.path.join(os.path.dirname(__file__), 'fixtures', 'proc')
        os.makedirs(self.fixture_dir, exist_ok=True)
        
        # Write global stat
        with open(os.path.join(self.fixture_dir, "stat"), "w") as f:
            f.write("btime 1690000000\n")
            
        # Create PID 1 (systemd)
        pid1_dir = os.path.join(self.fixture_dir, "1")
        os.makedirs(pid1_dir, exist_ok=True)
        with open(os.path.join(pid1_dir, "stat"), "w") as f:
            f.write("1 (systemd) S 0 1 1 0 -1 4194560\n")
        with open(os.path.join(pid1_dir, "status"), "w") as f:
            f.write("Name:\tsystemd\nUid:\t0 0 0 0\nThreads:\t1\n")
            
        # Create PID 2 (kthreadd)
        pid2_dir = os.path.join(self.fixture_dir, "2")
        os.makedirs(pid2_dir, exist_ok=True)
        with open(os.path.join(pid2_dir, "stat"), "w") as f:
            f.write("2 (kthreadd) S 0 1 1 0 -1 4194560\n")
        with open(os.path.join(pid2_dir, "status"), "w") as f:
            f.write("Name:\tkthreadd\nUid:\t0 0 0 0\nThreads:\t1\n")

    def tearDown(self):
        if os.path.exists(self.fixture_dir):
            shutil.rmtree(self.fixture_dir)

    @patch("os.readlink")
    def test_parse_procfs(self, mock_readlink):
        # Mock readlink since we can't easily create symlinks on Windows without admin
        def side_effect(path):
            if path.endswith(os.path.join("1", "exe")):
                return "/lib/systemd/systemd"
            if path.endswith(os.path.join("2", "exe")):
                raise OSError("No exe for kernel thread")
            if path.endswith(os.path.join("ns", "pid")):
                return "pid:[4026531836]"
            raise OSError("Invalid")
            
        mock_readlink.side_effect = side_effect
        
        provider = ProcfsProvider(proc_dir=self.fixture_dir)
        processes = provider.get_proc_processes()
        
        self.assertEqual(len(processes), 2)
        
        # Check PID 1
        p1 = next(p for p in processes if p.pid == 1)
        self.assertEqual(p1.name, "systemd")
        self.assertEqual(p1.state, "S")
        self.assertEqual(p1.ppid, 0)
        self.assertEqual(p1.uid, 0)
        self.assertEqual(p1.executable, "/lib/systemd/systemd")
        self.assertEqual(p1.namespace_id, 4026531836)
        
        # Check PID 2
        p2 = next(p for p in processes if p.pid == 2)
        self.assertEqual(p2.name, "kthreadd")
        self.assertEqual(p2.executable, "")

if __name__ == "__main__":
    unittest.main()
