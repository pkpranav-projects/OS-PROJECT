import os
import shutil
import unittest
from backend.module_provider import ModuleProvider

class TestModuleProvider(unittest.TestCase):
    def setUp(self):
        self.fixture_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        self.proc_modules = os.path.join(self.fixture_dir, 'proc_modules')
        self.sys_module = os.path.join(self.fixture_dir, 'sys_module')
        
        os.makedirs(self.sys_module, exist_ok=True)
        
        # Write dummy /proc/modules
        with open(self.proc_modules, "w") as f:
            f.write("ext4 753664 2 - Live 0xffffffffc04c0000\n")
            f.write("diamorphine 16384 0 - Live 0xffffffffc0500000\n")
            
        # Write dummy sysfs taint for diamorphine
        dia_sys = os.path.join(self.sys_module, "diamorphine")
        os.makedirs(dia_sys, exist_ok=True)
        with open(os.path.join(dia_sys, "taint"), "w") as f:
            f.write("E\n") # Unsigned

    def tearDown(self):
        if os.path.exists(self.proc_modules):
            os.remove(self.proc_modules)
        if os.path.exists(self.sys_module):
            shutil.rmtree(self.sys_module)

    def test_parse_modules(self):
        provider = ModuleProvider(self.proc_modules, self.sys_module)
        modules = provider.get_modules()
        
        self.assertEqual(len(modules), 2)
        
        ext4 = next(m for m in modules if m.name == "ext4")
        self.assertEqual(ext4.size, 753664)
        self.assertEqual(ext4.signature_status, "Unknown")
        self.assertTrue(ext4.trusted) # First run establishes baseline
        
        dia = next(m for m in modules if m.name == "diamorphine")
        self.assertEqual(dia.signature_status, "Unsigned")
        
        # Add a new module after baseline
        with open(self.proc_modules, "a") as f:
            f.write("new_bad_mod 4096 0 - Live 0xffffffffc0600000\n")
            
        modules_run2 = provider.get_modules()
        self.assertEqual(len(modules_run2), 3)
        bad = next(m for m in modules_run2 if m.name == "new_bad_mod")
        self.assertFalse(bad.trusted) # Untrusted because it wasn't in baseline

if __name__ == "__main__":
    unittest.main()
