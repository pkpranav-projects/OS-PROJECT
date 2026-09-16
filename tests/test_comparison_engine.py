import unittest
from backend.comparison_engine import ComparisonEngine
from backend.models import ProcessRecord

class TestComparisonEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ComparisonEngine()

    def test_match(self):
        k = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "kernel")]
        p = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "proc")]
        results = self.engine.compare(k, p)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "MATCH")

    def test_kernel_only(self):
        k = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "kernel")]
        p = []
        results = self.engine.compare(k, p)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "KERNEL_ONLY")

    def test_proc_only(self):
        k = []
        p = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "proc")]
        results = self.engine.compare(k, p)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "PROC_ONLY")

    def test_metadata_mismatch(self):
        k = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "kernel")]
        p = [ProcessRecord(1, 2, "init_fake", "S", 0, "", 0, 1, "proc")]
        results = self.engine.compare(k, p)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "METADATA_MISMATCH")
        self.assertIn("Name", results[0].differences[0])

    def test_confidence_escalation(self):
        k = [ProcessRecord(1, 0, "init", "S", 0, "", 0, 1, "kernel")]
        p = []
        # First scan
        results = self.engine.compare(k, p)
        self.assertEqual(results[0].confidence, "LOW")
        # Second scan
        results = self.engine.compare(k, p)
        self.assertEqual(results[0].confidence, "MEDIUM")
        # Third scan
        results = self.engine.compare(k, p)
        self.assertEqual(results[0].confidence, "HIGH")

if __name__ == "__main__":
    unittest.main()
