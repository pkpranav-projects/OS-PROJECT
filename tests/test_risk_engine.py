import unittest
from backend.risk_engine import RiskEngine
from backend.models import ComparisonResult, KernelModuleRecord, AlertSeverity

class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_no_alerts_on_match(self):
        comps = [ComparisonResult(1, "MATCH", ["None"], "HIGH", 0, 0, 0, "")]
        alerts = self.engine.evaluate(comps, [])
        self.assertEqual(len(alerts), 0)

    def test_kernel_only_high_risk(self):
        comps = [ComparisonResult(1, "KERNEL_ONLY", ["Missing"], "HIGH", 0, 0, 3, "")]
        alerts = self.engine.evaluate(comps, [])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)
        self.assertEqual(alerts[0].risk_score, 70)

    def test_suspicious_module(self):
        mods = [KernelModuleRecord("diamorphine", 123, "Live", "", "Unsigned", False)]
        alerts = self.engine.evaluate([], mods)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "SUSPICIOUS_MODULE")
        self.assertEqual(alerts[0].risk_score, 50) # 30 for untrusted + 20 for unsigned

if __name__ == "__main__":
    unittest.main()
