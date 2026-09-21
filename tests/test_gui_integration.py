import sys
import os
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer

app = QApplication.instance()
if app is None:
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication(sys.argv)

from gui.main_window import MainWindow

class TestGUIIntegration(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()
        
    def test_gui_initialization_and_scan(self):
        # Force a manual synchronous scan to bypass the thread for testing
        self.window.controller.run_scan()
        stats = self.window.controller.get_stats()
        self.window.on_scan_complete(stats)
        
        # Verify stats are displayed
        lbl_text = self.window.lbl_stats.text()
        self.assertIn("DEMO MODE", lbl_text)
        
        # Verify unified process explorer table populated
        self.assertGreater(self.window.proc_explorer.rowCount(), 0)
        
        # Trigger anomaly synchronously
        self.window.controller.trigger_anomaly("hidden_process")
        
        # Force synchronous update again after anomaly trigger
        self.window.controller.run_scan()
        stats2 = self.window.controller.get_stats()
        print('DB alerts inside test:', self.window.controller.current_alerts)
        self.window.on_scan_complete(stats2)
        
        # Verify alert was generated and added to alerts table
        self.assertGreater(self.window.a_table.rowCount(), 0)
        
        # Export reports and verify
        reports = self.window.controller.export_reports()
        self.assertTrue(os.path.exists(reports['json']))
        self.assertTrue(os.path.exists(reports['html']))

if __name__ == "__main__":
    unittest.main()
