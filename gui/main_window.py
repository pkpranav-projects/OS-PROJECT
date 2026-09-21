import sys
import time
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QTableWidget, QTableWidgetItem, QTabWidget, 
    QHeaderView, QPushButton, QMessageBox
)
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor, QBrush

from backend.main import BackendController

class WorkerThread(QThread):
    scan_complete = Signal(dict)

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.running = True

    def run(self):
        while self.running:
            self.controller.run_scan()
            stats = self.controller.get_stats()
            self.scan_complete.emit(stats)
            # Sleep in small increments to allow responsive stopping
            for _ in range(50):
                if not self.running:
                    break
                time.sleep(0.1)

    def stop(self):
        self.running = False
        self.wait()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.controller = BackendController()
        
        self.setWindowTitle("KernelGuard - Advanced Rootkit Detection")
        self.resize(1100, 750)
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.setup_ui()
        
        self.worker = WorkerThread(self.controller)
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.start()
        
    def setup_ui(self):
        self.apply_stylesheet()
        
        # 1. Dashboard Tab
        self.dash_tab = QWidget()
        dash_layout = QVBoxLayout(self.dash_tab)
        
        self.lbl_stats = QLabel("Initializing Security Engines...")
        self.lbl_stats.setAlignment(Qt.AlignCenter)
        dash_layout.addWidget(self.lbl_stats)
        
        dash_layout.addStretch()
        
        btn_layout = QHBoxLayout()
        btn_hidden = QPushButton("Demo: Inject Hidden Process")
        btn_hidden.clicked.connect(lambda: self.trigger("hidden_process"))
        btn_meta = QPushButton("Demo: Spoof Process Metadata")
        btn_meta.clicked.connect(lambda: self.trigger("mismatch"))
        btn_mod = QPushButton("Demo: Load Malicious Module")
        btn_mod.clicked.connect(lambda: self.trigger("bad_module"))
        
        btn_layout.addWidget(btn_hidden)
        btn_layout.addWidget(btn_meta)
        btn_layout.addWidget(btn_mod)
        dash_layout.addLayout(btn_layout)
        
        btn_export = QPushButton("Generate Security Report")
        btn_export.clicked.connect(self.export_reports)
        dash_layout.addWidget(btn_export)
        
        # 2. Process Explorer (Unified Table)
        self.proc_explorer = self.create_table([
            "PID", "Name", "PPID", "Kernel Status", "Userspace (/proc)", "Trust Verification"
        ])
        
        # 3. Kernel Modules
        self.m_table = self.create_table(["Module Name", "Size (bytes)", "State", "Signature", "Trusted"])
        
        # 4. Security Alerts (Combined Alerts and Events)
        self.alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(self.alerts_tab)
        alerts_layout.addWidget(QLabel("<h3>Active Rootkit Indicators & Alerts</h3>"))
        self.a_table = self.create_table(["Time", "Severity", "Target", "Score", "Indicator Evidence"])
        alerts_layout.addWidget(self.a_table)
        
        alerts_layout.addWidget(QLabel("<h3>System Events Log</h3>"))
        self.e_table = self.create_table(["Time", "Event", "PID", "Process Name", "Description"])
        alerts_layout.addWidget(self.e_table)
        
        # Add Tabs
        self.tabs.addTab(self.dash_tab, "Dashboard")
        self.tabs.addTab(self.proc_explorer, "Process Explorer")
        self.tabs.addTab(self.m_table, "Kernel Modules")
        self.tabs.addTab(self.alerts_tab, "Security Alerts")

    def create_table(self, headers):
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return t

    def start_scan(self):
        if not self.worker.isRunning():
            self.worker.start()

    def export_reports(self):
        paths = self.controller.export_reports()
        QMessageBox.information(self, "Export Successful", f"Security Reports saved to:\n{paths['html']}")
        
    def update_dashboard(self, stats):
        mode = "LIVE (Kernel Module Active)" if self.controller.is_live else "DEMO MODE (Simulated Data)"
        
        m_color = "#ff8c00" if stats['mismatches'] > 0 else "#2d2d2d"
        a_color = "#b22222" if stats['alerts'] > 0 else "#2d2d2d"
        
        r_color = "#00ff00"
        if stats['risk_score'] >= 80:
            r_color = "#ff0000"
        elif stats['risk_score'] >= 50:
            r_color = "#ff8c00"
            
        self.lbl_stats.setText(f"""
        <div style='text-align: center;'>
            <h1 style='color: #00aaff; font-size: 28px; margin-bottom: 5px;'>KernelGuard Security Status</h1>
            <h3 style='color: #aaaaaa; margin-top: 0;'>{mode}</h3>
            <hr style='border: 1px solid #444; width: 80%;'>
            <p style='font-size: 16px;'><b>Last Scan:</b> {time.ctime(stats['last_scan'])}</p>
            <p style='font-size: 16px;'><b>Tracked Processes:</b> {max(stats['kernel_count'], stats['proc_count'])} | <b>Kernel Modules:</b> {stats['modules']}</p>
            <br>
            <div style='background-color: {a_color}; padding: 15px; border-radius: 5px; margin: 10px 20%;'>
                <h2 style='margin: 0; color: white;'>Security Alerts: {stats['alerts']}</h2>
            </div>
            <div style='background-color: {m_color}; padding: 15px; border-radius: 5px; margin: 10px 20%;'>
                <h2 style='margin: 0; color: white;'>Kernel/User Mismatches: {stats['mismatches']}</h2>
            </div>
            <br>
            <h2 style='color: {r_color};'>Threat Level Score: {stats['risk_score']} / 100</h2>
        </div>
        """)
        
        if stats['alerts'] > getattr(self, '_last_alerts_count', 0):
            self.show_alert_popup()
        self._last_alerts_count = stats['alerts']
            
    def show_alert_popup(self):
        self._alert_popup = QMessageBox(self)
        self._alert_popup.setIcon(QMessageBox.Critical)
        self._alert_popup.setWindowTitle("CRITICAL: Rootkit Indicator Detected!")
        self._alert_popup.setText("A critical security alert has been triggered.\nKernelGuard has detected suspicious activity bypassing standard OS boundaries.\n\nPlease check the 'Security Alerts' tab.")
        self._alert_popup.setStyleSheet("background-color: #2b0000; color: white; font-weight: bold;")
        self._alert_popup.show()

    def on_scan_complete(self, stats):
        self.update_dashboard(stats)
        self.refresh_tables()
        
    def trigger(self, anomaly):
        self.controller.trigger_anomaly(anomaly)
        self.controller.run_scan()
        stats = self.controller.get_stats()
        self.on_scan_complete(stats)
        
    def refresh_tables(self):
        def get_item(text, color=None):
            item = QTableWidgetItem(str(text))
            if color:
                item.setBackground(QBrush(QColor(color)))
            return item

        # 1. Process Explorer (Unified Table)
        k_tasks = {t.pid: t for t in getattr(self.controller, 'last_k_tasks', [])}
        p_tasks = {t.pid: t for t in getattr(self.controller, 'last_p_tasks_list', [])}
        all_pids = sorted(list(set(k_tasks.keys()).union(set(p_tasks.keys()))))
        
        self.proc_explorer.setRowCount(len(all_pids))
        for i, pid in enumerate(all_pids):
            k = k_tasks.get(pid)
            p = p_tasks.get(pid)
            name = k.name if k else p.name
            ppid = k.ppid if k else p.ppid
            
            k_status = "Found" if k else "Missing"
            p_status = "Found" if p else "Missing"
            
            trust = "Trusted"
            color = None
            
            if k and not p:
                trust = "CRITICAL: Hidden Rootkit"
                color = "#660000"
            elif not k and p:
                trust = "WARNING: Dead/Ghost Process"
                color = "#664400"
            elif k and p and k.ppid != p.ppid:
                trust = "HIGH: PPID Spoofing"
                color = "#660000"

            self.proc_explorer.setItem(i, 0, get_item(pid, color))
            self.proc_explorer.setItem(i, 1, get_item(name, color))
            self.proc_explorer.setItem(i, 2, get_item(ppid, color))
            self.proc_explorer.setItem(i, 3, get_item(k_status, color))
            self.proc_explorer.setItem(i, 4, get_item(p_status, color))
            self.proc_explorer.setItem(i, 5, get_item(trust, color))
            
        # 2. Kernel Modules
        modules = getattr(self.controller, 'last_modules', [])
        self.m_table.setRowCount(len(modules))
        has_bad_modules = False
        for i, m in enumerate(modules):
            is_bad = (m.signature_status == "Unsigned" or not m.trusted)
            color = "#660000" if is_bad else None
            if is_bad: has_bad_modules = True
            
            self.m_table.setItem(i, 0, get_item(m.name, color))
            self.m_table.setItem(i, 1, get_item(m.size, color))
            self.m_table.setItem(i, 2, get_item(m.state, color))
            self.m_table.setItem(i, 3, get_item(m.signature_status, color))
            self.m_table.setItem(i, 4, get_item("Trusted" if m.trusted else "Untrusted", color))

        # 3. Security Alerts
        alerts = self.controller.current_alerts
        self.a_table.setRowCount(len(alerts))
        for i, a in enumerate(alerts):
            self.a_table.setItem(i, 0, QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(a.timestamp))))
            self.a_table.setItem(i, 1, QTableWidgetItem(a.severity.name))
            self.a_table.setItem(i, 2, QTableWidgetItem(a.target))
            self.a_table.setItem(i, 3, QTableWidgetItem(str(a.risk_score)))
            self.a_table.setItem(i, 4, QTableWidgetItem(a.explanation))

        # 4. Events Log
        events = getattr(self.controller, 'events', [])[-50:]
        self.e_table.setRowCount(len(events))
        for i, e in enumerate(events):
            self.e_table.setItem(i, 0, QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(e.timestamp))))
            self.e_table.setItem(i, 1, QTableWidgetItem(e.event_type))
            self.e_table.setItem(i, 2, QTableWidgetItem(str(e.pid)))
            self.e_table.setItem(i, 3, QTableWidgetItem(e.name))
            self.e_table.setItem(i, 4, QTableWidgetItem(e.description))
            
        # Tab Glowing Logic
        has_alerts = len(alerts) > 0
        has_mismatches = any(k_tasks.get(pid) and not p_tasks.get(pid) for pid in all_pids) or any(k_tasks.get(pid) and p_tasks.get(pid) and k_tasks[pid].ppid != p_tasks[pid].ppid for pid in all_pids)
        
        self.tabs.setTabText(1, "🔴 Process Explorer" if has_mismatches else "Process Explorer")
        self.tabs.setTabText(2, "🔴 Kernel Modules" if has_bad_modules else "Kernel Modules")
        self.tabs.setTabText(3, "🔴 Security Alerts" if has_alerts else "Security Alerts")

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QLabel {
                color: #d4d4d4;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #cccccc;
                padding: 12px 20px;
                border: 1px solid #333;
                font-weight: bold;
                font-size: 14px;
            }
            QTabBar::tab:selected {
                background: #007acc;
                color: white;
            }
            QTableWidget {
                background-color: #252526;
                color: #d4d4d4;
                gridline-color: #3f3f46;
                border: none;
                font-size: 13px;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #3f3f46;
                font-weight: bold;
            }
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0098ff;
            }
        """)

    def closeEvent(self, event):
        self.worker.stop()
        event.accept()
