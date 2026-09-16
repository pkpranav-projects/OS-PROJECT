import sys
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                              QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
                              QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox)
from PySide6.QtCore import QTimer, Qt, QThread, Signal
from backend.main import BackendController

class WorkerThread(QThread):
    scan_complete = Signal(dict)
    
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        
    def run(self):
        self.controller.run_scan()
        stats = self.controller.get_stats()
        self.scan_complete.emit(stats)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KernelGuard - Task Monitoring")
        self.resize(1000, 700)
        self.controller = BackendController()
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        self.setup_ui()
        
        self.worker = WorkerThread(self.controller)
        self.worker.scan_complete.connect(self.on_scan_complete)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.start_scan)
        self.timer.start(5000) # Scan every 5s
        
        # Apply visual styling
        self.apply_stylesheet()
        
        self.start_scan()
        
    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
            QTabWidget::pane {
                border: 1px solid #333333;
                background-color: #252526;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #cccccc;
                padding: 10px;
                border: 1px solid #333;
            }
            QTabBar::tab:selected {
                background: #007acc;
                color: white;
            }
            QTableWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                gridline-color: #333333;
                border: none;
            }
            QHeaderView::section {
                background-color: #252526;
                color: #d4d4d4;
                padding: 4px;
                border: 1px solid #333333;
            }
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QLabel {
                color: #d4d4d4;
            }
        """)

    def setup_ui(self):
        # Dashboard
        self.dash_tab = QWidget()
        dash_layout = QVBoxLayout(self.dash_tab)
        self.lbl_stats = QLabel("Loading stats...")
        self.lbl_stats.setTextFormat(Qt.RichText)
        dash_layout.addWidget(self.lbl_stats)
        
        btn_layout = QHBoxLayout()
        btn_hidden = QPushButton("Run Demo Anomaly: Hidden Process")
        btn_hidden.clicked.connect(lambda: self.trigger("hidden_process"))
        btn_meta = QPushButton("Run Demo Anomaly: Mismatch")
        btn_meta.clicked.connect(lambda: self.trigger("metadata_mismatch"))
        btn_mod = QPushButton("Run Demo Anomaly: Bad Module")
        btn_mod.clicked.connect(lambda: self.trigger("suspicious_module"))
        
        btn_layout.addWidget(btn_hidden)
        btn_layout.addWidget(btn_meta)
        btn_layout.addWidget(btn_mod)
        dash_layout.addLayout(btn_layout)
        
        btn_export = QPushButton("Export Reports")
        btn_export.clicked.connect(self.export_reports)
        dash_layout.addWidget(btn_export)
        
        # Tables
        self.k_table = self.create_table(["PID", "PPID", "Name", "State"])
        self.p_table = self.create_table(["PID", "PPID", "Name", "State"])
        self.c_table = self.create_table(["PID", "Status", "Differences", "Confidence"])
        self.a_table = self.create_table(["Time", "Severity", "Category", "Target", "Score", "Simulated"])
        self.m_table = self.create_table(["Name", "Size", "State", "Signature", "Trusted"])
        self.e_table = self.create_table(["Time", "Event", "PID", "PPID", "Name", "Executable", "Description"])
        
        self.tabs.addTab(self.dash_tab, "Dashboard")
        self.tabs.addTab(self.k_table, "Kernel Tasks")
        self.tabs.addTab(self.p_table, "Userspace (/proc)")
        self.tabs.addTab(self.c_table, "Comparison")
        self.tabs.addTab(self.a_table, "Alerts")
        self.tabs.addTab(self.m_table, "Modules")
        self.tabs.addTab(self.e_table, "Events")

    def create_table(self, headers):
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return t

    def start_scan(self):
        if not self.worker.isRunning():
            self.worker.start()

    def trigger(self, anomaly):
        self.controller.trigger_anomaly(anomaly)
        # Immediately run scan without waiting for timer
        self.start_scan()
        
    def export_reports(self):
        paths = self.controller.export_reports()
        QMessageBox.information(self, "Export Successful", f"Reports saved to:\n{paths['html']}")
        
    def update_dashboard(self, stats):
        mode = "LIVE" if self.controller.is_live else "MOCK/DEMO"
        
        m_color = "orange" if stats['mismatches'] > 0 else "#d4d4d4"
        a_color = "red" if stats['alerts'] > 0 else "#d4d4d4"
        
        r_color = "#d4d4d4"
        if stats['risk_score'] >= 80:
            r_color = "red"
        elif stats['risk_score'] >= 50:
            r_color = "orange"
        elif stats['risk_score'] > 0:
            r_color = "yellow"
            
        self.lbl_stats.setText(f"""
        <h2 style='color: #007acc;'>Mode: {mode}</h2>
        <p style='font-size: 14px;'>Last Scan: {time.ctime(stats['last_scan'])}</p>
        <p style='font-size: 14px;'>Kernel Tasks: {stats['kernel_count']}</p>
        <p style='font-size: 14px;'>Proc Tasks: {stats['proc_count']}</p>
        <p style='color: {m_color}; font-size: 16px; font-weight: bold;'>Mismatches: {stats['mismatches']}</p>
        <p style='color: {a_color}; font-size: 18px; font-weight: bold;'>Alerts: {stats['alerts']}</p>
        <p style='font-size: 14px;'>Modules: {stats['modules']}</p>
        <p style='color: {r_color}; font-size: 16px; font-weight: bold;'>Highest Risk Score: {stats['risk_score']}</p>
        """)
        
        if stats['alerts'] > getattr(self, '_last_alerts_count', 0):
            self.show_alert_popup()
        self._last_alerts_count = stats['alerts']
            
    def show_alert_popup(self):
        from PySide6.QtWidgets import QMessageBox
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Rootkit Indicator Detected!")
        msg.setText("A new security alert has been triggered.\nPlease check the 'Alerts' tab for details.")
        msg.setStyleSheet("background-color: #333333; color: white;")
        msg.show()

    def on_scan_complete(self, stats):
        self.update_dashboard(stats)
        self.refresh_tables()
        
    def refresh_tables(self):
        # Helper for coloring anomalous rows
        def get_item(text, color=None):
            item = QTableWidgetItem(str(text))
            if color:
                from PySide6.QtGui import QColor, QBrush
                item.setBackground(QBrush(QColor(color)))
            return item

        # Determine which PIDs have alerts
        alert_pids = set()
        for a in self.controller.current_alerts:
            if a.target.startswith("PID "):
                try:
                    alert_pids.add(int(a.target.split()[1]))
                except:
                    pass
        
        # Update Kernel table
        k_tasks = getattr(self.controller, 'last_k_tasks', [])
        self.k_table.setRowCount(len(k_tasks))
        for i, t in enumerate(k_tasks):
            color = "#8b0000" if t.pid in alert_pids else None
            self.k_table.setItem(i, 0, get_item(t.pid, color))
            self.k_table.setItem(i, 1, get_item(t.ppid, color))
            self.k_table.setItem(i, 2, get_item(t.name, color))
            self.k_table.setItem(i, 3, get_item(t.state, color))

        # Update Proc table
        p_tasks = getattr(self.controller, 'last_p_tasks_list', [])
        self.p_table.setRowCount(len(p_tasks))
        for i, t in enumerate(p_tasks):
            color = "#b8860b" if t.pid in alert_pids else None
            self.p_table.setItem(i, 0, get_item(t.pid, color))
            self.p_table.setItem(i, 1, get_item(t.ppid, color))
            self.p_table.setItem(i, 2, get_item(t.name, color))
            self.p_table.setItem(i, 3, get_item(t.state, color))
            
        # Update Comparison
        comps = self.controller.comparisons
        self.c_table.setRowCount(len(comps))
        for i, c in enumerate(comps):
            color = "#8b0000" if c.status != "MATCH" else None
            self.c_table.setItem(i, 0, get_item(c.pid, color))
            self.c_table.setItem(i, 1, get_item(c.status, color))
            self.c_table.setItem(i, 2, get_item(", ".join(c.differences), color))
            self.c_table.setItem(i, 3, get_item(c.confidence, color))
            
        # Update Alerts
        alerts = self.controller.current_alerts
        self.a_table.setRowCount(len(alerts))
        for i, a in enumerate(alerts):
            self.a_table.setItem(i, 0, QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(a.timestamp))))
            self.a_table.setItem(i, 1, QTableWidgetItem(a.severity.name))
            self.a_table.setItem(i, 2, QTableWidgetItem(a.category))
            self.a_table.setItem(i, 3, QTableWidgetItem(a.target))
            self.a_table.setItem(i, 4, QTableWidgetItem(str(a.risk_score)))
            self.a_table.setItem(i, 5, QTableWidgetItem(str(a.is_simulated)))
            
        # Update Modules
        modules = getattr(self.controller, 'last_modules', [])
        self.m_table.setRowCount(len(modules))
        for i, m in enumerate(modules):
            color = "#8b0000" if m.signature_status == "Unsigned" or not m.trusted else None
            self.m_table.setItem(i, 0, get_item(m.name, color))
            self.m_table.setItem(i, 1, get_item(m.size, color))
            self.m_table.setItem(i, 2, get_item(m.state, color))
            self.m_table.setItem(i, 3, get_item(m.signature_status, color))
            self.m_table.setItem(i, 4, get_item(m.trusted, color))

        # Update Events
        events = getattr(self.controller, 'events', [])
        # Only show the latest 50 events to avoid UI lag
        events = events[-50:]
        self.e_table.setRowCount(len(events))
        for i, e in enumerate(events):
            self.e_table.setItem(i, 0, QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(e.timestamp))))
            self.e_table.setItem(i, 1, QTableWidgetItem(e.event_type))
            self.e_table.setItem(i, 2, QTableWidgetItem(str(e.pid)))
            self.e_table.setItem(i, 3, QTableWidgetItem(str(e.ppid)))
            self.e_table.setItem(i, 4, QTableWidgetItem(e.name))
            self.e_table.setItem(i, 5, QTableWidgetItem(e.executable))
            self.e_table.setItem(i, 6, QTableWidgetItem(e.description))
