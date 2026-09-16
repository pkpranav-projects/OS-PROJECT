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
        self.start_scan()
        
    def export_reports(self):
        paths = self.controller.export_reports()
        QMessageBox.information(self, "Export Successful", f"Reports saved to:\n{paths['html']}")
        
    def on_scan_complete(self, stats):
        mode = "LIVE" if self.controller.is_live else "MOCK/DEMO"
        self.lbl_stats.setText(f"""
        <h2>Mode: {mode}</h2>
        <p>Last Scan: {time.ctime(stats['last_scan'])}</p>
        <p>Kernel Tasks: {stats['kernel_count']}</p>
        <p>Proc Tasks: {stats['proc_count']}</p>
        <p>Mismatches: {stats['mismatches']}</p>
        <p>Alerts: {stats['alerts']}</p>
        <p>Modules: {stats['modules']}</p>
        <p>Highest Risk Score: {stats['risk_score']}</p>
        """)
        
        self.refresh_tables()
        
    def refresh_tables(self):
        # Update Kernel table
        k_tasks = self.controller.provider.get_kernel_tasks()
        self.k_table.setRowCount(len(k_tasks))
        for i, t in enumerate(k_tasks):
            self.k_table.setItem(i, 0, QTableWidgetItem(str(t.pid)))
            self.k_table.setItem(i, 1, QTableWidgetItem(str(t.ppid)))
            self.k_table.setItem(i, 2, QTableWidgetItem(t.name))
            self.k_table.setItem(i, 3, QTableWidgetItem(t.state))

        # Update Proc table
        p_tasks = self.controller.provider.get_proc_processes()
        self.p_table.setRowCount(len(p_tasks))
        for i, t in enumerate(p_tasks):
            self.p_table.setItem(i, 0, QTableWidgetItem(str(t.pid)))
            self.p_table.setItem(i, 1, QTableWidgetItem(str(t.ppid)))
            self.p_table.setItem(i, 2, QTableWidgetItem(t.name))
            self.p_table.setItem(i, 3, QTableWidgetItem(t.state))
            
        # Update Comparison
        comps = self.controller.comparisons
        self.c_table.setRowCount(len(comps))
        for i, c in enumerate(comps):
            self.c_table.setItem(i, 0, QTableWidgetItem(str(c.pid)))
            self.c_table.setItem(i, 1, QTableWidgetItem(c.status))
            self.c_table.setItem(i, 2, QTableWidgetItem(", ".join(c.differences)))
            self.c_table.setItem(i, 3, QTableWidgetItem(c.confidence))
            
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
        modules = self.controller.provider.get_modules()
        self.m_table.setRowCount(len(modules))
        for i, m in enumerate(modules):
            self.m_table.setItem(i, 0, QTableWidgetItem(m.name))
            self.m_table.setItem(i, 1, QTableWidgetItem(str(m.size)))
            self.m_table.setItem(i, 2, QTableWidgetItem(m.state))
            self.m_table.setItem(i, 3, QTableWidgetItem(m.signature_status))
            self.m_table.setItem(i, 4, QTableWidgetItem(str(m.trusted)))

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
