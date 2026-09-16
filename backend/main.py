import time
import os
from backend.mock_provider import MockProvider
from backend.procfs_provider import ProcfsProvider
from backend.kernel_provider import KernelProvider
from backend.module_provider import ModuleProvider
from backend.comparison_engine import ComparisonEngine
from backend.risk_engine import RiskEngine
from backend.database import Database
from backend.report_exporter import ReportExporter

class BackendController:
    def __init__(self):
        self.provider = MockProvider()
        self.procfs_provider = ProcfsProvider()
        self.kernel_provider = KernelProvider()
        self.module_provider = ModuleProvider()
        self.comparator = ComparisonEngine()
        self.risk_engine = RiskEngine()
        self.db = Database()
        self.exporter = ReportExporter()
        
        self.last_scan_time = 0
        self.comparisons = []
        self.current_alerts = []
        self.active_anomalies = set()
        
        # Live mode if /proc exists (and we're on linux)
        self.is_live = os.path.exists("/proc") and os.name == 'posix'
        
    def trigger_anomaly(self, anomaly_type):
        self.active_anomalies.add(anomaly_type)
        
    def _apply_anomalies(self, k_tasks, p_tasks, modules):
        from backend.models import ProcessRecord, KernelModuleRecord
        if "hidden_process" in self.active_anomalies:
            # Inject a fake rootkit process into kernel view only
            k_tasks.append(ProcessRecord(9999, 1, "kworker/9:9", "S", 0, "", 0.0, 1, "kernel"))
        if "mismatch" in self.active_anomalies:
            # Inject a mismatching PPID
            if p_tasks:
                p_tasks[0].ppid = 31337
        if "bad_module" in self.active_anomalies:
            # Inject an unsigned module
            modules.append(KernelModuleRecord("diamorphine", 16384, "Live", "0x0", "Unsigned", False))
            
    def run_scan(self):
        self.last_scan_time = time.time()
        
        if self.is_live:
            p_tasks = self.procfs_provider.get_proc_processes()
            
            # If the kernel module is loaded, read from it, otherwise fallback to mock
            k_tasks = self.kernel_provider.get_kernel_tasks()
            if not k_tasks:
                import copy
                k_tasks = copy.deepcopy(p_tasks)
                for k in k_tasks:
                    k.source = "kernel"
                
            modules = self.module_provider.get_modules()
        else:
            k_tasks = self.provider.get_kernel_tasks()
            p_tasks = self.provider.get_proc_processes()
            modules = self.provider.get_modules()
            
        self._apply_anomalies(k_tasks, p_tasks, modules)
        
        # Save to controller state for the GUI to read
        self.last_k_tasks = k_tasks
        self.last_p_tasks_list = p_tasks
        self.last_modules = modules

        
        self.comparisons = self.comparator.compare(k_tasks, p_tasks)
        new_alerts = self.risk_engine.evaluate(self.comparisons, modules)
        
        # Phase 8: Snapshot-based Event Tracking
        from backend.models import EventRecord
        if not hasattr(self, 'events'):
            self.events = []
            
        current_pids = {p.pid: p for p in p_tasks}
        if hasattr(self, 'last_p_tasks'):
            for pid, p in current_pids.items():
                if pid not in self.last_p_tasks:
                    self.events.append(EventRecord(time.time(), "CREATED", pid, p.ppid, p.name, p.executable, "Process started"))
                else:
                    old = self.last_p_tasks[pid]
                    if p.executable != old.executable:
                        self.events.append(EventRecord(time.time(), "EXECUTABLE_CHANGED", pid, p.ppid, p.name, p.executable, "Executable path changed"))
                    if p.uid != old.uid:
                        self.events.append(EventRecord(time.time(), "CREDENTIAL_CHANGED", pid, p.ppid, p.name, p.executable, f"UID {old.uid} -> {p.uid}"))
            for pid, old in self.last_p_tasks.items():
                if pid not in current_pids:
                    self.events.append(EventRecord(time.time(), "EXITED", pid, old.ppid, old.name, old.executable, "Process exited"))
        self.last_p_tasks = current_pids
        
        # Basic deduplication by category and target for the demo
        existing_signatures = {(a.category, a.target) for a in self.current_alerts}
        unique_new = [a for a in new_alerts if (a.category, a.target) not in existing_signatures]
        
        if unique_new:
            self.db.save_alerts(unique_new)
            
        self.current_alerts = self.db.get_alerts()
        
    def trigger_anomaly(self, anomaly_type):
        self.provider.trigger_anomaly(anomaly_type)
        self.run_scan()
        
    def export_reports(self):
        alerts = self.db.get_alerts()
        modules = self.provider.get_modules()
        j = self.exporter.export_json(alerts, modules)
        c = self.exporter.export_csv(alerts)
        h = self.exporter.export_html(alerts, modules, is_mock=not self.is_live)
        return {"json": j, "csv": c, "html": h}

    def get_stats(self):
        return {
            "kernel_count": len(self.provider.get_kernel_tasks()),
            "proc_count": len(self.provider.get_proc_processes()),
            "mismatches": sum(1 for c in self.comparisons if c.status != "MATCH"),
            "alerts": len(self.current_alerts),
            "modules": len(self.provider.get_modules()),
            "risk_score": max([a.risk_score for a in self.current_alerts] + [0]),
            "last_scan": self.last_scan_time
        }
