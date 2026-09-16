import time
import random
from backend.models import ProcessRecord, KernelModuleRecord, EventRecord

class MockProvider:
    def __init__(self):
        self.start_time = time.time()
        self.base_pid = 1000
        self.kernel_processes = {}
        self.proc_processes = {}
        self.modules = []
        self.events = []
        self.anomalies = []
        self._initialize_base_data()
        
    def _initialize_base_data(self):
        # Create some standard processes
        procs = [
            (1, 0, "systemd", "/lib/systemd/systemd"),
            (2, 0, "kthreadd", ""),
            (500, 1, "sshd", "/usr/sbin/sshd"),
            (1001, 1, "bash", "/bin/bash"),
            (2005, 1001, "python3", "/usr/bin/python3"),
        ]
        
        for pid, ppid, name, exe in procs:
            rec = ProcessRecord(
                pid=pid, ppid=ppid, name=name, state="S", uid=0,
                executable=exe, start_time=self.start_time - 3600,
                thread_count=1, source="kernel", namespace_id=4026531836, cpu=0
            )
            self.kernel_processes[pid] = rec
            # Create a separate instance for procfs
            proc_rec = ProcessRecord(
                pid=pid, ppid=ppid, name=name, state="S", uid=0,
                executable=exe, start_time=self.start_time - 3600,
                thread_count=1, source="proc", namespace_id=4026531836, cpu=0
            )
            self.proc_processes[pid] = proc_rec
            
        self.modules = [
            KernelModuleRecord("ext4", 753664, "Live", "", "Valid", True),
            KernelModuleRecord("e1000e", 258048, "Live", "", "Valid", True),
        ]
        
    def trigger_anomaly(self, anomaly_type: str):
        if anomaly_type == "hidden_process":
            # Process in kernel, not in proc (classic hidden)
            pid = self.base_pid + random.randint(1, 1000)
            rec = ProcessRecord(
                pid=pid, ppid=1, name="kworker/u4:0", state="R", uid=0,
                executable="", start_time=time.time(),
                thread_count=1, source="kernel", namespace_id=4026531836, cpu=1
            )
            self.kernel_processes[pid] = rec
            self.anomalies.append(f"Hidden process {pid} injected.")
        elif anomaly_type == "metadata_mismatch":
            # Same PID, different PPID or name
            pid = 1001 # bash
            if pid in self.proc_processes:
                self.proc_processes[pid].name = "sh_hidden"
                self.anomalies.append(f"Name mismatch injected on {pid}.")
        elif anomaly_type == "suspicious_module":
            self.modules.append(
                KernelModuleRecord("diamorphine", 16384, "Live", "/tmp/diamorphine.ko", "Unsigned", False)
            )
            self.anomalies.append("Suspicious unsigned module injected.")

    def get_kernel_tasks(self):
        return list(self.kernel_processes.values())
        
    def get_proc_processes(self):
        return list(self.proc_processes.values())
        
    def get_modules(self):
        return self.modules
        
    def get_events(self):
        return self.events
