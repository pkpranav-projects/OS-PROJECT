import os
import time
from typing import List, Optional
from backend.models import ProcessRecord

class ProcfsProvider:
    def __init__(self, proc_dir: str = "/proc"):
        self.proc_dir = proc_dir

    def get_proc_processes(self) -> List[ProcessRecord]:
        processes = []
        if not os.path.exists(self.proc_dir):
            return processes

        # Boot time is needed to calculate start_time from jiffies in some cases,
        # but for simplicity we'll try to extract start time if available, or just mock it if missing.
        btime = self._get_btime()

        for pid_str in os.listdir(self.proc_dir):
            if not pid_str.isdigit():
                continue
            
            pid = int(pid_str)
            pid_dir = os.path.join(self.proc_dir, pid_str)
            
            try:
                record = self._parse_process(pid, pid_dir, btime)
                if record:
                    processes.append(record)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                # Process exited or we don't have permission to read it
                continue
            except Exception as e:
                # Log error in real app, ignore here
                pass
                
        return processes

    def _get_btime(self) -> float:
        try:
            with open(os.path.join(self.proc_dir, "stat"), "r") as f:
                for line in f:
                    if line.startswith("btime "):
                        return float(line.split()[1])
        except Exception:
            pass
        return time.time() - 3600 # Fallback 1 hour ago

    def _parse_process(self, pid: int, pid_dir: str, btime: float) -> Optional[ProcessRecord]:
        stat_path = os.path.join(pid_dir, "stat")
        status_path = os.path.join(pid_dir, "status")
        exe_path = os.path.join(pid_dir, "exe")
        ns_path = os.path.join(pid_dir, "ns", "pid")
        
        if not os.path.exists(stat_path) or not os.path.exists(status_path):
            return None
            
        # Parse stat
        with open(stat_path, "r") as f:
            stat_data = f.read()
            
        # Handle process names with spaces (e.g. "1 (my process) S...")
        start_paren = stat_data.find('(')
        end_paren = stat_data.rfind(')')
        
        if start_paren == -1 or end_paren == -1:
            return None
            
        name = stat_data[start_paren + 1:end_paren]
        parts = stat_data[end_paren + 2:].split()
        
        state = parts[0]
        ppid = int(parts[1])
        # In Linux, start time is the 22nd field (index 19 in parts after name)
        # Using a simplified start time logic for this phase
        start_time = btime 
        
        # Parse status for Uid and Threads
        uid = 0
        threads = 1
        with open(status_path, "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
                    
        # Parse exe (requires root for some procs)
        executable = ""
        try:
            executable = os.readlink(exe_path)
        except OSError:
            pass
            
        # Parse namespace
        namespace_id = None
        try:
            ns_link = os.readlink(ns_path)
            # looks like "pid:[4026531836]"
            if "pid:[" in ns_link:
                namespace_id = int(ns_link.split("pid:[")[1].split("]")[0])
        except OSError:
            pass
            
        return ProcessRecord(
            pid=pid,
            ppid=ppid,
            name=name,
            state=state,
            uid=uid,
            executable=executable,
            start_time=start_time,
            thread_count=threads,
            source="proc",
            namespace_id=namespace_id,
            cpu=None
        )
