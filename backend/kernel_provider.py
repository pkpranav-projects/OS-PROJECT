import os
from typing import List, Optional
from backend.models import ProcessRecord

class KernelProvider:
    def __init__(self, proc_file: str = "/proc/kernel_tasks"):
        self.proc_file = proc_file

    def get_kernel_tasks(self) -> List[ProcessRecord]:
        tasks = []
        if not os.path.exists(self.proc_file):
            return tasks

        try:
            with open(self.proc_file, "r") as f:
                for line in f:
                    record = self._parse_line(line.strip())
                    if record:
                        tasks.append(record)
        except (PermissionError, FileNotFoundError):
            pass

        return tasks

    def _parse_line(self, line: str) -> Optional[ProcessRecord]:
        # Example format: pid=1 ppid=0 name=systemd state=S uid=0
        if not line:
            return None
            
        try:
            parts = line.split()
            pid = int(parts[0].split("=")[1])
            ppid = int(parts[1].split("=")[1])
            name = parts[2].split("=")[1]
            state = parts[3].split("=")[1]
            uid = int(parts[4].split("=")[1])
            
            return ProcessRecord(
                pid=pid,
                ppid=ppid,
                name=name,
                state=state,
                uid=uid,
                executable="", # Kernel task list doesn't readily expose exe path safely
                start_time=0.0, # Not easily available without complex task_struct digging
                thread_count=1, # Defaulting for now
                source="kernel",
                namespace_id=None,
                cpu=None
            )
        except (IndexError, ValueError):
            return None
