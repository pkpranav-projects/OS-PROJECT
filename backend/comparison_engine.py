from typing import List
import time
from backend.models import ProcessRecord, ComparisonResult

class ComparisonEngine:
    def __init__(self):
        self.history = {} # pid -> count of consecutive mismatches

    def compare(self, kernel_tasks: List[ProcessRecord], proc_processes: List[ProcessRecord]) -> List[ComparisonResult]:
        results = []
        kernel_dict = {p.pid: p for p in kernel_tasks}
        proc_dict = {p.pid: p for p in proc_processes}
        
        all_pids = set(kernel_dict.keys()).union(set(proc_dict.keys()))
        
        for pid in all_pids:
            k_proc = kernel_dict.get(pid)
            p_proc = proc_dict.get(pid)
            
            if k_proc and p_proc:
                # Compare metadata
                differences = []
                if k_proc.name != p_proc.name:
                    differences.append(f"Name: Kernel='{k_proc.name}', Proc='{p_proc.name}'")
                if k_proc.ppid != p_proc.ppid:
                    differences.append(f"PPID: Kernel={k_proc.ppid}, Proc={p_proc.ppid}")
                    
                if differences:
                    status = "METADATA_MISMATCH"
                    explanation = "Process metadata differs between kernel and procfs."
                else:
                    status = "MATCH"
                    explanation = "Process matches in both views."
                    differences = ["None"]
            elif k_proc and not p_proc:
                status = "KERNEL_ONLY"
                differences = ["Missing in /proc"]
                explanation = "Process exists in kernel but is hidden from /proc."
            else:
                status = "PROC_ONLY"
                differences = ["Missing in Kernel"]
                explanation = "Process exists in /proc but not in kernel task list."
                
            # Track history for confidence
            if status != "MATCH":
                self.history[pid] = self.history.get(pid, 0) + 1
            else:
                if pid in self.history:
                    del self.history[pid]
                    
            consecutive = self.history.get(pid, 0)
            confidence = "LOW"
            if consecutive >= 3:
                confidence = "HIGH"
            elif consecutive > 1:
                confidence = "MEDIUM"
                
            if status == "MATCH":
                confidence = "HIGH"
                
            results.append(ComparisonResult(
                pid=pid,
                status=status,
                differences=differences,
                confidence=confidence,
                first_seen=time.time(), # Simplified
                last_seen=time.time(),
                consecutive_count=consecutive,
                explanation=explanation
            ))
            
        return results
