import time
from typing import List
from backend.models import Alert, ComparisonResult, AlertSeverity, KernelModuleRecord

class RiskEngine:
    def evaluate(self, comparisons: List[ComparisonResult], modules: List[KernelModuleRecord]) -> List[Alert]:
        alerts = []
        for comp in comparisons:
            if comp.status == "MATCH":
                continue
                
            score = 0
            severity = AlertSeverity.INFO
            
            # Simulated rootkits bypass the delay
            is_urgent = comp.consecutive_count >= 3

            if is_urgent:
                if comp.status == "KERNEL_ONLY":
                    # HIDDEN PROCESS (Classic Rootkit Behavior)
                    score = 100
                    severity = AlertSeverity.CRITICAL
                    comp.explanation = "CRITICAL: Process is running in kernel but deliberately hidden from userspace (/proc). This is a primary indicator of a Ring-0 rootkit."
                else:
                    # METADATA SPOOFING (e.g. PPID mismatch)
                    score = 75
                    severity = AlertSeverity.HIGH
                    comp.explanation = "HIGH: Process metadata (like Parent PID) in userspace does not match the true kernel structures. Indicates process hollowing or spoofing."

            if score > 0:
                alerts.append(Alert(
                    timestamp=time.time(),
                    severity=severity,
                    category=comp.status,
                    target=f"PID {comp.pid}",
                    risk_score=score,
                    evidence=", ".join(comp.differences),
                    explanation=comp.explanation,
                    is_simulated=True
                ))
                
        for mod in modules:
            if not mod.trusted or mod.signature_status == "Unsigned":
                score = 85
                severity = AlertSeverity.HIGH
                if mod.name == "diamorphine":
                    score = 100
                    severity = AlertSeverity.CRITICAL
                    
                alerts.append(Alert(
                    timestamp=time.time(),
                    severity=severity,
                    category="SUSPICIOUS_MODULE",
                    target=f"Module {mod.name}",
                    risk_score=score,
                    evidence=f"Trusted: {mod.trusted}, Signature: {mod.signature_status}",
                    explanation="CRITICAL: An unknown or unsigned kernel module was loaded. Rootkits often use LKM (Loadable Kernel Modules) to hook syscalls.",
                    is_simulated=True
                ))
                
        return alerts
