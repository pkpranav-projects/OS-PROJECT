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
            
            if comp.consecutive_count == 1:
                score = 20
                severity = AlertSeverity.LOW
            elif comp.consecutive_count >= 3:
                score = 50
                severity = AlertSeverity.MEDIUM
                if comp.status == "KERNEL_ONLY":
                    score = 70
                    severity = AlertSeverity.HIGH

            if score > 0:
                alerts.append(Alert(
                    timestamp=time.time(),
                    severity=severity,
                    category=comp.status,
                    target=f"PID {comp.pid}",
                    risk_score=score,
                    evidence=", ".join(comp.differences),
                    explanation=comp.explanation,
                    is_simulated=True # Assuming mock for Phase 1
                ))
                
        for mod in modules:
            if not mod.trusted:
                score = 30
                severity = AlertSeverity.LOW
                if mod.signature_status == "Unsigned":
                    score += 20
                    severity = AlertSeverity.MEDIUM
                    
                alerts.append(Alert(
                    timestamp=time.time(),
                    severity=severity,
                    category="SUSPICIOUS_MODULE",
                    target=f"Module {mod.name}",
                    risk_score=score,
                    evidence=f"Trusted: {mod.trusted}, Signature: {mod.signature_status}",
                    explanation="An unknown or unsigned kernel module was detected.",
                    is_simulated=True
                ))
                
        return alerts
