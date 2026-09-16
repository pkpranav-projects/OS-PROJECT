from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import time
import uuid

class AlertSeverity(Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    state: str
    uid: int
    executable: str
    start_time: float
    thread_count: int
    source: str # "kernel" or "proc"
    namespace_id: Optional[int] = None
    cpu: Optional[int] = None

@dataclass
class ComparisonResult:
    pid: int
    status: str # MATCH, KERNEL_ONLY, PROC_ONLY, METADATA_MISMATCH
    differences: List[str]
    confidence: str
    first_seen: float
    last_seen: float
    consecutive_count: int
    explanation: str

@dataclass
class Alert:
    timestamp: float
    severity: AlertSeverity
    category: str
    target: str # PID or Module
    risk_score: int
    evidence: str
    explanation: str
    resolution_status: str = "Active"
    is_simulated: bool = False
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class KernelModuleRecord:
    name: str
    size: int
    state: str
    location: str
    signature_status: str
    trusted: bool

@dataclass
class EventRecord:
    timestamp: float
    event_type: str
    pid: int
    ppid: int
    name: str
    executable: str
    description: str
