import os
from typing import List, Optional
from backend.models import KernelModuleRecord

class ModuleProvider:
    def __init__(self, proc_modules_path: str = "/proc/modules", sys_module_path: str = "/sys/module"):
        self.proc_modules_path = proc_modules_path
        self.sys_module_path = sys_module_path
        self.baseline = set()
        self.baseline_established = False

    def get_modules(self) -> List[KernelModuleRecord]:
        modules = []
        if not os.path.exists(self.proc_modules_path):
            return modules

        try:
            with open(self.proc_modules_path, "r") as f:
                for line in f:
                    # Format: ext4 753664 2 - Live 0xffffffffc04c0000
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        name = parts[0]
                        size = int(parts[1])
                        state = parts[4]
                        location = parts[5]
                        
                        sig_status = self._check_signature(name)
                        
                        trusted = True
                        if self.baseline_established and name not in self.baseline:
                            trusted = False
                        
                        modules.append(KernelModuleRecord(
                            name=name,
                            size=size,
                            state=state,
                            location=location,
                            signature_status=sig_status,
                            trusted=trusted
                        ))
        except (PermissionError, FileNotFoundError):
            pass

        # Establish baseline on first run
        if not self.baseline_established and modules:
            self.baseline = {m.name for m in modules}
            self.baseline_established = True

        return modules

    def _check_signature(self, name: str) -> str:
        taint_path = os.path.join(self.sys_module_path, name, "taint")
        if os.path.exists(taint_path):
            try:
                with open(taint_path, "r") as f:
                    taint = f.read().strip()
                    if 'E' in taint:
                        return "Unsigned"
                    elif taint == "":
                        return "Valid"
                    else:
                        return f"Tainted ({taint})"
            except (PermissionError, FileNotFoundError):
                pass
        return "Unknown"
