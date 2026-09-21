# KernelGuard: Cross-View Linux Task Monitoring & Rootkit Detection

KernelGuard is an advanced, cross-view Linux security monitoring framework. It bridges the gap between Ring 0 (kernel space) and Ring 3 (userspace) to detect suspicious indicators of compromise, such as hidden processes, metadata tampering, and unsigned kernel modules.

## 🚀 Architecture & Core Logic

Traditional userspace tools like `ps` and `top` rely on the `/proc` filesystem. A sufficiently privileged kernel-level threat (a rootkit) can hook system calls or manipulate Virtual File System (VFS) operations to hide its presence. 

KernelGuard counters this by utilizing a **Cross-View Comparison Engine**:
1. **Kernel Task Enumerator:** A custom Linux Kernel Module (LKM) safely traverses the internal `task_struct` linked list using `rcu_read_lock()` and exposes a raw, unhooked view of running processes.
2. **Userspace Procfs Scanner:** A separate engine independently parses standard `/proc` directories.
3. **Aggressive Risk Engine:** The backend compares both views in real-time and explicitly scores them based on established rootkit behavior:
   - **Hidden Processes [Score: 100 / CRITICAL]:** If a process exists in the kernel but is missing from `/proc`, it indicates a Ring-0 rootkit actively hooking `getdents` to hide.
   - **Malicious Modules [Score: 100 / CRITICAL]:** Detects explicitly unsigned modules or known rootkit signatures (e.g., `diamorphine`).
   - **PPID Spoofing [Score: 75 / HIGH]:** If parent-process metadata in userspace is desynced from the true kernel structures, it indicates Process Hollowing or spoofing.

## 🎨 Modern & Unified Interface

The GUI has been completely refactored from the ground up for simplicity and clarity. Instead of forcing users to cross-reference multiple raw tables, KernelGuard intelligently aggregates data into 4 modern views:

1. **Dashboard:** A sleek control panel showing global security scores, tracked processes, active mismatches, and quick-access buttons to run safe simulated rootkit attacks.
2. **Process Explorer:** A massive upgrade over raw tables. This unified view directly merges Kernel and `/proc` visibility into a single pane. A quick glance at the **"Trust Verification"** column immediately reveals if a process is "Trusted", a "Hidden Rootkit", or a "Ghost".
3. **Kernel Modules:** A dedicated audit page that verifies digital signatures and trust boundaries for all loaded modules.
4. **Security Alerts:** A consolidated threat feed containing both Critical Rootkit Indicators (with risk scores and forensic evidence) and general system event logs.

**Dynamic Threat Highlighting:** Any tab containing active rootkits will dynamically glow with a 🔴 indicator, guaranteeing threats are impossible to miss.

---

## 🛠️ Installation & Setup

KernelGuard is designed to be easily deployable across major Linux distributions (Ubuntu/Debian, RHEL/Fedora, and Arch Linux).

### Prerequisites
Ensure you are running on a Linux system (a dedicated Virtual Machine is highly recommended for security testing).

### 1. Clone the Repository
```bash
git clone https://github.com/pkpranav-projects/OS-PROJECT.git
cd OS-PROJECT
```

### 2. Make Scripts Executable
```bash
chmod +x install.sh run.sh
```

### 3. Run the Installer
The `install.sh` script handles everything automatically: it detects your Linux distro, installs required dependencies (`gcc`, `make`, `linux-headers`, `python3-venv`), builds the isolated Python environment, and compiles the C Kernel Module.
```bash
./install.sh
```

---

## 💻 Usage

To launch the KernelGuard dashboard, simply use the runner script. This script automatically loads the kernel module into Ring 0, launches the GUI with elevated privileges (preserving Wayland/X11 display variables), and securely unloads the module when you close the app.

```bash
./run.sh
```

### Testing Anomalies Safely
KernelGuard includes a **Live Demo Mode** accessible directly from the Dashboard. You can click the "Demo" buttons to safely inject simulated rootkit indicators directly into the live data pipeline. This immediately bypasses normal time-delays, triggering instant UI reactions and critical security alerts, allowing you to test the Risk Engine without deploying actual malware.

---

## ⚠️ Safety & Limitations

- **Educational Purpose:** This project is an indicator detector designed for university/academic research. It is not a guaranteed, production-grade rootkit detector.
- **Kernel Compromise:** As with any host-based intrusion detection system, a sufficiently privileged Ring 0 attacker could theoretically manipulate the `task_struct` list itself or subvert the monitoring module. For absolute assurance, out-of-band monitoring (e.g., hypervisor introspection or memory forensics) is required.
