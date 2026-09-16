# KernelGuard: Cross-View Linux Task Monitoring & Rootkit-Indicator Detection

KernelGuard is an advanced, cross-view Linux security monitoring framework. It bridges the gap between Ring 0 (kernel space) and Ring 3 (userspace) to detect suspicious indicators of compromise, such as hidden processes, metadata tampering, and unsigned kernel modules.

## 🛡️ Architecture & Features

Traditional userspace tools like `ps` and `top` rely on the `/proc` filesystem. A sufficiently privileged kernel-level threat (a rootkit) can hook system calls or manipulate Virtual File System (VFS) operations to hide its presence. 

KernelGuard counters this by utilizing a **Cross-View Comparison Engine**:
1. **Kernel Task Enumerator:** A custom Linux Kernel Module (LKM) safely traverses the internal `task_struct` linked list using `rcu_read_lock()` and exposes a raw, unhooked view of running processes.
2. **Userspace Procfs Scanner:** A separate engine independently parses standard `/proc` directories.
3. **Comparison & Risk Engine:** The backend compares both views in real-time. If a process exists in the kernel but is missing from `/proc`, it is flagged with a high-severity "Hidden Process" alert.

### Key Capabilities
- **Direct Task Enumeration:** Safely queries internal kernel structures without hooking system calls.
- **Process Anomaly Detection:** Detects hidden processes, PID spoofing, and parent-child mismatches.
- **Module Monitoring:** Baselines loaded kernel modules and audits `/sys/module` for taint flags and unsigned injections.
- **Event Tracking:** State-diffing event timeline logging `CREATED`, `EXITED`, and `CREDENTIAL_CHANGED` events.
- **Graphical Dashboard:** A responsive PySide6-based UI to visualize tasks, mismatches, and alerts.
- **Reporting:** Export detailed security audits to JSON, CSV, and HTML.

---

## 🚀 Installation & Setup

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

### Navigating the Interface
- **Dashboard:** High-level statistics, risk score overview, and "Run Demo Anomaly" buttons.
- **Kernel Tasks:** The raw process list read directly from our kernel module.
- **Userspace (/proc):** The standard process list visible to normal OS tools.
- **Comparison:** Real-time cross-referencing between the two views.
- **Alerts:** Risk-scored findings (e.g., KERNEL_ONLY indicating a hidden process).
- **Modules:** Audits all loaded LKMs for active baseline deviations and signature status.
- **Events:** Historical tracking of process state changes.

---

## 🧪 Testing Anomalies Safely

KernelGuard includes a **Demo/Mock Mode** accessible directly from the Dashboard. You can click the "Run Demo Anomaly" buttons to safely inject simulated rootkit indicators (such as an artificial hidden process or an unsigned module) into the data pipeline. This allows you to evaluate the Risk Engine and Alert generation without deploying actual malware on your host.

---

## ⚠️ Safety & Limitations

- **Educational Purpose:** This project is an indicator detector designed for university/academic research. It is not a guaranteed, production-grade rootkit detector.
- **Kernel Compromise:** As with any host-based intrusion detection system, a sufficiently privileged Ring 0 attacker could theoretically manipulate the `task_struct` list itself or subvert the monitoring module. For absolute assurance, out-of-band monitoring (e.g., hypervisor introspection or memory forensics) is required.
- **Race Conditions:** Process creation and termination happen in milliseconds. The Risk Engine uses a consecutive-scan threshold (history tracking) to prevent false positives caused by normal, short-lived processes.
