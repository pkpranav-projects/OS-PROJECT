# Kernel Task Monitoring and Rootkit-Indicator Detection

## Overview
This is a defensive monitoring project that detects suspicious inconsistencies across Linux process and module views. It enumerates tasks from the kernel, compares them against `/proc`, and generates risk-scored alerts for indicators of compromise (e.g., hidden processes, suspicious modules).

## Current Phase: Phase 1 (Mock Backend & GUI)
The project is currently operating in **Mock/Demo Mode**. All data is simulated for testing the GUI and logic engines without requiring kernel privileges.

## Features
- **Dashboard**: High-level overview of tasks, mismatches, alerts, and risk scores.
- **Kernel Tasks**: Processes enumerated from the simulated kernel task list.
- **Userspace (/proc)**: Processes enumerated from the simulated procfs.
- **Comparison Engine**: Matches PIDs and metadata, highlighting hidden or mismatched processes.
- **Alerts**: Risk-scored findings with explanations.
- **Modules**: Simulated loaded kernel modules.
- **Reports**: Export capabilities (JSON, HTML, CSV).

## Requirements
- Python 3
- PySide6

## Installation & Running
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Launch the GUI:
   ```bash
   python run_gui.py
   ```

## Testing Anomalies
Use the "Run Demo Anomaly" buttons on the Dashboard to inject simulated indicators, such as a hidden process or an unsigned module. Watch the Alerts table update automatically.

## Limitations
- Currently entirely mock data (Phase 1).
- Not a guaranteed rootkit detector. A compromised kernel can manipulate monitoring evidence.
