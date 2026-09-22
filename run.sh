#!/bin/bash
set -e

echo "======================================"
echo " Starting KernelGuard"
echo "======================================"

if [ ! -d "venv" ]; then
    echo "❌ ERROR: Virtual environment 'venv' not found."
    echo "Please run ./install.sh first."
    exit 1
fi

if [ ! -f "kernel/kernel_tasks.ko" ]; then
    echo "⚠️ WARNING: Kernel module 'kernel_tasks.ko' not found."
    echo "The application will run in DEMO mode only."
fi

# Load module
echo "[*] Loading kernel module (requires sudo)..."
sudo insmod kernel/kernel_tasks.ko 2>/dev/null || echo "ℹ️ Module already loaded or failed to load. Will attempt to run anyway."

# Run GUI
echo "[*] Launching GUI..."
# We use sudo -E to run as root (for deep /proc visibility) while preserving display variables for the GUI
if [ "$XDG_SESSION_TYPE" = "wayland" ]; then
    echo "ℹ️ Wayland detected. If GUI fails to launch, try running: xhost +local:root"
fi

sudo -E ./venv/bin/python run_gui.py || { echo "❌ ERROR: GUI crashed or failed to start. Ensure PySide6 is installed."; exit 1; }

# Unload module after closing
echo "[*] Unloading kernel module..."
sudo rmmod kernel_tasks 2>/dev/null || true
echo "✅ KernelGuard closed successfully."
