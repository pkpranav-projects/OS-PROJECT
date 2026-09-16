#!/bin/bash
echo "Starting KernelGuard..."

# Load module
echo "Loading kernel module (requires sudo)..."
sudo insmod kernel/kernel_tasks.ko 2>/dev/null || echo "Module already loaded or failed to load. Will attempt to run anyway."

# Run GUI
echo "Launching GUI..."
# We use sudo -E to run as root (for deep /proc visibility) while preserving display variables for the GUI
# Depending on Wayland/X11, you might need to allow root access to display via `xhost +local:` first if it fails.
if [ "$XDG_SESSION_TYPE" = "wayland" ]; then
    echo "Wayland detected. If GUI fails to launch, try running: xhost +local:root"
fi

sudo -E ./venv/bin/python run_gui.py

# Unload module after closing
echo "Unloading kernel module..."
sudo rmmod kernel_tasks 2>/dev/null
echo "KernelGuard closed successfully."
