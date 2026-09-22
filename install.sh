#!/bin/bash
set -e

echo "======================================"
echo " KernelGuard Installation Script"
echo "======================================"

echo "[*] Checking internet connectivity..."
if ! ping -c 1 8.8.8.8 &> /dev/null && ! ping -c 1 github.com &> /dev/null; then
    echo "❌ ERROR: No internet connection detected!"
    echo "Please ensure your VM has an active network connection to download dependencies."
    exit 1
fi

echo "[*] Installing system dependencies..."
if [ -f /etc/debian_version ]; then
    sudo apt-get update || { echo "❌ ERROR: Failed to update apt repositories. Check your network/DNS."; exit 1; }
    sudo apt-get install -y python3 python3-venv build-essential linux-headers-$(uname -r) || { echo "❌ ERROR: Failed to install apt packages. You might need to run 'sudo apt-get dist-upgrade' if your kernel headers are outdated."; exit 1; }
elif [ -f /etc/redhat-release ]; then
    sudo dnf install -y python3 make gcc kernel-devel-$(uname -r) || exit 1
elif [ -f /etc/arch-release ]; then
    sudo pacman -S --noconfirm python python-virtualenv make gcc linux-headers || exit 1
else
    echo "⚠️ Unsupported package manager. Please install python3, venv, gcc, make, and linux-headers manually."
fi

echo "[*] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv || { echo "❌ ERROR: Failed to create Python virtual environment."; exit 1; }
fi
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt || { echo "❌ ERROR: Failed to install Python dependencies. Check your network."; exit 1; }

echo "[*] Building kernel module..."
cd kernel
make || { echo "❌ ERROR: Failed to compile kernel module. Ensure linux-headers are correctly installed for your running kernel."; exit 1; }
cd ..

echo "✅ Installation complete! You can now run the app using ./run.sh"
