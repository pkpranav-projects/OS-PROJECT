#!/bin/bash
echo "Installing KernelGuard dependencies..."

# Detect OS and install packages
if [ -f /etc/debian_version ]; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv build-essential linux-headers-$(uname -r)
elif [ -f /etc/redhat-release ]; then
    sudo dnf install -y python3 make gcc kernel-devel-$(uname -r)
elif [ -f /etc/arch-release ]; then
    sudo pacman -S --noconfirm python python-virtualenv make gcc linux-headers
else
    echo "Please install python3, venv, gcc, make, and linux-headers manually."
fi

echo "Setting up Python virtual environment..."
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

echo "Building kernel module..."
cd kernel
make
cd ..

echo "Installation complete! You can now run the app using ./run.sh"
