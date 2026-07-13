# Linux Kernel Module - Task Viewer

A simple Linux Kernel Module that traverses the Linux process list using the kernel's `for_each_process()` macro and prints information about all running processes to the kernel log.

---

## Features

- Lists all running processes
- Displays Process ID (PID)
- Displays Process Name
- Uses Linux Kernel APIs
- Loadable Kernel Module (LKM)

---

## Project Structure

```
task_viewer/
├── task_viewer.c
├── Makefile
└── README.md
```

---

## Prerequisites

Install the required development packages.

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

Verify your kernel version.

```bash
uname -r
```

---

## Build the Module

Navigate to the project directory.

```bash
cd ~/kernel_projects/task_viewer
```

Compile the module.

```bash
make
```

Clean build files.

```bash
make clean
```

---

## Load the Module

Insert the kernel module.

```bash
sudo insmod task_viewer.ko
```

Verify that it is loaded.

```bash
lsmod | grep task_viewer
```

---

## View Output

Display the latest kernel log messages.

```bash
dmesg | tail
```

View more output.

```bash
dmesg | tail -50
```

Watch kernel messages live.

```bash
sudo dmesg -w
```

Filter only Task Viewer messages.

```bash
dmesg | grep "Task Viewer"
```

---

## Unload the Module

Remove the module.

```bash
sudo rmmod task_viewer
```

Verify removal.

```bash
lsmod | grep task_viewer
```

---

## Development Workflow

```bash
cd ~/kernel_projects/task_viewer

make clean

make

sudo insmod task_viewer.ko

dmesg | tail -50

sudo rmmod task_viewer
```

---

## Useful Commands

### Display loaded kernel modules

```bash
lsmod
```

### View module information

```bash
modinfo task_viewer.ko
```

### Check kernel version

```bash
uname -a
```

### View kernel logs

```bash
journalctl -k
```

### Follow kernel logs live

```bash
journalctl -kf
```

### Show running processes

```bash
ps -ef
```

### Interactive process viewer

```bash
top
```

or

```bash
htop
```

---

## Common Issues

### Module already loaded

```bash
sudo rmmod task_viewer
sudo insmod task_viewer.ko
```

### Invalid module format

Verify that the running kernel version matches the kernel headers used for compilation.

```bash
uname -r
modinfo task_viewer.ko
```

### Missing kernel headers

```bash
sudo apt install linux-headers-$(uname -r)
```

---

## Cleaning the Project

```bash
make clean
```

---

## Technologies Used

- C
- Linux Kernel Module (LKM)
- GNU Make
- Linux Kernel APIs

---

## Author

**P K PRANAV**

B.Tech Computer Science (Cyber Security)  
Amrita Vishwa Vidyapeetham
