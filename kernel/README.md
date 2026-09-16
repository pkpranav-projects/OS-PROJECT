# KernelGuard Kernel Module

This is the kernel-level component of the Kernel Task Monitoring project (Phase 3). 
It safely enumerates tasks using the `task_struct` linked list and exposes them via `/proc/kernel_tasks`.

## Safety Constraints Implemented
- Uses `rcu_read_lock()` for safe, non-blocking task list traversal.
- Prevents dereferencing dangling credential pointers using `rcu_access_pointer`.
- Never modifies kernel structures.
- Exposes output via standard `seq_file` to prevent buffer overflow issues common with legacy procfs writes.
- Includes `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)` macros to ensure compatibility across recent kernels (where `proc_ops` replaced `file_operations`).

## Build Instructions
Ensure you are in your **Linux Virtual Machine** and have kernel headers installed. For Debian/Ubuntu:
```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

To build:
```bash
make
```

## Loading the Module
Load the module into the kernel:
```bash
sudo insmod kernel_tasks.ko
```

Check the kernel log to ensure it loaded correctly:
```bash
dmesg | tail -n 5
```

## Unloading the Module
```bash
sudo rmmod kernel_tasks
```
