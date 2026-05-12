# FIM Developer Onboarding Guide

Welcome to the File Integrity Monitoring (FIM) project! This guide will help you set up your development environment, understand the repository structure, and build and run the daemon.

## Repository Structure

The codebase is split into userspace (C++) and kernel space (eBPF/C).

```text
fim/
├── docs/               # Documentation and architecture guides
├── include/            # Header files
│   ├── bpf/            # Shared headers between kernel and userspace (e.g., vmlinux.h, helpers.h)
│   └── user/           # C++ header files for the daemon
├── src/
│   ├── bpf/            # eBPF C code (create, delete, modify, rename hooks)
│   └── user/           # C++ source code for the FIM daemon and CLI
├── scripts/            # Helper scripts (e.g., debug.sh)
├── Makefile            # Root Makefile
└── config.txt          # Default testing configuration file
```

## Prerequisites

To build and run this project, you need a modern Linux distribution (preferably Ubuntu 22.04+ or Debian 12+) with a recent kernel (5.8+) that supports BPF ring buffers and fentry/fexit (if used).

Install the following dependencies:
*   `clang` and `llvm` (for compiling eBPF)
*   `libelf-dev`
*   `zlib1g-dev`
*   `libbpf-dev`
*   `bpftool`
*   `make` and a modern `g++`

## Building the Project

The build process is managed by Makefiles. The root Makefile recursively builds both the eBPF programs and the userspace daemon.

To build everything from scratch:
```bash
make clean
make all
```

This process involves:
1.  **eBPF Compilation (`src/bpf`):** `clang` compiles the `.bpf.c` files into object files. `bpftool` is then used to link them and generate the `fentry_bpf.skel.h` skeleton header.
2.  **Userspace Compilation (`src/user`):** The C++ code is compiled and linked against `libbpf` and the generated skeleton.

The resulting binary will be named `fim` (usually found in `src/user/` or moved to the root, depending on your build setup).

## Running and Managing the Daemon

The `fim` executable acts as both the CLI manager and the daemon itself. By default, it expects a configuration file at `/etc/fim/config.txt`.

### 1. Prepare the Configuration
Create the config file and directory if it doesn't exist:
```bash
sudo mkdir -p /etc/fim
sudo cp config.txt /etc/fim/config.txt
```
*(Refer to `docs/configformat.rst` for syntax details.)*

### 2. Validate Configuration
Before starting the daemon, you can check if your config has any syntax errors:
```bash
sudo ./fim validate
```

### 3. Start the Daemon
To start the daemon in the background (requires root privileges to load eBPF programs):
```bash
sudo ./fim run
```

### 4. Check Status
To verify the daemon is running and the PID file is valid:
```bash
sudo ./fim status
```

### 5. View Logs
FIM events are logged to the system's syslog. You can view them using the built-in CLI command:
```bash
sudo ./fim log
```
Alternatively, you can watch the trace pipe for direct kernel `bpf_printk` debugging output:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 6. Stop the Daemon
To gracefully shut down the daemon and unload the eBPF programs:
```bash
sudo ./fim stop
```

## Debugging Tips
- If the daemon fails to start, check `syslog` (`/var/log/syslog` or `journalctl -xe`).
- Use the provided `make debug` command (which wraps `scripts/debug.sh`) for testing environments.
- Ensure your kernel has `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and `CONFIG_DEBUG_INFO_BTF=y` enabled (see `docs/kernelconfig.txt`).
