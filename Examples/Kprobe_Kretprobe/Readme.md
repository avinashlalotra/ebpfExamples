# Kprobe and Kretprobe eBPF Example

This example demonstrates how to use `kprobe` and `kretprobe` within a single eBPF program, using eBPF Maps to pass data between them.

## Overview
It attaches to `do_sys_openat2`, tracking the start timestamp in a map on entry (`kprobe`), and calculating the total execution time on exit (`kretprobe`). It maintains total execution time per PID in another map `exec_duration`.

## Prerequisites
- Linux Kernel 5.8+ (for BTF and CO-RE)
- `bpftool` installed
- `clang` and `llvm`

## Instructions

1. **Build the eBPF program**
    ```bash
    make
    ```
    This generates `vmlinux.h` and compiles `main.c` into `prog.bpf.o`.

2. **Load into the Kernel**
    ```bash
    make load
    ```
    This uses `bpftool` to load and automatically attach the eBPF program, pinning it to `/sys/fs/bpf/my_kprobe_prog`.

3. **Check the Output Log**
    ```bash
    make showlog
    ```
    You will see the per-PID execution time printed via `bpf_printk()`.

4. **Examine the Map Content**
    ```bash
    make showmap
    ```
    Find the ID of the maps `start_time` and `exec_duration` and use:
    ```bash
    sudo bpftool map dump id <ID>
    ```

5. **Clean up**
    ```bash
    make unload
    make clean
    ```
