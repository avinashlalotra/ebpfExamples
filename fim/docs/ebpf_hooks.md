# eBPF Hooks and Maps Deep Dive

This document details the kernel-space mechanics of the File Integrity Monitoring (FIM) tool, specifically focusing on the eBPF hooks used and how data is managed across kernel boundaries before being shipped to userspace.

## Target Hooks

The FIM tool utilizes **kprobes** and **kretprobes** (or fentry/fexit) to intercept execution at specific points within the Linux kernel's Virtual File System (VFS) and Linux Security Modules (LSM) layers.

### 1. LSM Hooks
LSM hooks are strategically placed immediately before critical security and access control decisions.
*   **`security_inode_create`**: Intercepts the creation of new inodes.
*   **Advantage**: Catching events at the LSM layer ensures that the event is logged just before the actual filesystem modification is authorized, providing high-fidelity security auditing.

### 2. VFS Hooks
VFS hooks act as the common abstraction layer for all filesystems (ext4, xfs, btrfs, etc.).
*   **`vfs_mkdir`**: Intercepts directory creation.
*   **`vfs_write` / `vfs_writev`**: Intercepts file write operations.
*   **`do_truncate` / `vfs_fallocate`**: Intercepts file resizing and allocation, which can also modify file content or size.
*   **Advantage**: By hooking at the VFS layer, the FIM tool remains filesystem agnostic.

## Map Interactions and State Management

eBPF programs are heavily restricted in memory and execution time. They cannot perform dynamic memory allocation or long loops. To manage state, we use **BPF Maps**.

### 1. The `InodeMap` (Filtering)
To avoid flooding userspace with every single file operation on the entire system, the kernel program filters events early.
*   **Type**: `BPF_MAP_TYPE_HASH`
*   **Key**: `struct KEY { u64 inode; u32 dev; }`
*   **Value**: Boolean/Flags indicating it should be monitored.
*   **Flow**: When `vfs_mkdir` is called, the kprobe reads the parent directory's inode. It performs a lookup in the `InodeMap`. If the parent is not in the map, the eBPF program exits immediately (returning `0`).

### 2. The `LruMap` (Heap / Context Passing)
Kernel functions often require reading data at the entry point (kprobe) but waiting for the function to succeed before reporting the event (kretprobe). We pass context between these two probes using an LRU map.
*   **Type**: `BPF_MAP_TYPE_LRU_HASH` (or `BPF_MAP_TYPE_HASH`)
*   **Key**: Thread ID (`pid_tgid = bpf_get_current_pid_tgid()`)
*   **Value**: A shared context struct (`union ctx`) containing pre-allocated buffers (like file paths and intermediate state).
*   **Flow**:
    1.  **kprobe**: Allocates/finds a slot in the `LruMap` using the current thread ID. Resolves the absolute path from the `dentry` structure and saves it in the map.
    2.  **Kernel Execution**: The actual `vfs_mkdir` executes.
    3.  **kretprobe**: Wakes up, checks the return value. If successful (`ret == 0`), it retrieves the saved context from the `LruMap` using the thread ID, populates the final event, and submits it.

## Ring Buffer Propagation

Once an event is fully formed in the kretprobe, it must be sent to the C++ userspace daemon.

*   **Type**: `BPF_MAP_TYPE_RINGBUF`
*   **Flow**:
    1.  `bpf_ringbuf_reserve`: Reserves a chunk of memory in the ring buffer for the `EVENT` struct.
    2.  Populates the struct with the filepath, event type (`CREATE_EVENT`, `MODIFY_EVENT`, etc.), UID, and process info.
    3.  `bpf_ringbuf_submit`: Commits the data, waking up the polling userspace consumer (`fim.cpp`) to read and process the log.
