# LSM BPF Examples

This repository contains four eBPF programs that demonstrate Linux Security Module (LSM) hooks. These programs illustrate how to monitor and log file creation and deletion events at the kernel level, both system-wide and filtered by specific directory tracking.

## Example Guide

### 1. `d_insaniate_lsmhook`
This example uses the `lsm/d_instantiate` hook callback, triggered whenever a file object is instantiated in memory (e.g., when a new file is created).
- **Behavior:** Logs all file creations occurring globally across the entire system.
- **Output:** Outputs messages like `"FILE CREATED <filename>"` to the trace pipe.

### 2. `inode_unlink_lsmhook`
This example employs the `lsm/inode_unlink` hook callback, which fires when a file entry is unlinked or removed from its parent directory.
- **Behavior:** Logs all file deletions happening system-wide.
- **Output:** Outputs messages like `"FILE DELETED <filename>"` to the trace pipe.

### 3. `d_insaniate_with_lookup_table`
A more advanced version of the instantiation logger. Instead of tracking all system-wide creations, it uses a BPF Hash Map (`InodeMap`) to filter events.
- **Behavior:** It checks the inode number of the directory where a file is being created. If the directory's inode is present in the `InodeMap` (watched list), it logs the creation event. Otherwise, it ignores it.
- **Output:** Outputs messages like `"File <filename> created in directory <inode_nr>"` to the trace pipe.
- **Running:** This example likely involves adding an inode to the map using the `./example.sh` script or loading utilities. 

### 4. `inode_unlink_with_lookup_table`
Similar to the previous example but for deletions. It uses the `lsm/inode_unlink` hook combined with a BPF Hash Map.
- **Behavior:** Checks the parent directory's inode against the `InodeMap` when a file deletion occurs. If matched, it logs the event.
- **Output:** Outputs messages like `"File <filename> is being deleted"` to the trace pipe.
- **Running:** Features an `./example.sh` script to help facilitate testing targeted directory monitoring.

---

## Building and Running

First, set up the build environment for the entire suite:

```bash
./build_env_setup.sh
```

Then, navigate into the directory of the specific example you wish to run. 

For basic examples (`d_insaniate_lsmhook`, `inode_unlink_lsmhook`):
```bash
make all
make load
make showlog
```

For advanced examples containing lookup tables (`d_insaniate_with_lookup_table`, `inode_unlink_with_lookup_table`):
These directories feature additional helper Bash scripts (`example.sh`, `printInodeHex.sh`, `getMapid.sh`). You can run them manually using `bpftool` and `make` commands, or observe how `example.sh` populates the BPF lookup maps to trigger the focused logging.

To unload an example program when you are finished:
```bash
make unload
```

---

## Debugging

If the LSM-related programs are not triggering or loading correctly, ensure your kernel boot arguments have BPF and LSM capabilities enabled. You might need to modify your boot arguments (`GRUB_CMDLINE_LINUX` in `/etc/default/grub`) to add:

```
lsm=...,...,bpf
```
After updating, update grub (e.g., `update-grub`) and reboot.

## Notes

- The programs are compiled and loaded using the provided `Makefile` wrapping `bpftool`.
- The helper `bpf_printk()` writes output directly to the system's tracing pipe, which can be viewed at `/sys/kernel/debug/tracing/trace_pipe` (or via the `make showlog` target).
