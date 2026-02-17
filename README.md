# ebpfFileCreationLogger

This consists three examples of eBPF programs:
1. lsm_create : logs file creation
2. lsm_delete : logs file deletion
3. syscall : logs system calls





run build_env_setup.sh for setting up the environment


then in for each example run
```bash
    make all
    make load
    make showlog
``

Do not forget to unload : 
```bash
    make unload
```


# Debugging 

if lsm related program are not working 
then modify your boot args and add   " lsm=..,..,bpf "



# Note
This is using `bpftool` to load and attach the ebpf programs.



