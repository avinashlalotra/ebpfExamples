#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   /* pid */
    __type(value, u64); /* timestamp */
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   /* pid */
    __type(value, u64); /* total duration */
} exec_duration SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2_enter, int dfd, const char *filename, struct open_how *how) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(do_sys_openat2_exit, long ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp, stat_duration, ts;

    tsp = bpf_map_lookup_elem(&start_time, &pid);
    if (!tsp)
        return 0;

    ts = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_time, &pid);

    u64 *duration;
    duration = bpf_map_lookup_elem(&exec_duration, &pid);
    if (duration) {
        __sync_fetch_and_add(duration, ts);
    } else {
        bpf_map_update_elem(&exec_duration, &pid, &ts, BPF_ANY);
    }
    
    /* Print out the result, can be viewed securely in trace_pipe */
    bpf_printk("PID %d completed do_sys_openat2 in %llu ns, ret = %ld\n", pid, ts, ret);

    return 0;
}
