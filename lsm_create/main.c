#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/d_instantiate")
// this function will be called whenever a file is created
int BPF_PROG(test, struct dentry *dentry, struct inode *inode) {

  char filename[256];

  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

  bpf_probe_read_kernel_str(filename, sizeof(filename), name);

  bpf_printk("FILE CREATED %s\n", filename);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
