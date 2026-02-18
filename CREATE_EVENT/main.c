#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, u64);
} InodeMap SEC(".maps");

SEC("lsm/d_instantiate")
int BPF_PROG(d_instantiate, struct dentry *dentry, struct inode *inode) {

  u64 *val;
  char filename[255];
  // read inode number of parent directory
  u64 inode_nr = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);

  // check if parent is in watching list
  // If not just exit
  val = bpf_map_lookup_elem(&InodeMap, &inode_nr);
  if (!val) {
    return 0;
  }

  // if parent is in watching list, then check if the file is created in that
  // directory if yes then print the file name read file name
  const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
  bpf_probe_read_kernel_str(filename, sizeof(filename), name);
  bpf_printk("File %s created in directory %d", filename, inode_nr);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";