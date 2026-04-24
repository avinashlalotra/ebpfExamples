

#include "helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_CREATE

SEC("kprobe/security_inode_create")
int BPF_KPROBE(fim_inode_create_kprobe, struct inode *inode,
               struct dentry *dentry) {

  struct inode *parent_inode;
  struct VALUE *value;

  parent_inode = BPF_CORE_READ(dentry, d_parent, d_inode);

  value = is_monitored(parent_inode);
  if (!value)
    return 0;

  emit_event("lsm_inode_create", parent_inode, dentry, CREATE_EVENT);
  return 0;
}

/**
 * vfs_mkdir - create directory
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 * @mode:	mode of the new directory
 *
 * Create a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs @nop_mnt_idmap.
 */
SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(fim_vfs_mkdir_kprobe, struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode) {
  struct VALUE *value;
  struct inode *parent_inode;
  struct inode *child_inode;
  struct KEY key;
  __u32 heap_key = 0;
  union ctx *ctx_shared;
  u64 pid_tgid;

  parent_inode = dir;
  child_inode = BPF_CORE_READ(dentry, d_inode);
  pid_tgid = bpf_get_current_pid_tgid();

  key.inode = BPF_CORE_READ(parent_inode, i_ino);
  key.dev = BPF_CORE_READ(parent_inode, i_sb, s_dev);

  value = bpf_map_lookup_elem(&InodeMap, &key);
  if (!value) {
    bpf_printk("vfs_mkdir_kprobe: parent inode not monitored");
    return 0;
  }

  ctx_shared = bpf_map_lookup_elem(&heap_map, &heap_key);
  if (!ctx_shared) {
    bpf_printk("vfs_mkdir_kprobe: heap map not found");
    return 0;
  }

  __builtin_memset(ctx_shared, 0, sizeof(*ctx_shared));

  ctx_shared->create_ctx.child_inode = BPF_CORE_READ(child_inode, i_ino);
  ctx_shared->create_ctx.child_dev = BPF_CORE_READ(child_inode, i_sb, s_dev);
  ctx_shared->create_ctx.i_mode = BPF_CORE_READ(child_inode, i_mode);
  __builtin_memset(ctx_shared->create_ctx.filepath, 0,
                   sizeof(ctx_shared->create_ctx.filepath));

  construct_path(dentry, ctx_shared->create_ctx.filepath,
                 &ctx_shared->create_ctx.len);
  bpf_map_update_elem(&LruMap, &pid_tgid, ctx_shared, BPF_ANY);

  return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(fexit_vfs_mkdir, int ret) {
  union ctx *ctx_shared;
  u64 pid_tgid;
  struct EVENT *event;

  if (ret != 0) {
    bpf_printk("vfs_mkdir_kretprobe: ret != 0");
    return 0;
  }

  pid_tgid = bpf_get_current_pid_tgid();
  ctx_shared = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!ctx_shared) {
    bpf_printk("vfs_mkdir_kretprobe: heap map not found");
    return 0;
  }

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event) {
    bpf_printk("vfs_mkdir_kretprobe: ringbuf reserve failed");
    return 0;
  }

  event->before_size = 0;
  event->change_type = CREATE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = 0;
  event->file_size = DIR_SIZE;
  event->len = ctx_shared->create_ctx.len;
  getTTY(event);

  __builtin_memcpy(event->filepath, ctx_shared->create_ctx.filepath,
                   sizeof(event->filepath));

  print_event("fexit_vfs_mkdir", event);
  bpf_ringbuf_submit(event, 0);

  update_dir_map(ctx_shared, true);
  return 0;
}

#endif