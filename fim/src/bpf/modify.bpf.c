// SPDX-License-Identifier: GPL-2.0
//
#include "helpers.h"
#include "maps.h"
#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define MAY_WRITE 0x00000002

/* coverage 90%

write:     kprobe/vfs_write+ kretprobe/vfs_write        -- path verified
           kprobe/vfs_writev + kretprobe/vfs_writev     -- path verified

ebpf:
  before_size
  bytes_written
  tty details
*/

#ifdef CONFIG_MODIFY

/**
 * vfs_write kprobe
 *
 */
SEC("kprobe/vfs_write")
int BPF_KPROBE(fim_vfs_write, struct file *file, const char *buf, size_t count,
               loff_t *pos) {
  struct KEY inode_key = {};
  __u32 zero_key = 0;
  union ctx *ctx_shared;
  u64 pid_tgid;

  if (!file)
    return 0;

  /* Check parent directory is monitored */
  inode_key.inode =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  inode_key.dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  if (!bpf_map_lookup_elem(&InodeMap, &inode_key))
    return 0;

  ctx_shared = bpf_map_lookup_elem(&heap_map, &zero_key);
  if (!ctx_shared)
    return 0;

  __builtin_memset(ctx_shared, 0, sizeof(*ctx_shared));

  ctx_shared->write_ctx.before_size =
      BPF_CORE_READ(file, f_path.dentry, d_inode, i_size);
  pid_tgid = bpf_get_current_pid_tgid();

  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  ctx_shared->write_ctx.ptr = dentry;

  bpf_map_update_elem(&LruMap, &pid_tgid, ctx_shared, BPF_ANY);

  return 0;
}

/**
 returns number of bytes written
*/
SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(fexit_vfs_write, ssize_t ret) {

  struct EVENT *event;
  union ctx *ctx_shared;
  u64 pid_tgid;
  struct dentry *dentry;

  pid_tgid = bpf_get_current_pid_tgid();
  ctx_shared = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!ctx_shared)
    return 0;

  if (ret <= 0)
    goto out;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;
  dentry = ctx_shared->write_ctx.ptr;
  construct_path(dentry, event->filepath, &event->len);
  event->before_size = ctx_shared->write_ctx.before_size;
  event->change_type = WRITE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(dentry, d_inode, i_size);
  getTTY(event);

  print_event("vfs_write_kretprobe", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

/**
 *  vfs_writev kprobe
 */

SEC("kprobe/vfs_writev")
int BPF_KPROBE(fim_vfs_writev, struct file *file, const struct iovec *vec,
               unsigned long vlen, loff_t *pos, rwf_t flags) {

  struct KEY inode_key = {};
  __u32 zero_key = 0;
  union ctx *ctx_shared;
  u64 pid_tgid;

  if (!file)
    return 0;

  /* Check parent directory is monitored */
  inode_key.inode =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  inode_key.dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  if (!bpf_map_lookup_elem(&InodeMap, &inode_key))
    return 0;

  ctx_shared = bpf_map_lookup_elem(&heap_map, &zero_key);
  if (!ctx_shared)
    return 0;

  __builtin_memset(ctx_shared, 0, sizeof(*ctx_shared));

  ctx_shared->write_ctx.before_size =
      BPF_CORE_READ(file, f_path.dentry, d_inode, i_size);
  pid_tgid = bpf_get_current_pid_tgid();

  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  ctx_shared->write_ctx.ptr = dentry;

  bpf_map_update_elem(&LruMap, &pid_tgid, ctx_shared, BPF_ANY);

  return 0;
}

// returns number of bytes written
SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(fexit_vfs_writev, ssize_t ret) {

  struct EVENT *event;
  union ctx *ctx_shared;
  u64 pid_tgid;
  struct dentry *dentry;

  pid_tgid = bpf_get_current_pid_tgid();
  ctx_shared = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!ctx_shared)
    return 0;

  if (ret <= 0)
    goto out;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;
  dentry = ctx_shared->write_ctx.ptr;
  construct_path(dentry, event->filepath, &event->len);
  event->before_size = ctx_shared->write_ctx.before_size;
  event->change_type = WRITE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = ret;
  event->file_size = BPF_CORE_READ(dentry, d_inode, i_size);
  getTTY(event);

  print_event("vfs_writev_kretprobe", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

/**
 * do_truncate kprobe
 */
/////////////////////////////
SEC("kprobe/do_truncate")
int BPF_KPROBE(fim_do_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
               loff_t length, unsigned int time_attrs, struct file *filp) {
  struct KEY inode_key = {};
  __u32 zero_key = 0;
  union ctx *ctx_shared;
  u64 pid_tgid;

  /* Check parent directory is monitored */
  inode_key.inode = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);
  inode_key.dev = BPF_CORE_READ(dentry, d_parent, d_inode, i_sb, s_dev);
  if (!bpf_map_lookup_elem(&InodeMap, &inode_key))
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();

  ctx_shared = bpf_map_lookup_elem(&heap_map, &zero_key);
  if (!ctx_shared)
    return 0;

  ctx_shared->write_ctx.before_size = BPF_CORE_READ(dentry, d_inode, i_size);
  ctx_shared->write_ctx.new_size = length;
  ctx_shared->write_ctx.ptr = dentry;

  bpf_map_update_elem(&LruMap, &pid_tgid, ctx_shared, BPF_ANY);

  return 0;
}

/*
  returns 0 on success
  @length new file size
*/
SEC("fexit/do_truncate")
int BPF_PROG(fexit_vfs_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
             loff_t length, unsigned int time_attrs, struct file *filp,
             int ret) {

  struct EVENT *event;
  union ctx *ctx_shared;
  u64 pid_tgid;

  pid_tgid = bpf_get_current_pid_tgid();
  ctx_shared = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!ctx_shared)
    return 0;

  if (ret < 0)
    goto out;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  event->before_size = ctx_shared->write_ctx.before_size;
  event->change_type = WRITE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written =
      (__s64)ctx_shared->write_ctx.before_size - (__s64)length;
  event->file_size = length;
  construct_path(ctx_shared->write_ctx.ptr, event->filepath, &event->len);
  getTTY(event);

  print_event("fexit_do_truncate", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

#endif
