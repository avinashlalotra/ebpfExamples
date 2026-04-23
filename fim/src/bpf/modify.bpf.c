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

write:     file_permission+ kretprobe/vfs_write        -- path verified
writev:    file_permission+ kretprobe/vfs_writev       -- path verified

*/

#ifdef CONFIG_MODIFY

// Fires before any read/write op. Filtered to MAY_WRITE only.
SEC("kprobe/security_file_permission")
int BPF_PROG(fim_file_permission, struct file *file, int mask) {
  struct KEY inode_key = {};
  struct EVENT *event;
  __u32 zero_key = 0;
  struct dentry_ctx *dentry_ctx;
  u64 pid_tgid;

  if (!(mask & MAY_WRITE))
    return 0;

  if (!file)
    return 0;

  /* Check parent directory is monitored */
  inode_key.inode =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
  inode_key.dev =
      BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_sb, s_dev);

  if (!bpf_map_lookup_elem(&InodeMap, &inode_key))
    return 0;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return 0;

  event->before_size = BPF_CORE_READ(file, f_path.dentry, d_inode, i_size);
  event->file_size = -1;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->change_type = WRITE_INTENT;
  event->bytes_written = 0;
  pid_tgid = bpf_get_current_pid_tgid();
  getTTY(event);
  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  construct_path(dentry, event->filepath, &event->len);

  bpf_printk("file_permission: filename=%s before=%lld", event->filepath,
             event->before_size);

  dentry_ctx = bpf_map_lookup_elem(&heap_map, &zero_key);
  if (!dentry_ctx)
    goto submit;

  __builtin_memset(dentry_ctx, 0, sizeof(*dentry_ctx));
  dentry_ctx->before_size = event->before_size;
  __builtin_memcpy(dentry_ctx->filepath, event->filepath, MAX_PATH_LEN);
  dentry_ctx->len = event->len;

  bpf_map_update_elem(&LruMap, &pid_tgid, dentry_ctx, BPF_ANY);

submit:
  bpf_ringbuf_submit(event, 0);
  return 0;
}

/**
 returns number of bytes written
*/
SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(fexit_vfs_write, ssize_t ret) {

  bpf_printk("kretprobe_vfs_write: ret=%lld", ret);
  struct EVENT *event;
  struct dentry_ctx *dentry_ctx;
  u64 pid_tgid;

  pid_tgid = bpf_get_current_pid_tgid();
  dentry_ctx = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!dentry_ctx)
    return 0;

  if (ret <= 0)
    goto out;

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  event->before_size = dentry_ctx->before_size;
  event->change_type = WRITE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = ret;
  event->len = dentry_ctx->len;
  getTTY(event);

  __builtin_memcpy(event->filepath, dentry_ctx->filepath,
                   sizeof(event->filepath));

  print_event("fexit_vfs_write", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

#endif
