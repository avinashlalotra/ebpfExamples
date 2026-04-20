#include "helpers.h"
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_DELETE

// Unlink - file deletion
/* vfs_unlink - unlink a filesystem object
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	parent directory
 * @dentry:	victim
 * @delegated_inode: returns victim inode, if the inode is delegated.
 */

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(fentry_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, struct inode **delegated_inode) {

  struct VALUE *value;

  bpf_printk("fentry_vfs_unlink: %d", BPF_CORE_READ(dentry, d_inode));
  // check if parent directory is monitored
  value = is_monitored(dir);
  if (!value)
    return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  u32 key = 0;
  struct dentry_ctx *dentry_ctx;

  dentry_ctx = bpf_map_lookup_elem(&heap_map, &key);
  if (!dentry_ctx)
    return 0;
  __builtin_memset(dentry_ctx, 0, sizeof(*dentry_ctx));

  dentry_ctx->before_size = BPF_CORE_READ(dentry, d_inode, i_size);
  __builtin_memset(dentry_ctx->filepath, 0, sizeof(dentry_ctx->filepath));
  construct_path(dentry, dentry_ctx->filepath, &dentry_ctx->len);

  bpf_map_update_elem(&LruMap, &pid_tgid, dentry_ctx, BPF_ANY);
  return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(fexit_vfs_unlink, int ret) {

  struct EVENT *event;
  struct dentry_ctx *dentry_ctx;
  u64 pid_tgid;

  bpf_printk("fexit_vfs_unlink: %d", ret);
  pid_tgid = bpf_get_current_pid_tgid();
  // read the saved data at fentry
  dentry_ctx = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!dentry_ctx)
    return 0;

  if (ret < 0)
    goto out;
  // reserve space in ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  // populate the event
  event->before_size = dentry_ctx->before_size;
  event->change_type = DELETE_EVENT;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = 0;
  event->file_size = 0;
  event->len = dentry_ctx->len;
  getTTY(event);

  __builtin_memcpy(event->filepath, dentry_ctx->filepath,
                   sizeof(event->filepath));

  print_event("fexit_vfs_unlink", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

/* ───────────────────────────────────────────── */
/* RMDIR                                        */
/* ───────────────────────────────────────────── */
/**
 * vfs_rmdir - remove directory
 * @idmap:	idmap of the mount the inode was found from
 * @dir:	inode of @dentry
 * @dentry:	pointer to dentry of the base directory
 *
 * Remove a directory.
 *
 * If the inode has been found through an idmapped mount the idmap of
 * the vfsmount must be passed through @idmap. This function will then take
 * care to map the inode according to @idmap before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs @nop_mnt_idmap.
 */

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(fentry_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry) {

  struct VALUE *value;
  struct inode *ino;
  u64 pid_tgid;

  bpf_printk("fentry_vfs_rmdir: %d", BPF_CORE_READ(dentry, d_inode));
  // check if folder is monitored
  ino = BPF_CORE_READ(dentry, d_inode);
  value = is_monitored(ino);
  if (!value)
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  // populate the event and store in lru hash map
  u32 key = 0;
  struct dentry_ctx *dentry_ctx;

  dentry_ctx = bpf_map_lookup_elem(&heap_map, &key);
  if (!dentry_ctx)
    return 0;

  /* optional: clear it */
  __builtin_memset(dentry_ctx, 0, sizeof(*dentry_ctx));
  dentry_ctx->before_size = 4096;
  dentry_ctx->inode = BPF_CORE_READ(ino, i_ino);
  dentry_ctx->dev = BPF_CORE_READ(ino, i_sb, s_dev);
  __builtin_memset(dentry_ctx->filepath, 0, sizeof(dentry_ctx->filepath));
  construct_path(dentry, dentry_ctx->filepath, &dentry_ctx->len);

  bpf_map_update_elem(&LruMap, &pid_tgid, dentry_ctx, BPF_ANY);

  return 0;
}

SEC("kretprobe/vfs_rmdir")
int BPF_KRETPROBE(fexit_vfs_rmdir, int ret) {

  struct EVENT *event;
  struct KEY key = {};
  struct dentry_ctx *dentry_ctx;
  u64 pid_tgid;

  bpf_printk("fexit_vfs_rmdir: %d", ret);
  pid_tgid = bpf_get_current_pid_tgid();
  // read the saved data at fentry
  dentry_ctx = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!dentry_ctx)
    return 0;

  if (ret < 0)
    goto out;

  // deletion is sucess full remove entry from inode map
  key.inode = dentry_ctx->inode;
  key.dev = dentry_ctx->dev;
  bpf_map_delete_elem(&InodeMap, &key);

  // reserve space in ring buffer
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    goto out;

  // populate the event
  event->before_size = dentry_ctx->before_size;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->bytes_written = 0;
  event->file_size = 0;
  event->change_type = DELETE_EVENT;
  event->len = dentry_ctx->len;
  getTTY(event);

  __builtin_memcpy(event->filepath, dentry_ctx->filepath,
                   sizeof(event->filepath));

  print_event("fexit_vfs_rmdir", event);
  bpf_ringbuf_submit(event, 0);

out:
  bpf_map_delete_elem(&LruMap, &pid_tgid);
  return 0;
}

#endif