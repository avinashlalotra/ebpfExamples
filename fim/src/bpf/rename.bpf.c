#include "helpers.h"
#include "maps.h"
#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_RENAME

/* ── shared helper ───────────────────────────────────────────────────────── */

static __always_inline void fill_rename_event(struct EVENT *e, u64 file_size) {
  e->uid = bpf_get_current_uid_gid() >> 32;
  e->bytes_written = 0;
  e->file_size = file_size;
  getTTY(e);
}

/* ── fentry ──────────────────────────────────────────────────────────────── */

SEC("fentry/vfs_rename")
int BPF_PROG(fentry_vfs_rename, struct renamedata *rd) {
  struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
  if (!old_dentry)
    return 0;

  struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
  if (!old_inode)
    return 0;

  umode_t mode = BPF_CORE_READ(old_inode, i_mode);
  bool is_dir = ((mode & S_IFMT) == S_IFDIR);

  struct inode *old_dir = BPF_CORE_READ(rd, old_dir);
  struct inode *new_dir = BPF_CORE_READ(rd, new_dir);

  /* ── Check if any relevant path is monitored ──────────────────────── */
  bool monitored = false;

  if (is_dir) {
    /* For directories: capture if dir itself is monitored OR moving into
     * monitored area */
    monitored = is_monitored(old_inode) || (new_dir && is_monitored(new_dir));
  } else {
    /* For files: capture if either parent dir is monitored */
    monitored = (old_dir && is_monitored(old_dir)) ||
                (new_dir && is_monitored(new_dir));
  }

  if (!monitored)
    return 0;

  /* ── Prepare context for fexit ───────────────────────────────────── */
  u32 key = 0;
  struct dentry_ctx *d_ctx = bpf_map_lookup_elem(&heap_map, &key);
  if (!d_ctx)
    return 0;

  __builtin_memset(d_ctx, 0, sizeof(*d_ctx));

  d_ctx->is_dir = is_dir;
  d_ctx->inode_mon = is_dir && is_monitored(old_inode);
  d_ctx->is_old_dir_mon = !is_dir && old_dir && is_monitored(old_dir);
  d_ctx->is_new_dir_mon =
      (is_dir || !is_dir) && new_dir && is_monitored(new_dir);
  d_ctx->is_cross_dir = (old_dir != new_dir);
  d_ctx->inode = BPF_CORE_READ(old_inode, i_ino);
  d_ctx->dev = BPF_CORE_READ(old_inode, i_sb, s_dev);
  d_ctx->before_size = BPF_CORE_READ(old_inode, i_size);

  /* Capture target (overwrite case) */
  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
  struct inode *target_inode = BPF_CORE_READ(new_dentry, d_inode);
  if (target_inode) {
    d_ctx->overwrite = true;
    d_ctx->target_ino = BPF_CORE_READ(target_inode, i_ino);
    d_ctx->target_dev = BPF_CORE_READ(target_inode, i_sb, s_dev);
    d_ctx->target_size = BPF_CORE_READ(target_inode, i_size);
  }

  /* Capture old path (used for DELETE event) */
  construct_path(old_dentry, d_ctx->filepath, &d_ctx->len, 0);

  u64 pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&LruMap, &pid, d_ctx, BPF_ANY);

  return 0;
}

/* ── fexit ───────────────────────────────────────────────────────────────── */

SEC("fexit/vfs_rename")
int BPF_PROG(fexit_vfs_rename, struct renamedata *rd, int ret) {
  u64 pid = bpf_get_current_pid_tgid();
  struct dentry_ctx *old_ctx = bpf_map_lookup_elem(&LruMap, &pid);
  if (!old_ctx)
    return 0;

  if (ret != 0)
    goto cleanup;

  struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);

  /* ── 1. Emit DELETE event for old path ──────────────────────────── */
  struct EVENT *event_d = bpf_ringbuf_reserve(&rb, sizeof(*event_d), 0);
  if (!event_d)
    goto cleanup;

  fill_rename_event(event_d, old_ctx->before_size);
  event_d->before_size = old_ctx->before_size;
  event_d->change_type = RENAME_D_EVENT;

  /* Copy the old path to the event */
  if (old_ctx->len > 0) {
    __builtin_memcpy(event_d->filepath, old_ctx->filepath, MAX_PATH_LEN);
    event_d->len = old_ctx->len;
  }

  /* Update InodeMap: Remove dir if leaving monitored area */
  if (old_ctx->is_dir && old_ctx->is_cross_dir && old_ctx->inode_mon &&
      !old_ctx->is_new_dir_mon) {
    struct KEY k = {.inode = old_ctx->inode, .dev = old_ctx->dev};
    bpf_map_delete_elem(&InodeMap, &k);
  }

  print_event("fexit_vfs_rename", event_d);
  bpf_ringbuf_submit(event_d, 0);

  /* ── 2. Emit CREATE or OVERWRITE event for new path ─────────────── */
  struct EVENT *event_c = bpf_ringbuf_reserve(&rb, sizeof(*event_c), 0);
  if (!event_c)
    goto cleanup;

  fill_rename_event(event_c, old_ctx->before_size);
  construct_path(new_dentry, event_c->filepath, &event_c->len, 0);

  if (old_ctx->overwrite) {
    event_c->before_size = old_ctx->target_size;
    event_c->change_type = RENAME_OW_EVENT;
  } else {
    event_c->before_size = old_ctx->before_size;
    event_c->change_type = RENAME_C_EVENT;

    /* Update InodeMap: Add dir if entering monitored area */
    if (old_ctx->is_dir && old_ctx->is_cross_dir && old_ctx->is_new_dir_mon &&
        !old_ctx->inode_mon) {
      struct KEY k = {.inode = old_ctx->inode, .dev = old_ctx->dev};
      struct VALUE v = {1};
      bpf_map_update_elem(&InodeMap, &k, &v, BPF_ANY);
    }
  }

  print_event("fexit_vfs_rename", event_c);
  bpf_ringbuf_submit(event_c, 0);

cleanup:
  bpf_map_delete_elem(&LruMap, &pid);
  return 0;
}

#endif