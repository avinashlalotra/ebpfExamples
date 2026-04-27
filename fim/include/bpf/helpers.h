
#ifndef __HELPERS_H
#define __HELPERS_H

#include "maps.h"
#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline void construct_path(struct dentry *dentry, char *path,
                                           __u64 *len) {
  struct dentry *curr = dentry;
  *len = 0;

#pragma unroll
  for (int i = 0; i < MAX_DEPTH; i++) {

    struct dentry *parent = BPF_CORE_READ(curr, d_parent);
    if (curr == parent)
      break;
    struct qstr d_name = BPF_CORE_READ(curr, d_name);

    char *slot = path + (i * PER_LEVEL);

    /* Read name into fixed 64-byte slot */
    bpf_probe_read_kernel_str(slot, PER_LEVEL, d_name.name);

    /* Force null terminator at the last byte of the slot */
    slot[PER_LEVEL - 1] = '\0';
    *len = *len + 1;

    curr = parent;
  }
}

static __always_inline void getTTY(struct EVENT *event) {

  struct task_struct *task;

  task = (struct task_struct *)bpf_get_current_task();

  event->tty_major = -1;
  event->tty_minor = -1;

  event->tty_major = BPF_CORE_READ(task, signal, tty, driver, major);
  event->tty_minor = BPF_CORE_READ(task, signal, tty, index);
}

static __always_inline struct VALUE *is_monitored(struct inode *dir) {
  struct KEY key = {};
  struct VALUE *value;
  key.inode = BPF_CORE_READ(dir, i_ino);
  key.dev = BPF_CORE_READ(dir, i_sb, s_dev);

  bpf_printk("is_monitored: %ld,%ld", key.inode, key.dev);
  value = (struct VALUE *)bpf_map_lookup_elem(&InodeMap, &key);

  return value;
}

static __always_inline void print_event(const char *msg, struct EVENT *event) {

  if (event->change_type == DELETE_EVENT) {
    bpf_printk("%s: filepath: %s, type: DELETE", msg, event->filepath);
  } else if (event->change_type == CREATE_EVENT) {
    bpf_printk("%s: filepath: %s, type: CREATE", msg, event->filepath);
  } else if (event->change_type == WRITE_EVENT) {
    bpf_printk("%s: filepath: %s, type: WRITE, bytes_written: %llu", msg,
               event->filepath, event->bytes_written);
  } else if (event->change_type == RENAME_C_EVENT) {
    bpf_printk("%s: filepath: %s, type: RENAME_CREATE", msg, event->filepath);
  } else if (event->change_type == RENAME_D_EVENT) {
    bpf_printk("%s: filepath: %s, type: RENAME_DELETE", msg, event->filepath);
  } else if (event->change_type == RENAME_OW_EVENT) {
    bpf_printk("%s: filepath: %s, type: RENAME_OVERWRITE", msg,
               event->filepath);
  }
}

static __always_inline void update_dir_map(struct inode *inode, bool add) {
  struct KEY key = {};
  struct VALUE value = {1};
  __u32 mode;

  mode = BPF_CORE_READ(inode, i_mode);
  if (!S_ISDIR(mode))
    return;

  key.inode = BPF_CORE_READ(inode, i_ino);
  key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

  if (add)
    bpf_map_update_elem(&InodeMap, &key, &value, BPF_ANY);
  else
    bpf_map_delete_elem(&InodeMap, &key);
}

static __always_inline void emit_event(const char *msg,
                                       struct inode *parent_inode,
                                       struct dentry *dentry, __u8 type) {
  struct inode *inode;
  struct EVENT *event;

  inode = BPF_CORE_READ(dentry, d_inode);

  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (!event)
    return;

  event->before_size = 0;
  event->uid = bpf_get_current_uid_gid() >> 32;
  event->change_type = type;
  event->bytes_written = 0;

  if (S_ISDIR(BPF_CORE_READ(inode, i_mode)))
    event->file_size = 4096;
  else
    event->file_size = 0;

  construct_path(dentry, event->filepath, &event->len);
  getTTY(event);

  print_event(msg, event);
  bpf_ringbuf_submit(event, 0);
}

#endif /* __HELPERS_H */
