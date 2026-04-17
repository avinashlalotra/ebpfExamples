#ifndef USER_TYPES_H
#define USER_TYPES_H

#define INODE_MAP_MAX_ENTRIES 1000

#ifdef CONFIG_BPF
#include "vmlinux.h"
#ifndef S_ISDIR
#define S_IFMT 00170000
#define S_IFDIR 0040000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#else
#include <linux/types.h>
#endif

#define MAX_PATH_LEN 512
#define PER_LEVEL 32
#define MAX_DEPTH (MAX_PATH_LEN / PER_LEVEL)

/* Event types */
#define CREATE_EVENT 0xcu
#define DELETE_EVENT 0xdu
#define WRITE_EVENT 0xeu
#define RENAME_C_EVENT 0xfu
#define RENAME_D_EVENT 0xa
#define RENAME_OW_EVENT 0xb
#define WRITE_INTENT 0x10u

/* ───────────────────────────────────────────── */

struct KEY {
  __u64 inode;
  __u64 dev;
};

struct VALUE {
  __u64 dummy;
};

struct dentry_ctx {
  __u64 inode;
  __u64 dev;
  char filepath[MAX_PATH_LEN];
  __s64 before_size;
  __u64 len;
#ifdef CONFIG_RENAME
  bool is_dir;
  bool is_old_dir_mon;
  bool is_new_dir_mon;
  bool is_new_dir;
  __u64 target_ino;
  __u64 target_dev;
  __s64 target_size;
  bool unused;
  bool inode_mon;    // folder itself is monitored
  bool is_cross_dir; // old_dir != new_dir
  bool overwrite;
#endif
};

struct EVENT {
  __u32 uid;
  __u32 change_type;
  __u64 bytes_written;
  __s64 file_size;
  __s64 before_size;
  __u32 tty_major;
  __u32 tty_minor;
  __u64 len;
  char filepath[MAX_PATH_LEN];
};

#endif /* USER_TYPES_H */
