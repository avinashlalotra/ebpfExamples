#include "helpers.h"
#include "maps.h"
#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef CONFIG_RENAME

SEC("kprobe/vfs_rename")
int BPF_KPROBE(fim_vfs_rename_kprobe, struct renamedata *rd) {

  /* Four cases */
  /**  Source    Destination    ToDo
   *     0          0            Nothing
   *     0          1            Generate a CREATE event at Destination + DELETE
   * EVENT at Source for context 1          0            Generate a Delete event
   * at Source + CREATE event at Destination for context 1          1 Generate a
   * CREATE+DELETE EVENT
   */

  struct inode *old_dir, *new_dir, *source_inode, *destination_inode;
  struct dentry *old_dentry, *new_dentry;
  __u32 mode;
  u64 pid_tgid;
  bool isdir, source, destination;

  union ctx *ctx_shared;
  __u32 heap_key = 0;

  old_dir = BPF_CORE_READ(rd, old_dir);
  new_dir = BPF_CORE_READ(rd, new_dir);
  old_dentry = BPF_CORE_READ(rd, old_dentry);
  new_dentry = BPF_CORE_READ(rd, new_dentry);

  mode = BPF_CORE_READ(old_dentry, d_inode, i_mode);

  isdir = false; // assume its a file
  source_inode = old_dir;
  destination_inode = new_dir;

  if (S_ISDIR(mode))
    isdir = true;

  if (isdir) {
    source_inode = BPF_CORE_READ(old_dentry, d_inode);
    destination_inode = BPF_CORE_READ(new_dentry, d_inode);
  };

  source = is_monitored(source_inode);
  destination = is_monitored(destination_inode);

  if (!(source || destination))
    return 0;

  ctx_shared = bpf_map_lookup_elem(&heap_map, &heap_key);
  if (!ctx_shared)
    return 0;
  __builtin_memset(ctx_shared, 0, sizeof(*ctx_shared));

  destination_inode = BPF_CORE_READ(new_dentry, d_inode);
  if (destination_inode)
    ctx_shared->rename_ctx.overwrite = true;

  ctx_shared->rename_ctx.replaced_inode = destination_inode;
  pid_tgid = bpf_get_current_pid_tgid();

  ctx_shared->rename_ctx.isDir = isdir;
  ctx_shared->rename_ctx.source = source;
  ctx_shared->rename_ctx.destination = destination;
  ctx_shared->rename_ctx.rd = rd;
  ctx_shared->rename_ctx.old_inode = BPF_CORE_READ(old_dentry, d_inode);
  ctx_shared->rename_ctx.src_before_size =
      BPF_CORE_READ(old_dentry, d_inode, i_size);

  if (destination_inode)
    ctx_shared->rename_ctx.dest_before_size =
        BPF_CORE_READ(destination_inode, i_size);

  construct_path(old_dentry, ctx_shared->rename_ctx.filepath,
                 &ctx_shared->rename_ctx.len);

  bpf_map_update_elem(&LruMap, &pid_tgid, ctx_shared, BPF_ANY);
  return 0;
};

/* ── fexit ─────────────────────────────────────────────────────────────────
 */

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(fim_vfs_rename_kretprobe, int ret) {

  u64 pid_tgid;
  union ctx *ctx_shared;
  struct EVENT *src, *dest;
  __u32 uid;
  struct dentry *new_dentry;
  struct renamedata *rd;
  struct inode *source_inode;
  struct inode *replaced_inode;

  if (ret != 0)
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  ctx_shared = bpf_map_lookup_elem(&LruMap, &pid_tgid);
  if (!ctx_shared)
    return 0;

  /* source file*/
  src = bpf_ringbuf_reserve(&rb, sizeof(*src), 0);
  if (!src)
    return 0;

  uid = bpf_get_current_uid_gid() >> 32;

  src->before_size = ctx_shared->rename_ctx.src_before_size;
  src->file_size = 0; /* now the dentry don't exist */
  src->bytes_written = 0;
  __builtin_memcpy(src->filepath, ctx_shared->rename_ctx.filepath,
                   sizeof(src->filepath));
  src->uid = uid;
  src->len = ctx_shared->rename_ctx.len;
  getTTY(src);

  src->change_type = DELETE_EVENT;

  print_event("vfs_rename_src", src);
  bpf_ringbuf_submit(src, 0);

  /* destination file*/
  dest = bpf_ringbuf_reserve(&rb, sizeof(*dest), 0);
  if (!dest)
    return 0;

  rd = ctx_shared->rename_ctx.rd;
  source_inode = ctx_shared->rename_ctx.old_inode;
  replaced_inode = ctx_shared->rename_ctx.replaced_inode;
  new_dentry = BPF_CORE_READ(rd, new_dentry);
  if (ctx_shared->rename_ctx.overwrite) {
    dest->before_size = BPF_CORE_READ(replaced_inode, i_size);
  };

  dest->file_size = BPF_CORE_READ(source_inode, i_size);
  dest->bytes_written =
      0; /* in case of overwrites we can compare that from file sizes */
  construct_path(new_dentry, dest->filepath, &dest->len);
  getTTY(dest);
  dest->change_type = CREATE_EVENT;

  print_event("vfs_rename_dest", dest);
  bpf_ringbuf_submit(dest, 0);

  return 0;
}

#endif