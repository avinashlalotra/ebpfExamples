#ifndef __MAPS_H
#define __MAPS_H

#include "shared_types.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct InodeMap_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, INODE_MAP_MAX_ENTRIES);
  __uint(key_size, sizeof(struct KEY));
  __uint(value_size, sizeof(struct VALUE));
};

struct RingbufMap_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 18);
};

struct LruMap_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __uint(key_size, sizeof(u64));
  __uint(value_size, sizeof(struct dentry_ctx));
};
struct heap_map_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dentry_ctx);
};

extern struct InodeMap_t InodeMap SEC(".maps");
extern struct RingbufMap_t rb SEC(".maps");
extern struct LruMap_t LruMap SEC(".maps");
extern struct heap_map_t heap_map SEC(".maps");
#endif