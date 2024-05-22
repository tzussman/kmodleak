/*
 * Taken from https://github.com/iovisor/bcc/blob/master/libbpf-tools/core_fixes.bpf.h
 * Copyright (c) 2021 Hengqi Chen
 */

#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

/**
 * commit 3544de8ee6e4("mm, tracing: record slab name for kmem_cache_free()")
 * replaces `trace_event_raw_kmem_free` with `trace_event_raw_kfree` and adds
 * `tracepoint_kmem_cache_free` to enhance the information recorded for
 * `kmem_cache_free`.
 * see:
 *     https://github.com/torvalds/linux/commit/3544de8ee6e4
 */

struct trace_event_raw_kmem_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kfree___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

static __always_inline bool has_kfree()
{
	if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
		return true;
	return false;
}

static __always_inline bool has_kmem_cache_free()
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
		return true;
	return false;
}

/**
 * commit 11e9734bcb6a("mm/slab_common: unify NUMA and UMA version of
 * tracepoints") drops kmem_alloc event class, rename kmem_alloc_node to
 * kmem_alloc, so `trace_event_raw_kmem_alloc_node` is not existed any more.
 * see:
 *    https://github.com/torvalds/linux/commit/11e9734bcb6a
 */
struct trace_event_raw_kmem_alloc_node___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc_node(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
		return true;
	return false;
}

/**
 * commit 2c1d697fb8ba("mm/slab_common: drop kmem_alloc & avoid dereferencing
 * fields when not using") drops kmem_alloc event class. As a result,
 * `trace_event_raw_kmem_alloc` is removed, `trace_event_raw_kmalloc` and
 * `trace_event_raw_kmem_cache_alloc` are added.
 * see:
 *    https://github.com/torvalds/linux/commit/2c1d697fb8ba
 */
struct trace_event_raw_kmem_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmalloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc___x))
		return true;
	return false;
}

/**
 * commit ac3b43283923("module: replace module_layout with module_memory")
 * changed the layout of struct module's memory layout. The `core_layout` and
 * `init_layout` fields are replaced by a `mem` field.
 * see:
 *    https://github.com/torvalds/linux/commit/ac3b43283923
 */

/* /include/linux/module.h v6.4+ */
enum mod_mem_type___x {
	MOD_TEXT___x = 0,
	MOD_DATA___x,
	MOD_RODATA___x,
	MOD_RO_AFTER_INIT___x,
	MOD_INIT_TEXT___x,
	MOD_INIT_DATA___x,
	MOD_INIT_RODATA___x,

	MOD_MEM_NUM_TYPES___x,
	MOD_INVALID___x = -1,
};

#define MODULE_NAME_LEN		56  /* /include/linux/module.h */

struct module_memory___x {
	void *base;
	unsigned int size;
} __attribute__((preserve_access_index));

struct module___x {
	const char name[MODULE_NAME_LEN];
	struct module_memory___x mem[MOD_MEM_NUM_TYPES___x];
} __attribute__((preserve_access_index));

struct module_layout___x {
	void *base;
	unsigned int size;
} __attribute__((preserve_access_index));

struct module___o {
	const char name[MODULE_NAME_LEN];
	struct module_layout___x core_layout;
	struct module_layout___x init_layout;
} __attribute__((preserve_access_index));

static __always_inline void fill_module_text_layout(void *module, __u64 *text_base,
	__u64 *text_size, __u64 *init_text_base, __u64 *init_text_size) {

	struct module___x *mod = (struct module___x *)module;
	if (bpf_core_field_exists(mod->mem)) { // >= v6.4
		*text_base = (__u64)BPF_CORE_READ(mod, mem[MOD_TEXT___x].base);
		*text_size = BPF_CORE_READ(mod, mem[MOD_TEXT___x].size);
		*init_text_base = (__u64)BPF_CORE_READ(mod, mem[MOD_INIT_TEXT___x].base);
		*init_text_size = BPF_CORE_READ(mod, mem[MOD_INIT_TEXT___x].size);
	} else { // < v6.4
		struct module___o *mod_o = (struct module___o *)module;
		*text_base = (__u64)BPF_CORE_READ(mod_o, core_layout.base);
		*text_size = BPF_CORE_READ(mod_o, core_layout.size);
		*init_text_base = (__u64)BPF_CORE_READ(mod_o, init_layout.base);
		*init_text_size = BPF_CORE_READ(mod_o, init_layout.size);
	}
}

#endif /* __CORE_FIXES_BPF_H */
