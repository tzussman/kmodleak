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

#endif /* __CORE_FIXES_BPF_H */
