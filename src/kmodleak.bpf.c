/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * kmodleak
 * Copyright (c) 2023 Tal Zussman
 *
 * Based on memleak(8) from BCC by Sasha Goldshtein, JP Kobryn, and others
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.bpf.c
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "core_fixes.bpf.h"
#include "kmodleak.h"

const volatile size_t page_size = 4096;
const volatile char modtarget[MODULE_NAME_LEN] = "";
const volatile bool trace_all = false;
const volatile __u32 max_stack_depth = DEFAULT_MAX_STACK_DEPTH;
const volatile struct addr_range page_internal_ranges[PAGE_INTERNAL_RANGES_MAX];
const volatile __u32 nr_page_internal_ranges = 0;
const volatile struct addr_range vmap_internal_ranges[VMAP_INTERNAL_RANGES_MAX];
const volatile __u32 nr_vmap_internal_ranges = 0;

__u64 module_base = 0;
__u64 module_size = 0;
__u64 module_init_base = 0;
__u64 module_init_size = 0;

__u64 traced_module = 0; /* struct module * of the traced module */
__u64 truncated_stacks = 0; /* captures that filled the stack buffer */
bool mod_loaded = false;
bool mod_initialized = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allocs SEC(".maps");

/*
 * Stack traces of recorded allocations, keyed by a hash of their frames.
 * Values hold max_stack_depth frames and are sized by userspace.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, DEFAULT_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, STACKS_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} stacks SEC(".maps");

/*
 * Only need three entries in this map: loaded, initialized, and unloaded.
 * `max_entries` for ringbuf maps must be a power of 2 and multiple of the page
 * size.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

/*
 * Symbols for return addresses in the module's text, resolved in the kernel
 * while the module is loaded. Keyed by return address; the value is
 * bpf_snprintf("%pB") output.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* return address */
	__type(value, struct mod_sym);
	__uint(max_entries, MOD_SYMS_MAX_ENTRIES);
} mod_syms SEC(".maps");

struct stack_trace_t {
	long kern_stack_size;
	u64 kern_stack[]; /* max_stack_depth entries, sized by userspace */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct stack_trace_t) + DEFAULT_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 1);
} tmp_stack_traces SEC(".maps");

static __always_inline bool module_loaded(void) {
	return mod_loaded;
}

/*
 * ip is in the module's init text, which only runs while the module's state
 * is MODULE_STATE_COMING. The kernel sets that before module_load fires and
 * frees the init memory only after changing it and an RCU grace period, so
 * the state is read for init frames only until it has been seen to change.
 */
static __always_inline bool in_module_init(u64 ip) {
	struct module *mod = (struct module *)traced_module;
	enum module_state state;

	if (!(module_init_base <= ip && ip < module_init_base + module_init_size))
		return false;

	if (mod_initialized)
		return false;

	/* If the state cannot be read, keep treating the text as init text */
	if (bpf_core_read(&state, sizeof(state), &mod->state))
		return true;

	if (state == bpf_core_enum_value(enum module_state, MODULE_STATE_COMING))
		return true;

	mod_initialized = true;
	return false;
}

/* ip is in the module's text, core or init */
static __always_inline bool in_module(u64 ip) {
	return (module_base <= ip && ip < module_base + module_size) || in_module_init(ip);
}

/* Which allocator internals to look for on the stack, see *_internal_ranges */
enum check_internal {
	CHECK_NONE,
	CHECK_PAGE, /* a page allocation: slab allocator or vmalloc taking pages */
	CHECK_VMAP, /* a vmap area: the vm_map_ram block pool */
};

static __always_inline bool in_page_internal(u64 ip) {
	for (u32 i = 0; i < PAGE_INTERNAL_RANGES_MAX; i++) {
		if (i >= nr_page_internal_ranges)
			break;
		if (page_internal_ranges[i].start <= ip && ip < page_internal_ranges[i].end)
			return true;
	}

	return false;
}

static __always_inline bool in_vmap_internal(u64 ip) {
	for (u32 i = 0; i < VMAP_INTERNAL_RANGES_MAX; i++) {
		if (i >= nr_vmap_internal_ranges)
			break;
		if (vmap_internal_ranges[i].start <= ip && ip < vmap_internal_ranges[i].end)
			return true;
	}

	return false;
}

static void record_mod_sym(u64 ip) {
	static const char fmt[] = "%pB"; /* symbol for a return address */
	struct mod_sym sym;
	u64 args[1];

	if (bpf_map_lookup_elem(&mod_syms, &ip))
		return;

	args[0] = ip;
	if (bpf_snprintf(sym.name, sizeof(sym.name), fmt, args, sizeof(args)) < 0)
		return;

	bpf_map_update_elem(&mod_syms, &ip, &sym, BPF_NOEXIST);
}

/*
 * One frame of the stack captured by called_from_module(), run from
 * bpf_loop() so that the verifier checks it once rather than per frame.
 * Module frames are resolved while the module is loaded: the module's
 * symbols disappear from kallsyms when it is unloaded, and its __init
 * symbols as soon as its init function returns, so userspace cannot
 * reliably resolve them after the fact.
 */
struct walk_ctx {
	struct stack_trace_t *data;
	u64 hash; /* FNV-1a over the frames */
	enum check_internal check;
	bool found;
	bool via_internal;
};

/* vmlinux.h carries no errno values, and the libc header is not for the BPF target */
#define EEXIST 17

#define FNV_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

static long walk_frame(u64 i, void *ctx) {
	struct walk_ctx *walk = ctx;
	u64 ip;

	/* max_stack_depth is read-only data, so the verifier knows the bound */
	if (i >= max_stack_depth || i >= MAX_STACK_DEPTH_LIMIT)
		return 1;

	ip = walk->data->kern_stack[i];
	walk->hash = (walk->hash ^ ip) * FNV_PRIME;

	if (in_module(ip)) {
		walk->found = true;
		record_mod_sym(ip);
	} else if (walk->check == CHECK_PAGE && in_page_internal(ip)) {
		walk->via_internal = true;
	} else if (walk->check == CHECK_VMAP && in_vmap_internal(ip)) {
		walk->via_internal = true;
	}

	return 0;
}

static int record_alloc(u64 address, size_t size, u64 stack_hash) {
	struct alloc_info info;

	__builtin_memset(&info, 0, sizeof(info));
	info.size = size;
	info.stack_hash = stack_hash;

	if (address != 0)
		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc exited, address = %lx, size = %lu\n", address, info.size);

	return 0;
}

static int record_free(const void *address) {
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);

	if (trace_all)
		bpf_printk("free entered, address = %lx, size = %lu\n", address, info->size);

	return 0;
}

/*
 * Checks if the callsite passed through the specified module's text sections,
 * and if so keeps its stack trace and returns the hash that identifies it in
 * *stack_hash, or 0 if the stack could not be kept.
 * Allocations an allocator makes for itself while serving the module are not
 * counted: pages taken by the slab allocator or vmalloc, whose objects and
 * areas are accounted separately and which outlive them, and vmap areas
 * taken for the vm_map_ram block pool.
 */
static bool called_from_module(void *ctx, enum check_internal check, u64 *stack_hash) {
	struct walk_ctx walk = { .hash = FNV_OFFSET_BASIS, .check = check };
	struct stack_trace_t *data;
	long stack_bytes;
	u32 key = 0;

	if (!module_loaded())
		return false;

	data = bpf_map_lookup_elem(&tmp_stack_traces, &key);
	if (!data)
		return false;

	stack_bytes = bpf_get_stack(ctx, data->kern_stack, max_stack_depth * sizeof(*data->kern_stack), 0);
	if (stack_bytes < 0) {
		bpf_printk("bpf_get_stack() failed: %ld\n", stack_bytes);
		return false;
	}

	// bpf_get_stack() returns number of bytes available, divide by array type size
	data->kern_stack_size = stack_bytes / sizeof(*data->kern_stack);

	/* A full buffer may have cut off a module frame further up the stack */
	if (data->kern_stack_size >= max_stack_depth)
		__sync_fetch_and_add(&truncated_stacks, 1);

	walk.data = data;
	bpf_loop(data->kern_stack_size, walk_frame, &walk, 0);

	if (!walk.found || walk.via_internal)
		return false;

	/* Fold in the frame count so that a stack and a longer one it is a prefix of differ */
	walk.hash = (walk.hash ^ (u64)data->kern_stack_size) * FNV_PRIME;
	*stack_hash = walk.hash ? walk.hash : 1;

	/* bpf_get_stack() zeroed the frames past the captured ones */
	if (!bpf_map_lookup_elem(&stacks, stack_hash)) {
		long err = bpf_map_update_elem(&stacks, stack_hash, data->kern_stack, BPF_NOEXIST);

		/* Another CPU may have just kept the same stack */
		if (err && err != -EEXIST)
			*stack_hash = 0;
	}

	return true;
}

SEC("raw_tracepoint/module_load")
int kmodleak__module_load(struct bpf_raw_tracepoint_args *ctx) {
	struct module___x *mod = (struct module___x *)BPF_CORE_READ(ctx, args[0]);
	char modname[MODULE_NAME_LEN];
	struct mod_event *ev;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (bpf_strncmp(modname, sizeof(modname), (const char *)modtarget) != 0)
		return 0;

	fill_module_text_layout(mod, &module_base, &module_size, &module_init_base,
				&module_init_size);

	traced_module = (u64)mod;
	mod_loaded = true;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->state = MOD_LOADED;

	bpf_ringbuf_submit(ev, 0);

	return 0;
}

SEC("raw_tracepoint/module_free")
int kmodleak__module_free(struct bpf_raw_tracepoint_args *ctx) {
	struct module *mod = (struct module *)BPF_CORE_READ(ctx, args[0]);
	char modname[MODULE_NAME_LEN];
	struct mod_event *ev;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (bpf_strncmp(modname, sizeof(modname), (const char *)modtarget) != 0)
		return 0;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->state = MOD_FREED;

	bpf_ringbuf_submit(ev, 0);

	return 0;
}

SEC("tracepoint/kmem/kmalloc")
int kmodleak__kmalloc(void *ctx) {
	u64 stack_hash;
	const void *ptr;
	size_t bytes_alloc;

	if (!called_from_module(ctx, CHECK_NONE, &stack_hash))
		return 0;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	return record_alloc((u64)ptr, bytes_alloc, stack_hash);
}

SEC("tracepoint/kmem/kmalloc_node")
int kmodleak__kmalloc_node(void *ctx) {
	u64 stack_hash;
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;

		if (!called_from_module(ctx, CHECK_NONE, &stack_hash))
			return 0;

		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		return record_alloc((u64)ptr, bytes_alloc, stack_hash);
	} else {
		/* tracepoint is disabled if doesn't exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kfree")
int kmodleak__kfree(void *ctx) {
	const void *ptr;

	if (!module_loaded())
		return 0;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return record_free(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int kmodleak__kmem_cache_alloc(void *ctx) {
	u64 stack_hash;
	const void *ptr;
	size_t bytes_alloc;

	if (!called_from_module(ctx, CHECK_NONE, &stack_hash))
		return 0;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	return record_alloc((u64)ptr, bytes_alloc, stack_hash);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int kmodleak__kmem_cache_alloc_node(void *ctx) {
	u64 stack_hash;
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;

		if (!called_from_module(ctx, CHECK_NONE, &stack_hash))
			return 0;

		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		return record_alloc((u64)ptr, bytes_alloc, stack_hash);
	} else {
		/* tracepoint is disabled if doesn't exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int kmodleak__kmem_cache_free(void *ctx) {
	const void *ptr;

	if (!module_loaded())
		return 0;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return record_free(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int kmodleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx) {
	u64 stack_hash;

	/* a failed allocation is traced with a pfn of -1 */
	if (ctx->pfn == -1UL)
		return 0;

	if (!called_from_module(ctx, CHECK_PAGE, &stack_hash))
		return 0;

	return record_alloc(ctx->pfn, page_size << ctx->order, stack_hash);
}

SEC("tracepoint/kmem/mm_page_free")
int kmodleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx) {
	if (!module_loaded())
		return 0;

	return record_free((void *)ctx->pfn);
}

SEC("tracepoint/vmalloc/alloc_vmap_area")
int kmodleak__alloc_vmap_area(struct trace_event_raw_alloc_vmap_area *ctx) {
	u64 stack_hash;

	if (ctx->failed)
		return 0;

	if (!called_from_module(ctx, CHECK_VMAP, &stack_hash))
		return 0;

	return record_alloc(ctx->addr, ctx->size, stack_hash);
}

SEC("tracepoint/vmalloc/free_vmap_area_noflush")
int kmodleak__free_vmap_area_noflush(struct trace_event_raw_free_vmap_area_noflush *ctx) {
	if (!module_loaded())
		return 0;

	return record_free((void *)ctx->va_start);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int kmodleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx) {
	u64 stack_hash;
	if (!called_from_module(ctx, CHECK_NONE, &stack_hash))
		return 0;

	return record_alloc((u64)(ctx->ptr), ctx->bytes_alloc, stack_hash);
}

SEC("tracepoint/percpu/percpu_free_percpu")
int kmodleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx) {
	if (!module_loaded())
		return 0;

	return record_free(ctx->ptr);
}

char LICENSE[] SEC("license") = "GPL";
