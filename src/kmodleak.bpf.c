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

__u64 module_base = 0;
__u64 module_size = 0;
__u64 module_init_base = 0;
__u64 module_init_size = 0;

__u64 modload_pid_tgid = 0;
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

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

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
 * bpf_snprintf("%pS") output for the preceding byte.
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

/* ip is in the module's init text, which is only mapped until init completes */
static __always_inline bool in_module_init(u64 ip) {
	return !mod_initialized && module_init_base <= ip && ip < module_init_base + module_init_size;
}

/* ip is in the module's text, core or init */
static __always_inline bool in_module(u64 ip) {
	return (module_base <= ip && ip < module_base + module_size) || in_module_init(ip);
}

static void record_mod_sym(u64 ip) {
	static const char fmt[] = "%pS";
	struct mod_sym sym;
	u64 args[1];

	if (bpf_map_lookup_elem(&mod_syms, &ip))
		return;

	/*
	 * ip is a return address. bpf_snprintf() does not support %pB, so
	 * look up the preceding byte here and let userspace add one to the
	 * offset, which attributes a call at the very end of a function to
	 * that function rather than the one following it.
	 */
	args[0] = ip - 1;
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
	bool found;
};

static long walk_frame(u64 i, void *ctx) {
	struct walk_ctx *walk = ctx;
	u64 ip;

	/* max_stack_depth is read-only data, so the verifier knows the bound */
	if (i >= max_stack_depth || i >= MAX_STACK_DEPTH_LIMIT)
		return 1;

	ip = walk->data->kern_stack[i];
	if (in_module(ip)) {
		walk->found = true;
		record_mod_sym(ip);
	}

	return 0;
}

static int record_alloc(void *ctx, u64 address, size_t size) {
	struct alloc_info info;

	__builtin_memset(&info, 0, sizeof(info));
	info.size = size;

	if (address != 0) {
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
	}

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
 * Checks if the callsite passed through the specified module's text sections.
 */
static bool called_from_module(void *ctx) {
	struct walk_ctx walk = { .found = false };
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

	return walk.found;
}

/*
 * s2 is the modtarget rodata, which libbpf fills in before the program is
 * loaded. It must stay volatile all the way down to the access, otherwise
 * the compiler is free to fold the reads to its empty initializer.
 */
static inline int strncmp_mod(const char *s1, const volatile char *s2) {
	int n = MODULE_NAME_LEN;
	while (n && *s1 && (*s1 == *s2)) {
		++s1;
		++s2;
		--n;
	}

	if (n == 0)
		return 0;

	return *s1 - *s2;
}

SEC("raw_tracepoint/module_load")
int kmodleak__module_load(struct bpf_raw_tracepoint_args *ctx) {
	struct module___x *mod = (struct module___x *)BPF_CORE_READ(ctx, args[0]);
	char modname[MODULE_NAME_LEN];
	struct mod_event *ev;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (strncmp_mod(modname, modtarget) != 0)
		return 0;

	fill_module_text_layout(mod, &module_base, &module_size, &module_init_base,
				&module_init_size);

	modload_pid_tgid = bpf_get_current_pid_tgid();
	mod_loaded = true;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->state = MOD_LOADED;

	bpf_ringbuf_submit(ev, 0);

	return 0;
}

SEC("kretprobe/load_module")
int BPF_KRETPROBE(kmodleak__kretprobe__load_module) {
	struct mod_event *ev;

	if (mod_initialized || modload_pid_tgid != bpf_get_current_pid_tgid())
		return 0;

	mod_initialized = true;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->state = MOD_INITIALIZED;

	bpf_ringbuf_submit(ev, 0);

	return 0;
}

SEC("raw_tracepoint/module_free")
int kmodleak__module_free(struct bpf_raw_tracepoint_args *ctx) {
	struct module *mod = (struct module *)BPF_CORE_READ(ctx, args[0]);
	char modname[MODULE_NAME_LEN];
	struct mod_event *ev;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (strncmp_mod(modname, modtarget) != 0)
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
	const void *ptr;
	size_t bytes_alloc;

	if (!called_from_module(ctx))
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

	return record_alloc(ctx, (u64)ptr, bytes_alloc);
}

SEC("tracepoint/kmem/kmalloc_node")
int kmodleak__kmalloc_node(void *ctx) {
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;

		if (!called_from_module(ctx))
			return 0;

		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		return record_alloc(ctx, (u64)ptr, bytes_alloc);
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
	const void *ptr;
	size_t bytes_alloc;

	if (!called_from_module(ctx))
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

	return record_alloc(ctx, (u64)ptr, bytes_alloc);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int kmodleak__kmem_cache_alloc_node(void *ctx) {
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;

		if (!called_from_module(ctx))
			return 0;

		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		return record_alloc(ctx, (u64)ptr, bytes_alloc);
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
	if (!called_from_module(ctx))
		return 0;

	return record_alloc(ctx, ctx->pfn, page_size << ctx->order);
}

SEC("tracepoint/kmem/mm_page_free")
int kmodleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx) {
	if (!module_loaded())
		return 0;

	return record_free((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int kmodleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx) {
	if (!called_from_module(ctx))
		return 0;

	return record_alloc(ctx, (u64)(ctx->ptr), ctx->bytes_alloc);
}

SEC("tracepoint/percpu/percpu_free_percpu")
int kmodleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx) {
	if (!module_loaded())
		return 0;

	return record_free(ctx->ptr);
}

char LICENSE[] SEC("license") = "GPL";
