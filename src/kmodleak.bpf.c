#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "core_fixes.bpf.h"
#include "kmodleak.h"

const volatile size_t page_size = 4096;
const volatile char modtarget[MODULE_NAME_LEN] = "";
const volatile bool trace_all = false;

__u64 module_base = 0;
__u64 module_size = 0;
__u64 module_init_base = 0;
__u64 module_init_size = 0;

__u64 modload_pid_tgid = 0;
bool mod_initialized = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
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

struct stack_trace_t {
	long kern_stack_size;
	u64 kern_stack[PERF_MAX_STACK_DEPTH + 1];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct stack_trace_t));
	__uint(max_entries, 1);
} tmp_stack_traces SEC(".maps");

static __always_inline bool module_loaded(void) {
	return module_base != 0 && module_size != 0;
}

static int gen_alloc_exit2(void *ctx, u64 address, size_t size) {
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

static int gen_free_enter(const void *address) {
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);

	if (trace_all)
		bpf_printk("free entered, address = %lx, size = %lu\n", address, info->size);

	return 0;
}

static bool iterate_stack_trace(struct stack_trace_t *data) {
	volatile long stack_size = data->kern_stack_size; // verifier hack

	if (!data)
		return false;

	if (stack_size > PERF_MAX_STACK_DEPTH)
		return false;

	for (u32 i = 0; i < (stack_size & PERF_MAX_STACK_DEPTH); i++) {
		u64 ip = data->kern_stack[i & PERF_MAX_STACK_DEPTH];

		// ip is located in the module's VM area
		if (module_base <= ip && ip < module_base + module_size)
			return true;

		// ip is located in the module's init area (before initialization completed)
		if (!mod_initialized && module_init_base <= ip &&
		    ip < module_init_base + module_init_size)
			return true;
	}

	return false;
}

/*
 * Checks if the callsite passed through the specified module's text sections.
 */
static bool called_from_module(void *ctx) {
	struct stack_trace_t *data;
	u32 key = 0;

	if (!module_loaded())
		return false;

	data = bpf_map_lookup_elem(&tmp_stack_traces, &key);
	if (!data)
		return false;

	data->kern_stack_size = bpf_get_stack(ctx, data->kern_stack, sizeof(data->kern_stack), 0);

	// bpf_get_stack() returns number of bytes available, divide by array type size
	data->kern_stack_size /= sizeof(*data->kern_stack);

	if (data->kern_stack_size < 0) {
		bpf_printk("bpf_get_stack() failed: %d\n", data->kern_stack_size);
		return false;
	}

	if (!iterate_stack_trace(data))
		return false;

	return true;
}

static inline int strncmp_mod(const char *s1, const char *s2) {
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
	struct data_t *mod_loaded;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (strncmp_mod(modname, (const char *)modtarget) != 0)
		return 0;

	fill_module_text_layout(mod, &module_base, &module_size, &module_init_base,
				&module_init_size);

	modload_pid_tgid = bpf_get_current_pid_tgid();

	mod_loaded = bpf_ringbuf_reserve(&events, sizeof(*mod_loaded), 0);
	if (!mod_loaded)
		return 0;

	mod_loaded->val = MOD_LOADED;

	bpf_ringbuf_submit(mod_loaded, 0);

	return 0;
}

SEC("kretprobe/load_module")
int BPF_KRETPROBE(kmodleak__kretprobe__load_module) {
	struct data_t *mod_init_data;

	if (mod_initialized || modload_pid_tgid != bpf_get_current_pid_tgid())
		return 0;

	mod_initialized = true;

	mod_init_data = bpf_ringbuf_reserve(&events, sizeof(*mod_init_data), 0);
	if (!mod_init_data)
		return 0;

	mod_init_data->val = MOD_INITIALIZED;

	bpf_ringbuf_submit(mod_init_data, 0);

	return 0;
}

SEC("raw_tracepoint/module_free")
int kmodleak__module_free(struct bpf_raw_tracepoint_args *ctx) {
	struct module *mod = (struct module *)BPF_CORE_READ(ctx, args[0]);
	char modname[MODULE_NAME_LEN];
	struct data_t *mod_unloaded;

	bpf_probe_read_kernel_str(modname, sizeof(modname), &mod->name);

	if (strncmp_mod(modname, (const char *)modtarget) != 0)
		return 0;

	mod_unloaded = bpf_ringbuf_reserve(&events, sizeof(*mod_unloaded), 0);
	if (!mod_unloaded)
		return 0;

	mod_unloaded->val = MOD_FREED;

	bpf_ringbuf_submit(mod_unloaded, 0);

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

	return gen_alloc_exit2(ctx, (u64)ptr, bytes_alloc);
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

		return gen_alloc_exit2(ctx, (u64)ptr, bytes_alloc);
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

	return gen_free_enter(ptr);
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

	return gen_alloc_exit2(ctx, (u64)ptr, bytes_alloc);
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

		return gen_alloc_exit2(ctx, (u64)ptr, bytes_alloc);
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

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int kmodleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx) {
	if (!called_from_module(ctx))
		return 0;

	return gen_alloc_exit2(ctx, ctx->pfn, page_size << ctx->order);
}

SEC("tracepoint/kmem/mm_page_free")
int kmodleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx) {
	if (!module_loaded())
		return 0;

	return gen_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int kmodleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx) {
	if (!called_from_module(ctx))
		return 0;

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr), ctx->bytes_alloc);
}

SEC("tracepoint/percpu/percpu_free_percpu")
int kmodleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx) {
	if (!module_loaded())
		return 0;

	return gen_free_enter(ctx->ptr);
}

char LICENSE[] SEC("license") = "GPL";
