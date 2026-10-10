/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __KMODLEAK_H
#define __KMODLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000

#define MODULE_NAME_LEN 56 /* /include/linux/module.h */

/*
 * Stack depth: kernel.perf_event_max_stack decides, with this as the fallback
 * and a cap set by the 32 KB limit on per-CPU map values, which hold the
 * stack buffer: one long for the frame count plus one u64 per frame.
 */
#define DEFAULT_MAX_STACK_DEPTH 127
#define MAX_STACK_DEPTH_LIMIT ((32 * 1024 - 8) / 8)

/* Symbols for return addresses in the module's text, see record_mod_syms() */
#define MOD_SYMS_MAX_ENTRIES 4096

struct mod_sym {
	char name[128]; /* bpf_snprintf("%pB") output */
};

/* Kernel functions whose frames mark a page allocation as the slab allocator's */
#define SLAB_RANGES_MAX 64

struct addr_range {
	__u64 start;
	__u64 end;
};

struct alloc_info {
	__u64 size;
	int stack_id;
};

enum modstate_t {
	MOD_LOADED = 1,
	MOD_INITIALIZED = 2,
	MOD_FREED = 3,
};

struct mod_event {
	__u32 state; /* enum modstate_t */
};

#endif /* __KMODLEAK_H */
