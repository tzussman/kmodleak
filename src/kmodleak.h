/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __KMODLEAK_H
#define __KMODLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000

#define MODULE_NAME_LEN 56 /* /include/linux/module.h */

#define PERF_MAX_STACK_DEPTH 127 /* /include/uapi/linux/perf_event.h */

/* Symbols for return addresses in the module's init text, see record_init_syms() */
#define INIT_SYMS_MAX_ENTRIES 1024

struct init_sym {
	char name[128]; /* bpf_snprintf("%pS") output */
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
