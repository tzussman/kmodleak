#ifndef __KMODLEAK_H
#define __KMODLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000

#ifndef MODULE_NAME_LEN
#define MODULE_NAME_LEN 56 /* /include/linux/module.h */
#endif

#define PERF_MAX_STACK_DEPTH 127 /* /include/uapi/linux/perf_event.h */

struct alloc_info {
	__u64 size;
	int stack_id;
};

enum modstate_t {
	MOD_LOADED = 1,
	MOD_INITIALIZED = 2,
	MOD_FREED = 3,
};

struct data_t {
	__u32 val;
};

#endif /* __KMODLEAK_H */
