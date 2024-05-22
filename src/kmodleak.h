#ifndef __KMODLEAK_H
#define __KMODLEAK_H

#define ALLOCS_MAX_ENTRIES		1000000

#define PERF_MAX_STACK_DEPTH	127 /* /include/uapi/linux/perf_event.h */

struct alloc_info {
	__u64 size;
	__u64 timestamp_ns;
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
