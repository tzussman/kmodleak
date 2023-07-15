#!/usr/bin/env python3

import argparse

from bcc import BPF

class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size

MAX_MODULE_LENGTH = 56

description = """
Trace memory allocations made by a kernel module, and report leaks when unloading.
Requires loading and unloading the module while this script is running.
"""

parser = argparse.ArgumentParser(description=description)
parser.add_argument("module", type=str, help="the module to trace")

args = parser.parse_args()

module_name = args.module

if len(module_name) > MAX_MODULE_LENGTH:
    print(f"module name cannot exceed {MAX_MODULE_LENGTH} chars")
    exit(1)

bpf_source = """
#include <linux/mm.h>
#include <linux/module.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/perf_event.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

#define SHOULD_PRINT 0

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = stack_traces.get_stackid(ctx, 0);
        allocs.update(&address, &info);
        update_statistics_add(info.stack_id, info.size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}
"""

# TODO: check for struct module_layout using pahole or BPF CO-RE

bpf_module_source = """

#define MODULE_BASE_INDEX  0
#define MODULE_SIZE_INDEX  1

BPF_ARRAY(module_data, u64, 2);
BPF_PERF_OUTPUT(events);

struct data_t {
        u64 val;
};

static inline int strncmp_mod(char *s1, char *s2) {
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

RAW_TRACEPOINT_PROBE(module_load) {
        struct module *mod = (struct module *)ctx->args[0];
        char modname[MODULE_NAME_LEN], modtarget[MODULE_NAME_LEN] = "leak";
        int base_index = MODULE_BASE_INDEX, size_index = MODULE_SIZE_INDEX;
        u64 base, size;

        bpf_probe_read_kernel_str(modname, sizeof(modname), mod->name);

        if (strncmp_mod(modname, modtarget) != 0)
                return 0;

        base = (u64)mod->core_layout.base;
        size = mod->core_layout.size;

        module_data.update(&base_index, &base);
        module_data.update(&size_index, &size);
        return 0;
}

RAW_TRACEPOINT_PROBE(module_free) {
        struct module *mod = (struct module *)ctx->args[0];
        char modname[MODULE_NAME_LEN], modtarget[MODULE_NAME_LEN] = "leak";
        struct data_t data = { .val = 1 };

        bpf_probe_read_kernel_str(modname, sizeof(modname), mod->name);

        if (strncmp_mod(modname, modtarget) != 0)
                return 0;
        
        events.perf_submit(ctx, &data, sizeof(data));
                
        return 0;
}

"""

bpf_source_kernel = """

struct stack_trace_t {
        int kern_stack_size;
        __u64 kern_stack[PERF_MAX_STACK_DEPTH + 1];
};

BPF_PERCPU_ARRAY(tmp_stack_traces, struct stack_trace_t, 1);

#define __noinline __attribute__((noinline))

int noinline iterate_stack_trace(__u64 stack_size, __u64 base, __u64 size) {
        __u32 key = 0;
        struct stack_trace_t *data = tmp_stack_traces.lookup(&key);

        if (!data)
                return 0;

        for (uint i = 0; i < stack_size; i++) {
                __u64 ip = data->kern_stack[i & PERF_MAX_STACK_DEPTH];

                // ip is located in the module's VM area
                if (base <= ip && ip < base + size)
                        return 1;
        }

        return 0;
}


TRACEPOINT_PROBE(kmem, kmalloc) {
        struct stack_trace_t *data;
        __u32 key = 0;
        int base_index = MODULE_BASE_INDEX, size_index = MODULE_SIZE_INDEX;
        __u64 *base, *size;

        base = module_data.lookup(&base_index);
        size = module_data.lookup(&size_index);

        if (base == NULL || size == NULL || *base == 0 || *size == 0)
                return 0;

        data = tmp_stack_traces.lookup(&key);
        if (!data)
                return 0;

        data->kern_stack_size = bpf_get_stack(args, data->kern_stack, PERF_MAX_STACK_DEPTH, 0);

        if (data->kern_stack_size > PERF_MAX_STACK_DEPTH)
                return 0;

        if (iterate_stack_trace(data->kern_stack_size, *base, *size)) {
                gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
                return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
        }

        return 0;
}

TRACEPOINT_PROBE(kmem, kmalloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kfree) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
        gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order);
        return gen_alloc_exit2((struct pt_regs *)args, args->pfn);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
        return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}
"""

bpf_source_kernel_node = """

TRACEPOINT_PROBE(kmem, kmalloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
        gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
        return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}
"""

bpf_source += bpf_module_source + bpf_source_kernel
#if BPF.tracepoint_exists("kmem", "kmalloc_node"):
#    bpf_source += bpf_source_kernel_node

bpf = BPF(text=bpf_source)

def handle_perf_event(cpu, data, size):
    event = bpf["events"].event(data)
    if event.val == 1:
        print("Module unloaded")

bpf["events"].open_perf_buffer(handle_perf_event)

while True:
    try:
        bpf.perf_buffer_poll()
        break
    except KeyboardInterrupt:
        print(bpf['module_data'][0])
        break
