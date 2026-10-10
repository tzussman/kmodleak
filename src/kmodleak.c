/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * kmodleak
 * Copyright (c) 2023 Tal Zussman
 *
 * Based on memleak(8) from BCC by Sasha Goldshtein, JP Kobryn, and others
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c
 */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kmodleak.h"
#include "kmodleak.skel.h"
#include "trace_helpers.h"

static struct env {
	bool trace_all;
	bool percpu;
	int max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool verbose;
	char modname[MODULE_NAME_LEN];
} env = {
	.trace_all = false, // -t --trace
	.percpu = false, // --percpu
	.max_stack_depth = DEFAULT_MAX_STACK_DEPTH, // overridden by kernel.perf_event_max_stack
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.verbose = false,
	.modname = "",
};

struct allocation_node {
	uint64_t address;
	size_t size;
	struct allocation_node *next;
};

struct allocation {
	int stack_id;
	size_t size;
	size_t count;
	struct allocation_node *allocations;
};

const char *argp_program_version = "kmodleak 0.1";
const char *argp_program_bug_address = "https://github.com/tzussman/kmodleak";

const char argp_args_doc[] =
	"Trace outstanding memory allocations from a kernel module.\n"
	"\n"
	"USAGE: kmodleak [--help] [-t] [-P] [modname]\n"
	"\n"
	"EXAMPLES:\n"
	"./kmodleak module\n"
	"        Trace allocations from 'module' and display leaks on unload.\n"
	"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{ "trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{ "percpu", 'P', NULL, 0, "trace percpu allocations" },
	{ "verbose", 'v', NULL, 0, "print extra messages" },
	{},
};

static volatile sig_atomic_t exiting;

static void sig_handler(int signo) {
	exiting = 1;
}

struct ksyms *ksyms;

static struct kmodleak_bpf *skel = NULL;

static int mod_syms_fd = -1;

static bool mod_loaded = false;

error_t argp_parse_arg(int key, char *arg, struct argp_state *state) {
	static int pos_args = 0;

	switch (key) {
	case 't':
		env.trace_all = true;
		break;
	case 'P':
		env.percpu = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1) {
			if (strlen(arg) >= MODULE_NAME_LEN) {
				fprintf(stderr, "module name '%s' too long; must be < %d chars\n", arg,
					MODULE_NAME_LEN);
				argp_usage(state);
			}

			/* The kernel names modules with underscores where files have dashes */
			for (size_t i = 0; arg[i]; i++)
				env.modname[i] = arg[i] == '-' ? '_' : arg[i];
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

/*
 * Print a frame resolved by the BPF program, see record_mod_sym(). sym is
 * bpf_snprintf("%pS") output for addr - 1: name+0xoff/0xsize [module].
 */
static void print_mod_sym_frame(size_t i, uint64_t addr, const struct mod_sym *sym) {
	char name[sizeof(sym->name)];
	unsigned long off;

	if (sscanf(sym->name, "%127[^+]+0x%lx", name, &off) == 2)
		printf("\t%3zu [<%016lx>] %s+0x%lx\n", i, addr, name, off + 1);
	else
		printf("\t%3zu [<%016lx>] %s\n", i, addr, sym->name);
}

void print_stack_frames_by_ksyms(uint64_t *stack) {
	struct mod_sym mod_sym;
	const struct ksym *ksym;
	uint64_t addr;

	for (size_t i = 0; i < env.max_stack_depth; ++i) {
		addr = stack[i];

		if (addr == 0)
			break;

		/* Module frames were resolved by the BPF program while it was loaded */
		if (bpf_map_lookup_elem(mod_syms_fd, &addr, &mod_sym) == 0) {
			print_mod_sym_frame(i, addr, &mod_sym);
			continue;
		}

		/*
		 * Frame 0 is the instruction pointer when the stack was captured.
		 * Every other frame is a return address, which is the first byte
		 * of the next function when the call was the caller's last
		 * instruction, so look up the preceding byte to attribute it to
		 * the caller.
		 */
		ksym = ksyms ? ksyms__map_addr(ksyms, i == 0 ? addr : addr - 1) : NULL;

		/*
		 * Print the stack frames. Give the frame index a field width of 3,
		 * since the current max stack depth is triple digits.
		 */
		if (ksym)
			printf("\t%3zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name,
			       addr - ksym->addr);
		else
			printf("\t%3zu [<%016lx>] <%s>\n", i, addr, "null sym");
	}
}

int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd) {
	int ret = 0;

	uint64_t *stack = calloc(env.max_stack_depth, sizeof(*stack));
	if (!stack) {
		perror("failed to allocate stack array");
		return -ENOMEM;
	}

	for (size_t i = 0; i < nr_allocs; ++i) {
		const struct allocation *alloc = &allocs[i];

		printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

		struct allocation_node *it = alloc->allocations;
		while (it != NULL) {
			printf("\taddr = %#lx size = %zu\n", it->address, it->size);
			it = it->next;
		}

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			if (errno == ENOENT)
				continue;

			perror("failed to lookup stack trace");

			ret = -errno;
			goto cleanup;
		}

		print_stack_frames_by_ksyms(stack);
	}

cleanup:
	free(stack);
	return ret;
}

int alloc_size_compare(const void *a, const void *b) {
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order
	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

int print_allocs(int allocs_fd, int stack_traces_fd) {
	size_t nr_allocs = 0, nr_nostack = 0, nostack_size = 0;
	int ret = 0;

	struct allocation *allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	if (!allocs) {
		perror("failed to allocate array");
		return -ENOMEM;
	}

	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
		struct alloc_info alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key)) {
			if (errno == ENOENT)
				break; // no more keys, done

			perror("map get next key error");

			ret = -errno;
			goto cleanup;
		}

		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			ret = -errno;
			goto cleanup;
		}

		/*
		 * bpf_get_stackid() fails when the stack map is full or on a
		 * hash collision. Count these so that they are not hidden.
		 */
		if (alloc_info.stack_id < 0) {
			nr_nostack++;
			nostack_size += alloc_info.size;
			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == alloc_info.stack_id) {
				alloc->size += alloc_info.size;
				alloc->count++;

				struct allocation_node *node =
					malloc(sizeof(struct allocation_node));
				if (!node) {
					perror("malloc failed");
					ret = -errno;
					goto cleanup;
				}
				node->address = curr_key;
				node->size = alloc_info.size;
				node->next = alloc->allocations;
				alloc->allocations = node;

				stack_exists = true;
				break;
			}
		}

		if (stack_exists)
			continue;

		// When the stack_id does not exist in the allocs array,
		// create a new entry in the array
		struct allocation alloc = {
			.stack_id = alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
			.allocations = NULL,
		};

		struct allocation_node *node = malloc(sizeof(struct allocation_node));
		if (!node) {
			perror("malloc failed");
			ret = -errno;
			goto cleanup;
		}
		node->address = curr_key;
		node->size = alloc_info.size;
		node->next = NULL;
		alloc.allocations = node;

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	printf("\n%zu stacks with outstanding allocations:\n", nr_allocs);

	print_stack_frames(allocs, nr_allocs, stack_traces_fd);

	if (nr_nostack)
		printf("%zu bytes in %zu allocations with no stack trace available\n",
		       nostack_size, nr_nostack);

	// Free allocs list
	for (size_t i = 0; i < nr_allocs; i++) {
		struct allocation_node *it = allocs[i].allocations;
		while (it != NULL) {
			struct allocation_node *this = it;
			it = it->next;
			free(this);
		}
	}

cleanup:
	free(allocs);
	return ret;
}

bool has_kernel_node_tracepoints(void) {
	return tracepoint_exists("kmem", "kmalloc_node") &&
	       tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct kmodleak_bpf *skel) {
	bpf_program__set_autoload(skel->progs.kmodleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.kmodleak__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct kmodleak_bpf *skel) {
	bpf_program__set_autoload(skel->progs.kmodleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.kmodleak__percpu_free_percpu, false);
}

void detach_kernel_module_load_tracepoint(struct kmodleak_bpf *skel) {
	bpf_link__destroy(skel->links.kmodleak__module_load);
	skel->links.kmodleak__module_load = NULL;
}

void detach_kernel_module_init_kretprobe(struct kmodleak_bpf *skel) {
	bpf_link__destroy(skel->links.kmodleak__kretprobe__load_module);
	skel->links.kmodleak__kretprobe__load_module = NULL;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct mod_event *ev = data;

	if (ev->state == MOD_LOADED) {
		mod_loaded = true;

		detach_kernel_module_load_tracepoint(skel);

		printf("module '%s' loaded\n", env.modname);
	} else if (ev->state == MOD_INITIALIZED) {
		detach_kernel_module_init_kretprobe(skel);
	} else if (ev->state == MOD_FREED) {
		if (!mod_loaded) {
			fprintf(stderr, "error: module '%s' freed before loaded\n", env.modname);
			return -1;
		}

		printf("module '%s' unloaded\n", env.modname);
		exiting = 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	int ret = 0;
	struct ring_buffer *events = NULL;
	struct sigaction sa;
	int max_stack;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	// Make progress messages visible as they happen when redirected to a file
	setvbuf(stdout, NULL, _IOLBF, 0);

	// Parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;

	// Install signal handler
	if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) {
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}

	// Post-processing and validation of env settings
	if (env.modname[0] == '\0') {
		fprintf(stderr, "kmodleak: missing module name\n");
		return 1;
	}

	/*
	 * The kernel caps stack traces at kernel.perf_event_max_stack and refuses
	 * a stack map deeper than that, so size everything from it.
	 */
	max_stack = read_perf_event_max_stack();
	if (max_stack < 1)
		fprintf(stderr, "warning: cannot read kernel.perf_event_max_stack, assuming %d\n",
			env.max_stack_depth);
	else if (max_stack > MAX_STACK_DEPTH_LIMIT)
		env.max_stack_depth = MAX_STACK_DEPTH_LIMIT;
	else
		env.max_stack_depth = max_stack;

	// Check if module is already loaded
	if (is_kernel_module(env.modname)) {
		fprintf(stderr, "module '%s' is already loaded. Please unload and try again.\n",
			env.modname);
		return 1;
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	printf("using page size: %ld\n", env.page_size);

	libbpf_set_print(libbpf_print_fn);

	skel = kmodleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto cleanup;
	}

	skel->rodata->trace_all = env.trace_all;
	skel->rodata->page_size = env.page_size;
	skel->rodata->max_stack_depth = env.max_stack_depth;
	memcpy(skel->rodata->modtarget, env.modname, sizeof(env.modname));

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.max_stack_depth * sizeof(unsigned long));
	bpf_map__set_value_size(skel->maps.tmp_stack_traces,
				sizeof(long) + env.max_stack_depth * sizeof(uint64_t));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

	// Disable kernel tracepoints based on settings or availability
	if (!has_kernel_node_tracepoints())
		disable_kernel_node_tracepoints(skel);

	if (!env.percpu)
		disable_kernel_percpu_tracepoints(skel);

	ret = kmodleak_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	const int allocs_fd = bpf_map__fd(skel->maps.allocs);
	const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
	mod_syms_fd = bpf_map__fd(skel->maps.mod_syms);

	ret = kmodleak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

	// Set up ring buffer polling
	events = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!events) {
		ret = 1;
		fprintf(stderr, "Failed to create ring buffer\n");

		goto cleanup;
	}

	printf("Tracing module memory allocs... Unload module (or hit Ctrl-C) to end\n");

	// Main loop
	while (!exiting) {
		ret = ring_buffer__poll(events, -1); // infinite timeout

		if (ret == -EINTR) {
			ret = 0;
			break;
		} else if (ret < 0) {
			fprintf(stderr, "error polling ring buffer: %d\n", ret);
			goto cleanup;
		} else {
			ret = 0;
		}
	}

	/* Kernel symbols for the report; the module's own are in mod_syms */
	ksyms = ksyms__load();
	if (!ksyms)
		fprintf(stderr, "warning: failed to load kernel symbols\n");

	if (print_allocs(allocs_fd, stack_traces_fd))
		ret = 1;

cleanup:
	ksyms__free(ksyms);
	ring_buffer__free(events);
	kmodleak_bpf__destroy(skel);

	printf("done\n");

	return ret;
}
