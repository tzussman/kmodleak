/* 
 * kmodleak
 * Copyright (c) 2023 Tal Zussman 
 *
 * Based on memleak(8) from BCC by Sasha Goldshtein, JP Kobryn, and others
 * https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c
 */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "kmodleak.h"
#include "kmodleak.skel.h"
#include "trace_helpers.h"

static struct env {
	bool trace_all;
	bool percpu;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool verbose;
	char modname[MODULE_NAME_LEN];
} env = {
	.trace_all = false, // -t --trace
	.percpu = false, // --percpu
	.perf_max_stack_depth = PERF_MAX_STACK_DEPTH,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.verbose = false,
	.modname = "",
};

struct allocation_node {
	uint64_t address;
	size_t size;
	struct allocation_node* next;
};

struct allocation {
	uint64_t stack_id;
	size_t size;
	size_t count;
	struct allocation_node* allocations;
};

const char *argp_program_version = "kmodleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/tzussman/kmodleak";

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
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{"percpu", 'P', NULL, 0, "trace percpu allocations"},
	{"verbose", 'v', NULL, 0, "print extra messages"},
	{},
};

static volatile sig_atomic_t exiting;

static void sig_handler(int signo)
{
	exiting = 1;
}

struct ksyms *ksyms;

static struct kmodleak_bpf *skel = NULL;

static bool mod_loaded = false;

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
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
			memcpy(env.modname, arg, sizeof(env.modname));
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

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void print_stack_frames_by_ksyms(uint64_t *stack)
{
	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

		/*
		 * Print the stack frames. Give the frame index a field width of 3,
		 * since the current max stack depth is triple digits.
		 */
		if (ksym)
			printf("\t%3zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name, addr - ksym->addr);
		else
			printf("\t%3zu [<%016lx>] <%s>\n", i, addr, "null sym");
	}
}

int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd)
{
	int ret = 0;

	uint64_t *stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		perror("failed to allocate stack array");
		return -ENOMEM;
	}

	for (size_t i = 0; i < nr_allocs; ++i) {
		const struct allocation *alloc = &allocs[i];

		printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

		struct allocation_node* it = alloc->allocations;
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

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order
	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

int print_allocs(int allocs_fd, int stack_traces_fd)
{
	size_t nr_allocs = 0;
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

		// filter invalid stacks
		if (alloc_info.stack_id < 0)
			continue;

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == alloc_info.stack_id) {
				alloc->size += alloc_info.size;
				alloc->count++;

				struct allocation_node* node = malloc(sizeof(struct allocation_node));
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

		// when the stack_id does not exist in the allocs array,
		//   create a new entry in the array
		struct allocation alloc = {
			.stack_id = alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
			.allocations = NULL
		};

		struct allocation_node* node = malloc(sizeof(struct allocation_node));
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

bool has_kernel_node_tracepoints()
{
	return tracepoint_exists("kmem", "kmalloc_node") &&
		tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct kmodleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.kmodleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.kmodleak__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct kmodleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.kmodleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.kmodleak__percpu_free_percpu, false);
}

void disable_kernel_module_load_tracepoint(struct kmodleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.kmodleak__module_load, false);
}

void disable_kernel_module_init_tracepoint(struct kmodleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.kmodleak__kretprobe__load_module, false);
}

int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct data_t *d = data;

	if (d->val == MOD_LOADED) {
		mod_loaded = true;
		
		disable_kernel_module_load_tracepoint(skel);

		printf("module '%s' loaded\n", env.modname);
	} else if (d->val == MOD_INITIALIZED) {
		disable_kernel_module_init_tracepoint(skel);
	} else if (d->val == MOD_FREED) {
		if (!mod_loaded) {
			fprintf(stderr, "error: module '%s' freed before loaded\n", env.modname);
			return -1;
		}

		printf("module '%s' unloaded\n", env.modname);
		exiting = 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct ring_buffer *events = NULL;
	int modlen;
	struct sigaction sa;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	// parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;

	// install signal handler
	if (sigaction(SIGINT, &sa, NULL)) {
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}

	// post-processing and validation of env settings
	modlen = strlen(env.modname);
	if (modlen == 0) {
		fprintf(stderr, "kmodleak: missing module name\n");
		return 1;
	}

	if (modlen >= MODULE_NAME_LEN) {
		fprintf(stderr, "module name '%s' too long; must be < %d chars\n",
				env.modname, MODULE_NAME_LEN);
		return 1;
	}

	// Check if module is already loaded
	if (is_kernel_module(env.modname)) {
		fprintf(stderr, "module '%s' is already loaded. Please unload and try again.\n", env.modname);
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
	memcpy(skel->rodata->modtarget, env.modname, sizeof(env.modname));

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

	// disable kernel tracepoints based on settings or availability
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

	ret = kmodleak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

	/* Set up ring buffer polling */
	events = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!events) {
		ret = 1;
		fprintf(stderr, "Failed to create ring buffer\n");

		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "Failed to load ksyms\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	printf("Tracing module memory allocs... Unload module (or hit Ctrl-C) to end\n");

	// main loop
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

	print_allocs(allocs_fd, stack_traces_fd);

cleanup:
	ksyms__free(ksyms);
	ring_buffer__free(events);
	kmodleak_bpf__destroy(skel);

	printf("done\n");

	return ret;
}
