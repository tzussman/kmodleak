# kmodleak

[![Github Actions](https://github.com/tzussman/kmodleak/actions/workflows/build.yml/badge.svg)](https://github.com/tzussman/kmodleak/actions/workflows/build.yml)

`kmodleak` is an eBPF tool for tracing Linux kernel module memory leaks.
For full functionality, it requires loading and unloading the target module
while it is running. Once the module is unloaded, `kmodleak` will terminate
automatically, and display a summary of the leaks.

*The infrastructure in this repo was taken from
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/).*
*`kmodleak`'s design is inspired by and based on
[`memleak`](https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c) from BCC.*

## Setup

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

### Install Dependencies

You will need `clang` (at least v12 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

If your distribution does not offer a recent enough version of `clang`, see
the automatic installation script at [apt.llvm.org](https://apt.llvm.org/).

### Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/tzussman/kmodleak
```

### Building

Makefile build:

```console
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
$ sudo ./kmodleak leak
using page size: 4096
Tracing module memory allocs... Unload module (or hit Ctrl-C) to end
module 'leak' loaded
module 'leak' unloaded
[19:56:56] Top 1 stacks with outstanding allocations:
128 bytes in 1 allocations from stack
        addr = 0xffff000086586a80 size = 128
        0 [<ffff8000102ab2c8>] __traceiter_kmalloc+0x68
        1 [<ffff8000102ab2c8>] __traceiter_kmalloc+0x68
        2 [<ffff80001031d7f0>] kmem_cache_alloc_trace+0x25c
        3 [<ffff800008db8038>] efivarfs_exit+0x5084
        4 [<ffff800010013630>] do_one_initcall+0x50
        5 [<ffff80001016fc40>] do_init_module+0x60
        6 [<ffff800010172270>] load_module+0x2290
        7 [<ffff800010038810>] kretprobe_trampoline+0x0
        8 [<ffff800010172a8c>] __arm64_sys_finit_module+0x2c
        9 [<ffff800010027d10>] el0_svc_common+0x70
        10 [<ffff800010027e14>] do_el0_svc+0x34
        11 [<ffff800010bc448c>] el0_svc+0x2c
        12 [<ffff800010bc4b34>] el0_sync_handler+0x1a4
        13 [<ffff800010011db4>] el0_sync+0x174
done
```

### Installation

TODO

## Troubleshooting

libbpf debug logs are quite helpful to pinpoint the exact source of problems,
so it's usually a good idea to look at them before starting to debug or
posting question online.

For `./kmodleak`, run it in verbose mode (`-v`) to see libbpf debug logs:

```console
$ sudo ./kmodleak -v leak
using page size: 4096
libbpf: loading object 'kmodleak_bpf' from buffer
libbpf: elf: section(2) .symtab, size 2400, link 1, flags 0, type=2
libbpf: elf: section(3) .text, size 600, link 0, flags 6, type=1
libbpf: sec '.text': found program 'validate_stack' at insn offset 0 (0 bytes), code size 75 insns (600 bytes)
libbpf: elf: section(4) raw_tracepoint/module_load, size 808, link 0, flags 6, type=1
libbpf: sec 'raw_tracepoint/module_load': found program 'kmodleak__module_load' at insn offset 0 (0 bytes), code size 101 insns (808 bytes)
libbpf: elf: section(5) kretprobe/load_module, size 208, link 0, flags 6, type=1
...
```
