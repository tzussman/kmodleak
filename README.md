# kmodleak

[![Github Actions](https://github.com/tzussman/kmodleak/actions/workflows/build.yml/badge.svg)](https://github.com/tzussman/kmodleak/actions/workflows/build.yml)

`kmodleak` is an eBPF tool for tracing Linux kernel module memory leaks.
For full functionality, it requires loading and unloading the target module
while it is running. It does NOT load or unload modules itself. Once the module
is unloaded, `kmodleak` will automatically terminate and display a summary of
any detected memory leaks.

#### Credits

*The infrastructure in this repo was taken from
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/).*
*`kmodleak`'s design is inspired by and based on
[`memleak`](https://github.com/iovisor/bcc/blob/master/libbpf-tools/memleak.c)
from BCC.*
*`kmodleak` was also inspired by [`KEDR`](https://github.com/euspectre/kedr) and
is intended to serve as a lightweight replacement for its memory leak detector.*

## Setup

### Requirements

`kmodleak` must be run as root on a kernel built with `CONFIG_DEBUG_INFO_BTF`,
`CONFIG_KPROBES` and `CONFIG_BPF_EVENTS`. Linux 5.13 or later is required for
the BPF helpers used.

### Install Dependencies

You will need `clang` (v17 or later), `gcc`, `make`, `libelf` and `zlib` to
build `kmodleak`. Package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang gcc make libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang gcc make elfutils-libelf elfutils-libelf-devel zlib-devel
```

If your distribution does not offer a recent enough version of `clang`, see
the automatic installation script at [apt.llvm.org](https://apt.llvm.org/).

### Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/tzussman/kmodleak
```

### Building

Build with `make` and run the result as root:

```console
$ git submodule update --init --recursive       # check out libbpf
$ cd src
$ make
$ sudo ./kmodleak leak  # Module is loaded and unloaded by the user (not shown)
using page size: 4096
Tracing module memory allocs... Unload module (or hit Ctrl-C) to end
module 'leak' loaded
module 'leak' unloaded

1 stacks with outstanding allocations:
128 bytes in 1 allocations from stack
        addr = 0xffff0000cb2c1500 size = 128
          0 [<ffff80008038567c>] __traceiter_kmalloc+0x74
          1 [<ffff80008038567c>] __traceiter_kmalloc+0x74
          2 [<ffff8000803f5d68>] __kmalloc_cache_noprof+0x338
          3 [<ffff80007c44403c>] leak_init+0x34
          4 [<ffff800080015d9c>] do_one_initcall+0x64
          5 [<ffff8000801a6328>] do_init_module+0x60
          6 [<ffff8000801a878c>] load_module+0x1f54
          7 [<ffff8000801a8bac>] init_module_from_file+0xe4
          8 [<ffff8000801a8d90>] __arm64_sys_finit_module+0x150
          9 [<ffff80008002d634>] invoke_syscall+0x5c
         10 [<ffff80008002d740>] el0_svc_common.constprop.0+0x48
         11 [<ffff80008002d80c>] do_el0_svc+0x24
         12 [<ffff8000815000d8>] el0_svc+0x38
         13 [<ffff800081500550>] el0t_64_sync_handler+0xa0
         14 [<ffff8000800115a0>] el0t_64_sync+0x198
done
```

## Usage

`kmodleak` monitors kernel module memory allocations and detects leaks. The typical workflow is:

1. **Start kmodleak** - Run `kmodleak` with the module name you want to monitor
2. **Load the module** - In another terminal, load your kernel module with `insmod`
3. **Use the module** - Exercise your module's functionality
4. **Unload the module** - Remove the module with `rmmod`
5. **View results** - `kmodleak` automatically exits and shows any detected leaks

### Options

- `-t`, `--trace`: print a message for each traced allocation and free to the
  kernel trace buffer (`/sys/kernel/tracing/trace_pipe`)
- `-P`, `--percpu`: also trace per-CPU allocations
- `-v`, `--verbose`: print libbpf debug messages

Hitting Ctrl-C before the module is unloaded ends tracing early and prints the
allocations outstanding at that point.

### Basic Example

**Terminal 1** - Start monitoring:
```console
$ sudo ./kmodleak mymodule
using page size: 4096
Tracing module memory allocs... Unload module (or hit Ctrl-C) to end
```

**Terminal 2** - Load, use, and unload your module:
```console
$ sudo insmod mymodule.ko
$ # Exercise your module's functionality
$ sudo rmmod mymodule
```

**Terminal 1** - Results appear automatically:
```console
module 'mymodule' loaded
module 'mymodule' unloaded

1 stacks with outstanding allocations:
128 bytes in 1 allocations from stack
        addr = 0xffff0000cb2c1500 size = 128
          0 [<ffff80008038567c>] __traceiter_kmalloc+0x74
          1 [<ffff80008038567c>] __traceiter_kmalloc+0x74
          2 [<ffff8000803f5d68>] __kmalloc_cache_noprof+0x338
          3 [<ffff80007c44403c>] mymodule_init+0x34
          ...
done
```

The repository includes a couple sample modules for testing under the `mod`
directory.

### Installation

To install `kmodleak` to `/usr/local/bin`:

```shell
$ cd src
$ make
$ sudo make install
```

Set `PREFIX` to install somewhere else, e.g. `make install PREFIX=~/.local`.
`make uninstall` removes the installed binary.

## Troubleshooting

libbpf debug logs are quite helpful to pinpoint the exact source of problems,
so it's usually a good idea to look at them before starting to debug or
posting question online.

For `./kmodleak`, run it in verbose mode (`-v`) to see libbpf debug logs:

```console
$ sudo ./kmodleak -v leak
using page size: 4096
libbpf: loading object 'kmodleak_bpf' from buffer
libbpf: elf: section(2) .symtab, size 2208, link 1, flags 0, type=2
libbpf: elf: section(3) .text, size 1544, link 0, flags 6, type=1
libbpf: sec '.text': found program 'called_from_module' at insn offset 0 (0 bytes), code size 84 insns (672 bytes)
libbpf: sec '.text': found program 'record_alloc' at insn offset 84 (672 bytes), code size 109 insns (872 bytes)
libbpf: elf: section(4) raw_tracepoint/module_load, size 1104, link 0, flags 6, type=1
libbpf: sec 'raw_tracepoint/module_load': found program 'kmodleak__module_load' at insn offset 0 (0 bytes), code size 138 insns (1104 bytes)
libbpf: elf: section(5) kretprobe/load_module, size 208, link 0, flags 6, type=1
...
```
