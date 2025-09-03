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
$ sudo ./kmodleak leak  # Module is loaded and unloaded by the user (not shown)
using page size: 4096
Tracing module memory allocs... Unload module (or hit Ctrl-C) to end
module 'leak' loaded
module 'leak' unloaded

1 stacks with outstanding allocations:
128 bytes in 1 allocations from stack
        addr = 0xffff00008ba60f00 size = 128
          0 [<ffff80000834df84>] kmalloc_trace+0xf0
          1 [<ffff80000834df84>] kmalloc_trace+0xf0
          2 [<ffff800032f2f060>] leak_init+0x34
          3 [<ffff800008074dd0>] do_one_initcall+0x60
          4 [<ffff8000081b3404>] do_init_module+0x50
          5 [<ffff8000081b5458>] load_module+0x1cb8
          6 [<ffff8000081b5c7c>] __do_sys_finit_module+0xac
          7 [<ffff8000081b5d88>] __arm64_sys_finit_module+0x28
          8 [<ffff800008089bd8>] invoke_syscall+0x78
          9 [<ffff800008089cac>] el0_svc_common.constprop.0+0x4c
         10 [<ffff800008089d88>] do_el0_svc+0x34
         11 [<ffff800008d03794>] el0_svc+0x34
         12 [<ffff800008d04cd4>] el0t_64_sync_handler+0xf4
         13 [<ffff800008071548>] el0t_64_sync+0x18c
done
```

## Usage

`kmodleak` monitors kernel module memory allocations and detects leaks. The typical workflow is:

1. **Start kmodleak** - Run `kmodleak` with the module name you want to monitor
2. **Load the module** - In another terminal, load your kernel module with `insmod`
3. **Use the module** - Exercise your module's functionality  
4. **Unload the module** - Remove the module with `rmmod`
5. **View results** - `kmodleak` automatically exits and shows any detected leaks

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
        addr = 0xffff00008ba60f00 size = 128
          0 [<ffff80000834df84>] kmalloc_trace+0xf0
          1 [<ffff80000834df84>] kmalloc_trace+0xf0
          2 [<ffff800032f2f060>] mymodule_init+0x34
          ...
done
```

The repository includes a couple sample modules for testing under the `mod`
directory.

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
