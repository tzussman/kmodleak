#!/bin/sh

# Dump a vmlinux.h from the running kernel's BTF, or from the BTF file given
# as the first argument, using the bpftool built by src/Makefile.

BPFTOOL=${BPFTOOL:-$(dirname "$0")/../src/.output/bpftool/bootstrap/bpftool}

if [ ! -x "$BPFTOOL" ]; then
	echo "$0: $BPFTOOL not found; run make in src/ first or set BPFTOOL" >&2
	exit 1
fi

exec "$BPFTOOL" btf dump file "${1:-/sys/kernel/btf/vmlinux}" format c
