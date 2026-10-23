#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ] || [ "$#" -ne 1 ]; then
    echo "usage (Linux only): $0 ABSOLUTE_OUTPUT_DIRECTORY" >&2
    exit 2
fi
case "$1" in
    /*) task_output=$1 ;;
    *) echo 'output directory must be absolute' >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64) task_arch=x86 ;;
    aarch64) task_arch=arm64 ;;
    *) echo 'supported hosts: Linux x86_64 or aarch64' >&2; exit 2 ;;
esac
task_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
task_multiarch=$(cc -dumpmachine)
mkdir -p "$task_output"
# pkg-config values come from the trusted system libbpf installation.
# shellcheck disable=SC2046
clang -O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_"$task_arch" \
    -I"/usr/include/$task_multiarch" $(pkg-config --cflags libbpf) \
    -Wall -Werror -c "$task_source/warm_containment.bpf.c" \
    -o "$task_output/warm_containment.bpf.o"
# shellcheck disable=SC2046
cc -O2 -g -std=c11 -Wall -Wextra -Werror \
    $(pkg-config --cflags libbpf) "$task_source/warm_containment_test.c" \
    $(pkg-config --libs libbpf) -o "$task_output/warm-containment-test"
echo "Built $task_output/warm_containment.bpf.o and warm-containment-test"
