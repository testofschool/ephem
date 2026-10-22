#!/bin/sh
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'ephem-jail must be built on Linux with Linux development headers' >&2
    exit 1
fi
bundle_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
output_path=${1:-"$bundle_dir/target/ephem-jail"}
mkdir -p -- "$(dirname -- "$output_path")"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -Wshadow -Wformat=2 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie \
    -Wl,-z,relro,-z,now,-z,noexecstack \
    -I"$bundle_dir/bpf" \
    "$bundle_dir/crates/ephem-jail/main.c" \
    "$bundle_dir/bpf/worker_containment.bpf.c" \
    -o "$output_path"
printf '%s\n' "$output_path"
