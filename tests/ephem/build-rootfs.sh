#!/bin/sh
# Build a new dedicated fixture root; never use an application/host root here.
set -eu
if [ "$(uname -s)" != Linux ]; then
    echo 'UNAVAILABLE: this fixture requires Linux' >&2
    exit 77
fi
if [ "$#" -ne 1 ]; then
    echo 'usage: build-rootfs.sh NEW_ABSOLUTE_ROOTFS_DIRECTORY' >&2
    exit 64
fi
ephem_fixture_root=$1
case "$ephem_fixture_root" in
    /*) ;;
    *) echo 'rootfs path must be absolute' >&2; exit 64 ;;
esac
case "$ephem_fixture_root" in
    /|*/../*|*/..|*/./*|*/.) echo 'unsafe rootfs path' >&2; exit 64 ;;
esac
if [ -e "$ephem_fixture_root" ] || [ -L "$ephem_fixture_root" ]; then
    echo 'rootfs path must not exist' >&2
    exit 64
fi
ephem_fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ephem_fixture_cc=${CC:-cc}
if ! command -v "$ephem_fixture_cc" >/dev/null 2>&1; then
    echo 'UNAVAILABLE: a Linux C compiler with static libc is required' >&2
    exit 77
fi
umask 022
mkdir -m 0755 -- "$ephem_fixture_root"
mkdir -m 1777 -- "$ephem_fixture_root/tmp"
mkdir -m 0755 -- "$ephem_fixture_root/app"
printf 'unchanged test sentinel\n' > "$ephem_fixture_root/app/sentinel"
chmod 0444 "$ephem_fixture_root/app/sentinel"
printf 'SYNTHETIC_SECRET_VISIBLE_TO_WORKER\n' > "$ephem_fixture_root/app/fixture-secret"
chmod 0444 "$ephem_fixture_root/app/fixture-secret"
if ! "$ephem_fixture_cc" -O2 -Wall -Wextra -Werror -static -fno-pie -no-pie \
    "$ephem_fixture_dir/fixture.c" -o "$ephem_fixture_root/worker"; then
    echo 'UNAVAILABLE: building the static Linux fixture failed; incomplete root retained' >&2
    exit 77
fi
chmod 0555 "$ephem_fixture_root/worker" "$ephem_fixture_root/app"
printf 'ephem-test-rootfs-v1\n' > "$ephem_fixture_root/.ephem-test-rootfs"
printf '%s\n' "$ephem_fixture_root"
