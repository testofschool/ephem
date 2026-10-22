#!/bin/sh
# Privileged, read-only fresh-execution profile. No image mutation or rebuild.
set -eu

ephem_die() { printf 'ephem entrypoint: %s\n' "$*" >&2; exit 64; }
ephem_path() {
    case "$1" in
        /*) ;;
        *) ephem_die "$2 must be absolute" ;;
    esac
    case "$1" in
        *[!a-zA-Z0-9_./-]*|*/../*|*/..|*/./*|*/.|*//*) ephem_die "$2 must be a simple canonical path" ;;
    esac
}
ephem_owned() {
    [ "$(stat -c '%u' -- "$1")" = 0 ] || ephem_die "$2 must be root-owned"
    ephem_mode=$(stat -c '%a' -- "$1")
    [ "$((0$ephem_mode & 0022))" = 0 ] || ephem_die "$2 must not be group/world writable"
}
ephem_ancestry() {
    ephem_ancestor=$1
    while :; do
        ephem_owned "$ephem_ancestor" "$2"
        [ "$ephem_ancestor" != / ] || break
        ephem_ancestor=${ephem_ancestor%/*}
        [ -n "$ephem_ancestor" ] || ephem_ancestor=/
    done
}

[ "$(uname -s)" = Linux ] || ephem_die 'Linux is required'
[ "$(id -u)" = 0 ] || ephem_die 'the experimental namespace launcher requires root'
: "${EPHEM_SOCKET:?EPHEM_SOCKET is required}"
: "${EPHEM_JAIL:?EPHEM_JAIL is required}"
: "${EPHEM_ROOT:?EPHEM_ROOT is required}"
: "${EPHEM_WORKER:?EPHEM_WORKER is required}"
: "${EPHEM_CGROUP_ROOT:?EPHEM_CGROUP_ROOT is required}"
ephem_gate=${EPHEM_GATE:-/opt/ephem/bin/ephem-gate}

for ephem_tool in stat readlink find awk; do
    command -v "$ephem_tool" >/dev/null 2>&1 || ephem_die "required tool unavailable: $ephem_tool"
done
ephem_path "$EPHEM_SOCKET" EPHEM_SOCKET
ephem_path "$EPHEM_JAIL" EPHEM_JAIL
ephem_path "$EPHEM_ROOT" EPHEM_ROOT
ephem_path "$EPHEM_WORKER" EPHEM_WORKER
ephem_path "$ephem_gate" EPHEM_GATE
[ "$EPHEM_ROOT" != / ] || ephem_die 'host root cannot be a worker rootfs'
[ "$EPHEM_WORKER" != / ] || ephem_die 'worker must name an executable'

for ephem_binary in "$ephem_gate" "$EPHEM_JAIL"; do
    [ -f "$ephem_binary" ] && [ -x "$ephem_binary" ] && [ ! -L "$ephem_binary" ] || ephem_die 'gate and jail must be regular executable files'
    [ "$(readlink -f -- "$ephem_binary")" = "$ephem_binary" ] || ephem_die 'binary path contains a symlink'
    ephem_ancestry "$ephem_binary" 'binary ancestry'
done
[ -d "$EPHEM_ROOT" ] && [ ! -L "$EPHEM_ROOT" ] || ephem_die 'rootfs must be a real directory'
[ "$(readlink -f -- "$EPHEM_ROOT")" = "$EPHEM_ROOT" ] || ephem_die 'rootfs path contains a symlink'
ephem_ancestry "$EPHEM_ROOT" 'rootfs ancestry'
ephem_symlink=$(find -P "$EPHEM_ROOT" -type l -printf x -quit) || ephem_die 'cannot inspect rootfs'
[ -z "$ephem_symlink" ] || ephem_die 'symlinks in rootfs are unsupported'
[ -r /proc/self/mountinfo ] || ephem_die 'mountinfo is required'
ephem_mount=$(awk -v prefix="$EPHEM_ROOT/" 'index($5, prefix) == 1 {print "x"; exit}' /proc/self/mountinfo) || ephem_die 'cannot inspect mounts'
[ -z "$ephem_mount" ] || ephem_die 'nested rootfs mounts are unsupported'
[ -f "$EPHEM_ROOT$EPHEM_WORKER" ] && [ -x "$EPHEM_ROOT$EPHEM_WORKER" ] || ephem_die 'worker missing from rootfs'
ephem_ancestry "$EPHEM_ROOT$EPHEM_WORKER" 'worker ancestry'

ephem_socket_parent=${EPHEM_SOCKET%/*}
[ -n "$ephem_socket_parent" ] || ephem_socket_parent=/
[ -d "$ephem_socket_parent" ] && [ ! -L "$ephem_socket_parent" ] || ephem_die 'socket parent must exist as a real directory'
[ "$(readlink -f -- "$ephem_socket_parent")" = "$ephem_socket_parent" ] || ephem_die 'socket parent contains a symlink'
ephem_ancestry "$ephem_socket_parent" 'socket directory ancestry'
[ ! -e "$EPHEM_SOCKET" ] && [ ! -L "$EPHEM_SOCKET" ] || ephem_die 'socket path already exists'

# Optional gate flags precede `--`; arguments after `--` go to the worker.
# No shell evaluation or automatic deletion of an existing socket occurs.
exec "$ephem_gate" --socket "$EPHEM_SOCKET" --jail "$EPHEM_JAIL" \
    --root "$EPHEM_ROOT" --worker "$EPHEM_WORKER" --cgroup-root "$EPHEM_CGROUP_ROOT" "$@"
