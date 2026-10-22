#!/bin/sh
# Explicit administrator action for a NEW, empty cgroup v2 subtree.
# Never changes host sysctls, enables swap, moves processes, or reuses a subtree.
set -eu
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 64; }
[ "$#" = 1 ] || { echo 'usage: prepare-cgroup.sh /sys/fs/cgroup/NEW_NAME' >&2; exit 64; }
ephem_group=$1
case "$ephem_group" in
  /sys/fs/cgroup/*) ;;
  *) echo 'use a new direct child of /sys/fs/cgroup' >&2; exit 64 ;;
esac
ephem_name=${ephem_group#/sys/fs/cgroup/}
case "$ephem_name" in
  ''|*[!A-Za-z0-9_-]*) echo 'invalid cgroup name' >&2; exit 64 ;;
esac
[ ! -e "$ephem_group" ] || { echo 'existing cgroup refused' >&2; exit 64; }
for ephem_controller in cpu memory pids; do
  case " $(cat /sys/fs/cgroup/cgroup.subtree_control) " in
    *" $ephem_controller "*) ;;
    *) echo "root cgroup must already delegate $ephem_controller (see docs/OPERATIONS.md)" >&2; exit 64 ;;
  esac
done
mkdir -- "$ephem_group"
# Bound all request launchers/workers together, excluding the trusted gate.
printf '536870912\n' > "$ephem_group/memory.max"
printf '0\n' > "$ephem_group/memory.swap.max"
printf '16\n' > "$ephem_group/pids.max"
printf '200000 100000\n' > "$ephem_group/cpu.max"
printf '+cpu +memory +pids\n' > "$ephem_group/cgroup.subtree_control"
printf '%s\n' "$ephem_group"
