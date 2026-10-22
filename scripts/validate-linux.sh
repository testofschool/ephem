#!/bin/sh
# Dedicated Linux test machine only. Never changes host swap/core sysctls.
set -eu
[ "$(id -u)" = 0 ] || { echo 'dedicated Linux root test environment required' >&2; exit 77; }
[ "$#" = 1 ] || { echo 'usage: validate-linux.sh NEW_REPORT_DIRECTORY' >&2; exit 64; }
ephem_report=$1
[ ! -e "$ephem_report" ] || { echo 'preserve existing evidence' >&2; exit 64; }
mkdir -p -- "$ephem_report"
ephem_bundle=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ephem_bundle"
ephem_cgroup=/sys/fs/cgroup/ephem-test-$$
sh packaging/prepare-cgroup.sh "$ephem_cgroup"
trap 'rmdir -- "$ephem_cgroup" || true' EXIT
python3 tests/test_ephemeral_lifecycle.py --cgroup-root "$ephem_cgroup" \
  --report "$ephem_report/lifecycle.json" > "$ephem_report/lifecycle.stdout" 2> "$ephem_report/lifecycle.stderr"
python3 tests/ephem/audit_probes.py --gate "$ephem_bundle/target/release/ephem-gate" \
  --jail "$ephem_bundle/target/ephem-jail" --cgroup-root "$ephem_cgroup" \
  --report "$ephem_report/boundaries.json" > "$ephem_report/boundaries.stdout" 2> "$ephem_report/boundaries.stderr"
python3 tests/ephem/seccomp_policy_probes.py --report "$ephem_report/seccomp.json" \
  > "$ephem_report/seccomp.stdout" 2> "$ephem_report/seccomp.stderr"
python3 tests/test_fail_closed.py --gate "$ephem_bundle/target/release/ephem-gate" \
  --jail "$ephem_bundle/target/ephem-jail" --report "$ephem_report/preflight.json"
python3 tests/ephem/parent_race.py --jail "$ephem_bundle/target/ephem-jail" \
  --report "$ephem_report/parent-race.json"
echo 'Linux integration checks completed. Read reports; this is not production approval.'
