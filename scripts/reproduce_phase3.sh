#!/usr/bin/env bash
# Run only the repository's trusted fixtures in a dedicated Linux VM.
set -euo pipefail
umask 022

task_repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$task_repo"
if [[ $# -gt 1 || (${1:-} != '' && ${1:-} != '--check') ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

task_missing=()
task_privilege=()
if [[ $(uname -s) != Linux ]]; then
    task_missing+=("Linux >=5.12 on x86_64/aarch64 (detected $(uname -s)/$(uname -m))")
else
    case $(uname -m) in
        x86_64|aarch64) ;;
        *) task_missing+=("supported architecture x86_64/aarch64 (detected $(uname -m))") ;;
    esac
    for task_command in python3 cargo rustc cc mktemp tee install cat rm; do
        command -v "$task_command" >/dev/null 2>&1 || task_missing+=("$task_command")
    done
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            task_privilege=(sudo -n --)
        else
            task_missing+=("root or noninteractive sudo (authenticate with sudo -v first)")
        fi
    fi
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - <<'PY'
import platform
import re
from pathlib import Path
match = re.match(r"(\d+)\.(\d+)", platform.release())
raise SystemExit(0 if match and tuple(map(int, match.groups())) >= (5, 12) else 1)
PY
        then task_missing+=("Linux kernel >=5.12 (detected $(uname -r))"); fi
        if ! python3 - <<'PY'
from pathlib import Path
lines = Path('/proc/self/mountinfo').read_text().splitlines()
raise SystemExit(0 if any(' - cgroup2 ' in line for line in lines) else 1)
PY
        then task_missing+=("mounted cgroup v2 hierarchy"); fi
        [[ -r /proc/self/status && -r /proc/self/fdinfo/0 ]] || task_missing+=("mounted readable procfs")
    fi
    task_php_config=${PHP_CONFIG:-php-config8.3}
    if ! command -v "$task_php_config" >/dev/null 2>&1; then
        task_missing+=("PHP 8.3 NTS embed development headers/config ($task_php_config)")
    elif command -v cc >/dev/null 2>&1 && command -v mktemp >/dev/null 2>&1 \
        && command -v cat >/dev/null 2>&1 && command -v rm >/dev/null 2>&1; then
        task_probe=$(mktemp -d /tmp/ephem-prereq.XXXXXXXX)
        trap 'rm -rf -- "$task_probe"' EXIT
        if ! "$task_php_config" --includes > "$task_probe/includes"; then
            task_missing+=("working $task_php_config --includes")
        else
            read -r -a task_php_includes < "$task_probe/includes"
            cat > "$task_probe/embed.c" <<'C'
#include <php.h>
#include <sapi/embed/php_embed.h>
#if PHP_VERSION_ID < 80300 || PHP_VERSION_ID >= 80400 || defined(ZTS)
#error PHP_8_3_NTS_embed_required
#endif
int main(int argc, char **argv) { return php_embed_init(argc, argv); }
C
            if ! cc "${task_php_includes[@]}" "$task_probe/embed.c" -lphp8.3 -o "$task_probe/embed" > "$task_probe/compile.log" 2>&1; then
                task_missing+=("linkable libphp8.3 embed and PHP 8.3 NTS headers (cc -lphp8.3 failed)")
                cat "$task_probe/compile.log" >&2
            fi
        fi
        rm -rf -- "$task_probe"
        trap - EXIT
    fi
fi
if [[ ${#task_missing[@]} -gt 0 ]]; then
    printf 'UNRUN (exit 77): missing prerequisites:\n' >&2
    printf ' - %s\n' "${task_missing[@]}" >&2
    exit 77
fi
if [[ ${1:-} == --check ]]; then
    echo 'Prerequisites available; namespace/mount/seccomp permission is validated at runtime.'
    exit 0
fi

for task_input in reports/phase3/VALIDATION.json tests/test_stateful_isolation.py \
    scripts/verify_phase3_run.py runtime/phase3/build-php-adapter.sh; do
    if [[ ! -f "$task_input" || ! -r "$task_input" ]]; then
        printf 'FAIL: incomplete checkout; required file missing/unreadable: %s\n' "$task_input" >&2
        exit 1
    fi
done

# Fresh, private output paths prevent replacement of retained evidence or /tmp symlinks.
task_run=$(mktemp -d /tmp/ephem-phase3.XXXXXXXX)
task_native_root="$task_run/native-root"
echo "Run evidence: $task_run"
trap 'task_rc=$?; if [[ $task_rc -ne 0 ]]; then printf "Verification incomplete (exit %s); evidence retained: %s\n" "$task_rc" "$task_run" >&2; fi' EXIT

cargo test --locked --workspace 2>&1 | tee "$task_run/cargo-test.log"
cargo build --locked --release --workspace 2>&1 | tee "$task_run/cargo-build-workspace.log"
# Match the measured feature set after the workspace feature-unified build.
cargo build --locked --release -p ephem-stateful -p ephem-warm-pool 2>&1 | tee "$task_run/cargo-build-deliverable.log"
PHP_CONFIG="$task_php_config" sh runtime/phase3/build-php-adapter.sh 2>&1 | tee "$task_run/php-adapter-build.log"

# A fresh root-owned parent also keeps UDS paths private while the harness runs.
"${task_privilege[@]}" install -d -m 0755 -o root -g root "$task_native_root"
"${task_privilege[@]}" python3 tests/test_stateful_isolation.py --require-p95 \
    --output "$task_run/stateful-verification.json" 2>&1 | tee "$task_run/stateful.log"
"${task_privilege[@]}" ./target/release/ephem-warm-pool --root "$task_native_root" \
    --iterations 1000 --warmup 100 --lifecycle-check --require-p95-ms 2 \
    2> "$task_run/warm-native.stderr.log" \
    | tee "$task_run/warm-native.json"
python3 scripts/verify_phase3_run.py --reference reports/phase3/VALIDATION.json \
    --stateful "$task_run/stateful-verification.json" --native "$task_run/warm-native.json" \
    | tee "$task_run/comparison.txt"
printf 'Evidence retained: %s\n' "$task_run"
