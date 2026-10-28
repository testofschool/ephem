#!/bin/sh
# diagnose.sh — READ-ONLY PHP2Shell exposure check. Run it on YOUR OWN server.
# It changes nothing: it reads your PHP version and config, and greps your code
# for session.upload_progress usage so you know what turning the mitigation on
# would break. No network, no writes, no patching. Review output, then act yourself.
#
# Usage:  sh diagnose.sh [CODE_DIR]     (CODE_DIR defaults to the current directory)
set -eu
CODE_DIR="${1:-.}"
PHP_BIN="${PHP_BIN:-php}"

echo "== PHP2Shell read-only self-diagnosis =="
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)   code_dir: $CODE_DIR"

# 1. PHP version and branch support status (CVE-2026-109618 / -109619)
if ! command -v "$PHP_BIN" >/dev/null 2>&1; then
    echo "php: NOT FOUND on PATH (set PHP_BIN=/path/to/php). Cannot assess version." ; exit 0
fi
VER=$("$PHP_BIN" -r 'echo PHP_VERSION;')
MAJMIN=$("$PHP_BIN" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "php_version: $VER"
case "$MAJMIN" in
  8.5|8.4|8.3) echo "branch_status: supported — official fix exists; update to the latest patch release." ;;
  8.2)        echo "branch_status: security-only until 2026-12-31 — patched (8.2.35+), but plan to move to 8.3+." ;;
  8.1|8.0|7.4|7.3|7.2|7.1|7.0|5.6|5.5|5.4|5.3|5.2)
              echo "branch_status: END-OF-LIFE — PHP.net ships NO official build for this branch. A distro backport, a paid LTS, or migration is required." ;;
  *)          echo "branch_status: UNKNOWN branch ($MAJMIN) — verify manually." ;;
esac

# 2. Is the attack-surface feature on? (read-only: ini value only)
UP=$("$PHP_BIN" -r 'echo ini_get("session.upload_progress.enabled") ? "1" : "0";')
if [ "$UP" = "1" ]; then
  echo "session.upload_progress.enabled: 1 (ON — default). KISA/PHP suggest setting it to 0 in php.ini or the FPM pool if the feature is unused, then restarting PHP workers."
else
  echo "session.upload_progress.enabled: 0 (already off)."
fi

# 3. What would turning it off break? Grep code for actual use (read-only).
echo "-- code use of session upload progress (so you know what disabling it affects) --"
HITS=$(grep -R -n -I -l -e 'upload_progress' -e 'session.upload_progress' "$CODE_DIR" 2>/dev/null || true)
if [ -n "$HITS" ]; then
  echo "status: USED — disabling the feature will affect these files; review before you turn it off:"
  echo "$HITS" | sed 's/^/  /'
else
  echo "status: not referenced in $CODE_DIR — disabling it is unlikely to change your app's behaviour (still verify any framework/plugin code outside this dir)."
fi
echo "== end. This report changed nothing. Apply fixes yourself after review. =="
