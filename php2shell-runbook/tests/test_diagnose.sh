#!/bin/sh
# Frozen detector tests. Exit 0 = all pass.
set -eu
cd "$(dirname "$0")/.."
fail=0
pos=$(sh tools/diagnose.sh fixtures/pos); echo "$pos" | grep -q "status: USED" || { echo "FAIL pos"; fail=1; }
neg=$(sh tools/diagnose.sh fixtures/neg); echo "$neg" | grep -q "status: not referenced" || { echo "FAIL neg"; fail=1; }
printf '#!/bin/sh\ncase "$*" in *PHP_VERSION*)echo 7.4.33;;*MAJOR*)echo 7.4;;*enabled*)echo 1;;esac\n' > /tmp/php74t && chmod +x /tmp/php74t
eol=$(PHP_BIN=/tmp/php74t sh tools/diagnose.sh fixtures/neg); echo "$eol" | grep -q "END-OF-LIFE" || { echo "FAIL eol"; fail=1; }
[ "$fail" = 0 ] && echo "ALL PASS (3/3)" || exit 1
