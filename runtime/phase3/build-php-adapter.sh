#!/bin/sh
set -eu
task_config=${PHP_CONFIG:-php-config8.3}
task_output=${1:-target/phase3/libephem_php.so}
mkdir -p "$(dirname "$task_output")"
# shellcheck disable=SC2046
cc -std=c11 -O2 -fPIC -shared -Wall -Wextra -Werror \
  $("$task_config" --includes) runtime/phase3/embed.c -lphp8.3 -o "$task_output"
