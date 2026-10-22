#!/bin/sh
# Build only the verified official security release in new owned VM directories.
set -eu
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ] || [ "$#" -ne 4 ]; then
    echo 'usage (Linux root): build-patched-php.sh SOURCE_TAR NEW_BUILD_DIR NEW_PREFIX NEW_REPORT_DIR' >&2
    exit 64
fi
ephem_php_tar=$1
ephem_php_build=$2
ephem_php_prefix=$3
ephem_php_report=$4
for ephem_php_new in "$ephem_php_build" "$ephem_php_prefix" "$ephem_php_report"; do
    case "$ephem_php_new" in
        /*) ;;
        *) echo 'new paths must be absolute' >&2; exit 64 ;;
    esac
    if [ -e "$ephem_php_new" ] || [ -L "$ephem_php_new" ]; then
        echo 'refusing to overwrite an existing build, prefix or report directory' >&2
        exit 64
    fi
done
ephem_php_expected=c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53
ephem_php_actual=$(sha256sum "$ephem_php_tar")
ephem_php_actual=${ephem_php_actual%% *}
if [ "$ephem_php_actual" != "$ephem_php_expected" ]; then
    echo 'official PHP security release source hash mismatch' >&2
    exit 65
fi
umask 022
mkdir -m 0755 -- "$ephem_php_build" "$ephem_php_report"
tar -xzf "$ephem_php_tar" -C "$ephem_php_build" --strip-components=1
cd "$ephem_php_build"
printf '%s\n' "$ephem_php_actual" > "$ephem_php_report/source.sha256"
printf '%s\n' '--disable-all --enable-cgi --disable-cli --without-pear' > "$ephem_php_report/configure-options.txt"
./configure --disable-all --enable-cgi --disable-cli --without-pear \
    --prefix="$ephem_php_prefix" > "$ephem_php_report/configure.log" 2>&1
make -j4 > "$ephem_php_report/make.log" 2>&1
make install > "$ephem_php_report/install.log" 2>&1
"$ephem_php_prefix/bin/php-cgi" -n -v > "$ephem_php_report/php-version.txt"
sha256sum "$ephem_php_prefix/bin/php-cgi" > "$ephem_php_report/php-cgi.sha256"
cat "$ephem_php_report/php-version.txt"
