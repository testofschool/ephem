#!/bin/sh
# Named strict profile: an absent identity policy can never fall back to legacy.
set -eu
: "${EPHEM_ROOT_MANIFEST:?EPHEM_ROOT_MANIFEST is mandatory for the zero profile}"
ephem_bundle=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec "$ephem_bundle/entrypoint.sh" --root-manifest "$EPHEM_ROOT_MANIFEST" "$@"
