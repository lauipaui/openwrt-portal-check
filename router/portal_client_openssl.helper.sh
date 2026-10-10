#!/bin/sh
# Safe compatibility entry point: configuration is DATA, never sourced/evaluated.
# Crypto/XML/HTTP are implemented by the bounded cipher-helper client command.
# The old incomplete nc transport and shared /tmp diagnostics are removed.
set -eu
umask 077
export PORTAL_TIME_OFFSET="$(date +%z)"
config_file=${1:-portal.conf}
mode=${2:-auth}
helper_bin=${PORTAL_CIPHER_HELPER:-/root/portal/cipher-helper}
export GOMEMLIMIT=${GOMEMLIMIT:-6MiB}
[ -x "$helper_bin" ] || { echo 'A current cipher-helper is required; no unsafe legacy fallback is used.' >&2; exit 2; }
if [ "$mode" = auth ]; then
    if [ -z "${PORTAL_USER:-}" ]; then
        printf 'Portal account: ' >&2
        IFS= read -r PORTAL_USER
    fi
    if [ -z "${PORTAL_PASSWORD:-}" ]; then
        printf 'Portal password: ' >&2
        IFS= read -r -s PORTAL_PASSWORD
        printf '\n' >&2
    fi
    export PORTAL_USER PORTAL_PASSWORD
fi
exec "$helper_bin" client "$config_file" "$mode"
