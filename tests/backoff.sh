#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export PORTAL_BASE_DIR="$work"
sed '/^case "${1:-run}" in/,$d; /^trap /d' "$root/router/portal_auto_auth.with-damod.sh" > "$work/functions.sh"
. "$work/functions.sh"
trap 'rm -rf "$runtime_dir" "$work"' EXIT
log_message(){ :; }
refresh_portal_endpoints(){ return 1; }
detect_portal_algorithm(){ return 1; }
# The real configuration-check caller must not reset failures on no update.
consecutive_failures=0
actual=''
for n in 1 2 3 4; do
 if check_portal_configuration; then consecutive_failures=0; fi
 consecutive_failures=$((consecutive_failures+1))
 actual="$actual $(current_retry_delay)"
done
[ "$actual" = ' 60 120 240 300' ] || { echo "FAIL backoff:$actual"; exit 1; }
refresh_portal_endpoints(){ return 0; }
check_portal_configuration || { echo 'FAIL applied change status'; exit 1; }
detect_portal_algorithm(){ return 0; }
refresh_portal_endpoints(){ return 1; }
check_portal_configuration || { echo 'FAIL algorithm activation status'; exit 1; }
echo 'PASS shell backoff and configuration update status'
