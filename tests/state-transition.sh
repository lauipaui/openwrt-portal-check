#!/bin/sh
set -eu
if [ "$#" -eq 0 ]; then
 sh "$0" auth-failed
 sh "$0" accepted-offline
 echo 'PASS verified migration enters online state without failure backoff/re-auth'
 exit 0
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
export PORTAL_BASE_DIR="$work"
sed '/^case "${1:-run}" in/,$d; /^trap /d' "$root/router/portal_auto_auth.with-damod.sh" > "$work/functions.sh"
. "$work/functions.sh"
check_files(){ return 0; }
check_probe_tool(){ return 0; }
acquire_lock(){ return 0; }
release_lock(){ rm -rf "$runtime_dir" "$work"; }
session_available(){ return 1; }
refresh_wan_ip(){ return 1; }
verify_online_with_retries(){ return 1; }
read_keep_interval(){ echo 120; }
check_portal_configuration(){ return 0; }
log_message(){ :; }
case "$1" in
 auth-failed) authenticate(){ return 1; } ;;
 accepted-offline) authenticate(){ return 0; } ;;
esac
sleep_for(){
 [ "$need_auth" -eq 0 ] && [ "$consecutive_failures" -eq 0 ] && [ "$next_keep" -gt "$(date +%s)" ] && [ "$1" -eq "$probe_interval" ] || {
  echo "FAIL state: auth=$need_auth failures=$consecutive_failures next=$next_keep sleep=$1"; exit 1;
 }
 exit 0
}
consecutive_failures=3
run_loop
