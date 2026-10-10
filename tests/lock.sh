#!/bin/sh
# Single-instance lock: lives on tmpfs, survives only while its holder is really
# a portal_auto_auth process, and is never blocked by a recycled PID.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
bg=''
cleanup(){ [ -z "$bg" ] || kill $bg 2>/dev/null || :; rm -rf "$work"; }
trap cleanup EXIT
mkdir "$work/run" "$work/base"
export PORTAL_BASE_DIR="$work/base"
export PORTAL_LOCK_ROOT="$work/run"
sed '/^case "${1:-run}" in/,$d; /^trap /d' "$root/router/portal_auto_auth.with-damod.sh" > "$work/functions.sh"
. "$work/functions.sh"
trap 'rm -rf "$runtime_dir"; cleanup' EXIT
log_message(){ printf '%s\n' "$*" >> "$work/log"; }
fail(){ echo "FAIL lock: $1"; exit 1; }
reset_lock(){ rm -rf "$lock_dir"; : > "$work/log"; }

[ "$lock_dir" = "$work/run/portal-auto-auth.lock" ] || fail "lock not under PORTAL_LOCK_ROOT: $lock_dir"

# 1. fresh acquire records our PID
reset_lock
acquire_lock || fail 'fresh acquire'
[ "$(cat "$lock_pid_file")" = "$$" ] || fail 'pid file not ours'

# 2. dead holder is reclaimed
reset_lock
true & dead=$!; wait "$dead" 2>/dev/null || :
mkdir "$lock_dir"; printf '%s\n' "$dead" > "$lock_pid_file"
acquire_lock || fail 'dead holder not reclaimed'
grep -q 'stale' "$work/log" || fail 'stale reclaim not logged'

# 3. our own PID in the file is stale by definition
reset_lock
mkdir "$lock_dir"; printf '%s\n' "$$" > "$lock_pid_file"
acquire_lock || fail 'own pid must not block'

# 4. a live portal_auto_auth process holds the lock
printf '#!/bin/sh\nsleep 60\n' > "$work/portal_auto_auth.sh"
sh "$work/portal_auto_auth.sh" & holder=$!
bg="$holder"
sleep 1
reset_lock
mkdir "$lock_dir"; printf '%s\n' "$holder" > "$lock_pid_file"
if acquire_lock; then fail 'live portal_auto_auth holder must block a second instance'; fi
grep -q "already running with PID $holder" "$work/log" || fail 'holder refusal not logged'

# 5. a recycled PID (live, but an unrelated process) must not block startup
if [ -r "/proc/$$/cmdline" ]; then
 sleep 60 & other=$!
 bg="$bg $other"
 reset_lock
 mkdir "$lock_dir"; printf '%s\n' "$other" > "$lock_pid_file"
 acquire_lock || fail 'unrelated live PID blocked startup'
 skipped=''
else
 skipped=' (recycled-PID case skipped: no /proc)'
fi

# 6. unusable lock root falls back to the base directory
(
 PORTAL_LOCK_ROOT="$work/does-not-exist"
 sed '/^case "${1:-run}" in/,$d; /^trap /d' "$root/router/portal_auto_auth.with-damod.sh" > "$work/functions2.sh"
 . "$work/functions2.sh"
 trap 'rm -rf "$runtime_dir"' EXIT
 [ "$lock_dir" = "$work/base/portal-auto-auth.lock" ] || { echo "FAIL lock: fallback dir $lock_dir"; exit 1; }
)
echo "PASS lock: tmpfs path, stale/dead/own PID reclaimed, live holder blocks, recycled PID ignored, base_dir fallback$skipped"
