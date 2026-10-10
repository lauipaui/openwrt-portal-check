#!/bin/sh
# portal-watchdog: restarts only an enabled service that procd no longer runs,
# respects the cooldown and the pause file, and never revives a disabled one.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
wd="$root/router/portal-watchdog"
cat > "$work/init" <<'EOF'
#!/bin/sh
d=$(dirname "$0")
case "$1" in
 enabled) [ ! -e "$d/not-enabled" ] ;;
 running) [ -e "$d/up" ] ;;
 restart) echo restart >> "$d/calls"; [ ! -e "$d/restart-fails" ] || exit 1; : > "$d/up" ;;
esac
EOF
chmod 700 "$work/init"
export WATCHDOG_INIT="$work/init" WATCHDOG_STAMP="$work/stamp" WATCHDOG_DISABLE_FILE="$work/disabled" WATCHDOG_COOLDOWN_SECONDS=600
fail(){ echo "FAIL watchdog: $1"; exit 1; }
calls(){ if [ -e "$work/calls" ]; then wc -l < "$work/calls" | tr -d ' '; else echo 0; fi; }
run(){ sh "$wd" >"$work/out" 2>&1; }

# 1. healthy service: no action, no stamp
: > "$work/up"
run || fail 'healthy run must succeed'
[ "$(calls)" -eq 0 ] || fail 'healthy service restarted'
[ ! -e "$work/stamp" ] || fail 'stamp written for healthy service'

# 2. procd gave up: restart once, stamp written, logged
rm -f "$work/up"
run || fail 'restart run must succeed'
[ "$(calls)" -eq 1 ] || fail "expected 1 restart, got $(calls)"
[ -e "$work/up" ] || fail 'service not up after restart'
[ -s "$work/stamp" ] || fail 'stamp missing'
grep -q 'not running; restarting' "$work/out" || fail 'restart not logged'

# 3. dies again inside the cooldown: left alone
rm -f "$work/up"
run || fail 'cooldown run must succeed'
[ "$(calls)" -eq 1 ] || fail 'restarted during cooldown'

# 4. cooldown elapsed: restarted again
WATCHDOG_COOLDOWN_SECONDS=0 run || fail 'post-cooldown run'
[ "$(calls)" -eq 2 ] || fail 'not restarted after cooldown'

# 5. pause file honoured
rm -f "$work/up" "$work/stamp"; : > "$work/disabled"
run || fail 'paused run'
[ "$(calls)" -eq 2 ] || fail 'restarted while paused'
rm -f "$work/disabled"

# 6. disabled service stays down
: > "$work/not-enabled"
run || fail 'not-enabled run'
[ "$(calls)" -eq 2 ] || fail 'revived a disabled service'
rm -f "$work/not-enabled"

# 7. a stamp from the future (clock step) must not block forever
printf '%s\n' "9999999999" > "$work/stamp"
run || fail 'future-stamp run'
[ "$(calls)" -eq 3 ] || fail 'future stamp blocked the watchdog'

# 8. failed restart is reported with a non-zero exit
rm -f "$work/up" "$work/stamp"; : > "$work/restart-fails"
if run; then fail 'failed restart must exit non-zero'; fi
grep -q 'Restart of .* failed' "$work/out" || fail 'failure not logged'

# 9. garbage stamp and garbage cooldown are tolerated
rm -f "$work/restart-fails" "$work/up"; printf 'junk\n' > "$work/stamp"
WATCHDOG_COOLDOWN_SECONDS=abc run || fail 'garbage input run'
[ -e "$work/up" ] || fail 'garbage stamp blocked restart'
echo 'PASS watchdog: restart when procd gave up, cooldown, pause file, disabled service, clock step, failure exit, bad input'
