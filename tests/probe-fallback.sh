#!/bin/sh
# Fallback connectivity probes: a single failing probe site must not look like a
# captive portal, while a real outage (every probe failing) still does.
set -eu
if [ "$#" -eq 0 ]; then
 for c in defaults explicit-url fallback-list recovery-log; do
  sh "$0" "$c"
 done
 echo 'PASS fallback probes: defaults, explicit URL disables defaults, list validation, recovery log'
 exit 0
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
export PORTAL_BASE_DIR="$work"
export PORTAL_LOCK_ROOT="$work"
cat > "$work/fake-helper" <<'EOF'
#!/bin/sh
[ "$1" = probe ] || exit 2
case " ${FAKE_OK_URLS:-} " in *" $2 "*) exit 0 ;; esac
exit 1
EOF
chmod 700 "$work/fake-helper"
export PORTAL_CIPHER_HELPER="$work/fake-helper"
miui=http://connect.rom.miui.com/generate_204
hicloud=http://connectivitycheck.platform.hicloud.com/generate_204
vivo=http://wifi.vivo.com.cn/generate_204
case "$1" in
 explicit-url) export PORTAL_PROBE_URL=http://primary.test/204 ;;
 fallback-list) export PORTAL_PROBE_URL=http://primary.test/204
  export PORTAL_PROBE_FALLBACK_URLS='http://b.test/204 file:///etc/passwd http://c.test/a?b=1 http://*.test ftp://e.test/x http://d.test/204' ;;
esac
sed '/^case "${1:-run}" in/,$d; /^trap /d' "$root/router/portal_auto_auth.with-damod.sh" > "$work/functions.sh"
. "$work/functions.sh"
trap 'rm -rf "$runtime_dir" "$work"' EXIT
log_message(){ printf '%s\n' "$*" >> "$work/log"; }
fail(){ echo "FAIL $1: $2"; exit 1; }
validate_delays
case "$1" in
 defaults)
  [ "$probe_url" = "$miui" ] || fail defaults "primary $probe_url"
  [ "$probe_fallback_urls" = " $hicloud $vivo" ] || fail defaults "fallbacks '$probe_fallback_urls'"
  FAKE_OK_URLS="$miui"; export FAKE_OK_URLS
  probe_online || fail defaults 'primary ok must be online'
  [ "$probe_degraded" -eq 0 ] || fail defaults 'degraded set while primary ok'
  FAKE_OK_URLS="$hicloud"; export FAKE_OK_URLS
  probe_online || fail defaults 'hicloud fallback must be online'
  [ "$probe_degraded" -eq 1 ] || fail defaults 'degraded not recorded'
  FAKE_OK_URLS="$vivo"; export FAKE_OK_URLS
  probe_online || fail defaults 'second fallback must be online'
  FAKE_OK_URLS=''; export FAKE_OK_URLS
  ! probe_online || fail defaults 'all probes failing must be offline'
  ;;
 explicit-url)
  [ -z "$probe_fallback_urls" ] || fail explicit-url "defaults leaked: '$probe_fallback_urls'"
  FAKE_OK_URLS="$hicloud $vivo $miui"; export FAKE_OK_URLS
  ! probe_online || fail explicit-url 'built-in fallback used despite explicit PORTAL_PROBE_URL'
  FAKE_OK_URLS='http://primary.test/204'; export FAKE_OK_URLS
  probe_online || fail explicit-url 'explicit primary must be online'
  ;;
 fallback-list)
  [ "$probe_fallback_urls" = ' http://b.test/204 http://d.test/204' ] || fail fallback-list "kept '$probe_fallback_urls'"
  FAKE_OK_URLS='http://d.test/204'; export FAKE_OK_URLS
  probe_online || fail fallback-list 'valid fallback must be used'
  ;;
 recovery-log)
  FAKE_OK_URLS="$hicloud"; export FAKE_OK_URLS
  probe_online; probe_online
  [ "$(grep -c 'fallback probe returned 204' "$work/log")" -eq 1 ] || fail recovery-log 'degraded must log once, not per probe'
  FAKE_OK_URLS="$miui"; export FAKE_OK_URLS
  probe_online
  grep -q 'Primary connectivity probe recovered' "$work/log" || fail recovery-log 'recovery not logged'
  [ "$probe_degraded" -eq 0 ] || fail recovery-log 'degraded not cleared'
  ;;
esac
