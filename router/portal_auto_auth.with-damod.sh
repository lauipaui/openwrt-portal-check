#!/bin/sh
# Keep a CNDATA portal session alive with protocol keep-alives and fast recovery.
set -u
umask 077
export PORTAL_TIME_OFFSET="$(date +%z)"
export GOMEMLIMIT=${GOMEMLIMIT:-6MiB}

base_dir=${PORTAL_BASE_DIR:-/root/portal}
client="$base_dir/portal_client_openssl.sh"
config="$base_dir/portal.current.conf"
user_file="$base_dir/portal.user"
password_file="$base_dir/portal.password"
session_ticket_file="$base_dir/portal-session.ticket"
session_keep_url_file="$base_dir/portal-session.keep-url"
session_interval_file="$base_dir/portal-session.interval"
helper_bin=${PORTAL_CIPHER_HELPER:-"$base_dir/cipher-helper"}
export PORTAL_CIPHER_HELPER="$helper_bin"
runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/portal-auto.XXXXXX") || exit 1
lock_dir="$base_dir/.portal-auto-auth.lock"
lock_pid_file="$lock_dir/pid"
probe_file="$runtime_dir/probe"
probe_url=${PORTAL_PROBE_URL:-http://connect.rom.miui.com/generate_204}
probe_interval=${PORTAL_PROBE_SECONDS:-60}
probe_timeout=${PORTAL_PROBE_TIMEOUT_SECONDS:-10}
post_auth_delay=${PORTAL_POST_AUTH_DELAY_SECONDS:-3}
post_auth_attempts=${PORTAL_POST_AUTH_ATTEMPTS:-3}
default_keep_interval=${PORTAL_KEEP_SECONDS:-300}
retry_delay=${PORTAL_RETRY_SECONDS:-60}
retry_delay_max=${PORTAL_RETRY_MAX_SECONDS:-300}
portal_refresh_interval=${PORTAL_REFRESH_SECONDS:-300}
portal_page_file="$runtime_dir/page"
algo_probe_file="$runtime_dir/module"
algo_probe_request_file="$runtime_dir/request"
consecutive_failures=0
last_portal_refresh=''
export PORTAL_SESSION_TICKET_FILE="$session_ticket_file"
export PORTAL_SESSION_KEEP_URL_FILE="$session_keep_url_file"
export PORTAL_SESSION_INTERVAL_FILE="$session_interval_file"
export PORTAL_KEEP_SECONDS="$default_keep_interval"

log_message() {
    logger -t portal-auto-auth "$*" 2>/dev/null || printf '%s\n' "$*"
}

check_files() {
    for required_file in "$client" "$config" "$user_file" "$password_file"; do
        [ -r "$required_file" ] || {
            log_message "Missing required file: $required_file"
            return 1
        }
    done
}

current_wan_ip() {
    ifstatus "${PORTAL_WAN_IFACE:-wan}" 2>/dev/null | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null
}

# Rewrite IPV4, wlanuserip and clientip when the WAN address changes; returns 0 only if the config was updated.
refresh_wan_ip() {
    new_ip=$(current_wan_ip)
    case "$new_ip" in ''|*[!0-9.]*) return 1 ;; esac
    if "$helper_bin" config-wan "$config" "$new_ip" >/dev/null 2>&1; then
        log_message 'WAN IPv4 changed; safely updated data configuration and forcing re-authentication.'
        return 0
    fi
    return 1
}

validate_delays() {
    case "$probe_interval" in ''|*[!0-9]*|0) probe_interval=60 ;; esac
    case "$probe_timeout" in ''|*[!0-9]*|0) probe_timeout=10 ;; esac
    case "$post_auth_delay" in ''|*[!0-9]*|0) post_auth_delay=3 ;; esac
    case "$post_auth_attempts" in ''|*[!0-9]*|0) post_auth_attempts=3 ;; esac
    case "$default_keep_interval" in ''|*[!0-9]*|0) default_keep_interval=300 ;; esac
    case "$retry_delay" in ''|*[!0-9]*|0) retry_delay=60 ;; esac
    [ "$probe_interval" -ge 15 ] || probe_interval=15
    [ "$probe_interval" -le 60 ] || probe_interval=60
    [ "$retry_delay" -ge 60 ] || retry_delay=60
    case "$retry_delay_max" in ''|*[!0-9]*|0) retry_delay_max=300 ;; esac
    [ "$retry_delay_max" -ge "$retry_delay" ] || retry_delay_max=$retry_delay
    [ "$retry_delay_max" -le 3600 ] || retry_delay_max=3600
    case "$portal_refresh_interval" in ''|*[!0-9]*|0) portal_refresh_interval=300 ;; esac
    [ "$portal_refresh_interval" -ge 60 ] || portal_refresh_interval=60
}

check_probe_tool() {
    [ -x "$helper_bin" ] || { log_message 'A current cipher-helper is required for strict HTTP probing and safe data parsing.'; return 1; }
}

session_available() {
    [ -s "$session_ticket_file" ] && [ -s "$session_keep_url_file" ]
}

acquire_lock() {
    if mkdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$$" > "$lock_pid_file"
        return 0
    fi
    lock_pid=''
    [ ! -r "$lock_pid_file" ] || lock_pid=$(sed -n '1p' "$lock_pid_file")
    case "$lock_pid" in
        ''|*[!0-9]*) ;;
        *)
            if kill -0 "$lock_pid" 2>/dev/null; then
                log_message "Another portal auto-auth process is already running with PID $lock_pid."
                return 1
            fi
            ;;
    esac
    log_message 'Removing a stale portal auto-auth lock.'
    rm -f "$lock_pid_file"
    rmdir "$lock_dir" 2>/dev/null || return 1
    mkdir "$lock_dir" 2>/dev/null || return 1
    printf '%s\n' "$$" > "$lock_pid_file"
}

release_lock() {
    lock_owner=''
    [ ! -r "$lock_pid_file" ] || lock_owner=$(sed -n '1p' "$lock_pid_file")
    if [ "$lock_owner" = "$$" ]; then
        rm -f "$lock_pid_file"
        rmdir "$lock_dir" 2>/dev/null
    fi
    rm -rf "$runtime_dir"
}

handle_signal() {
    [ -z "${sleep_pid:-}" ] || kill "$sleep_pid" 2>/dev/null
    exit 0
}

sleep_for() {
    sleep "$1" &
    sleep_pid=$!
    wait "$sleep_pid" 2>/dev/null
    sleep_pid=''
}

read_keep_interval() {
    keep_seconds=$default_keep_interval
    [ ! -r "$session_interval_file" ] || keep_seconds=$(sed -n '1p' "$session_interval_file")
    case "$keep_seconds" in ''|*[!0-9]*|0) keep_seconds=$default_keep_interval ;; esac
    [ "$keep_seconds" -ge 60 ] || keep_seconds=60
    [ "$keep_seconds" -le 900 ] || keep_seconds=900
    echo "$keep_seconds"
}

format_time() {
    date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "epoch $1"
}

config_value() { "$helper_bin" config-get "$config" "$1"; }

load_credentials() {
    PORTAL_USER=$(sed -n '1p' "$user_file")
    PORTAL_PASSWORD=$(sed -n '1p' "$password_file")
    [ -n "$PORTAL_USER" ] && [ -n "$PORTAL_PASSWORD" ] || return 1
    export PORTAL_USER PORTAL_PASSWORD
}

# A URL taken from the (untrusted, plain-HTTP, MITM-able) portal page is written
# into the config file, which is later sourced by the client as shell.  Only
# accept characters that legitimately occur in these URLs; reject anything that
# could break out of the single-quoted assignment (', $, `, \, whitespace, ...).
# This is the primary defence against portal-driven command injection.
safe_portal_url() {
    case "$1" in
        '' | *[!A-Za-z0-9._:/?=\&%~@+-]*) return 1 ;;
        http://* | https://*) return 0 ;;
        *) return 1 ;;
    esac
}

extract_cdata_tag() {
    awk -v tag="$1" '
        {
            pattern = "<" tag "><![CDATA["
            start = index($0, pattern)
            if (start > 0) {
                rest = substr($0, start + length(pattern))
                stop = index(rest, "]]>")
                if (stop > 0) {
                    print substr(rest, 1, stop - 1)
                    exit
                }
            }
        }
    ' "$2"
activate_candidate() {
    load_credentials || { log_message 'Portal credentials are empty.'; return 1; }
    "$helper_bin" candidate-activate "$config" "$1" "$probe_url" "$probe_timeout" "$post_auth_attempts" "$post_auth_delay"
}

fetch_portal_page() {
    "$helper_bin" portal-page "$config" "$probe_url" "$portal_page_file"
}

# Endpoint updates are candidates too: trusted host + path, then actual auth
# and independent connectivity verification before local state is replaced.
refresh_portal_endpoints() {
    now=$(date +%s)
    if [ -n "${last_portal_refresh:-}" ] &&
        [ $((now - last_portal_refresh)) -lt "$portal_refresh_interval" ]; then
        return 1
    fi
    last_portal_refresh=$now
    fetch_portal_page || return 1
    page_ticket=$(extract_cdata_tag ticket-url "$portal_page_file")
    page_auth=$(extract_cdata_tag auth-url "$portal_page_file")
    if ! safe_portal_url "$page_ticket" || ! safe_portal_url "$page_auth"; then
        log_message 'Portal page returned a ticket/auth URL with unexpected characters; refusing to adopt it.'
        return 1
    fi
    current_ticket=$(config_value TICKET_URL)
    current_auth=$(config_value AUTH_URL)
    new_ticket=$page_ticket
    if [ -n "$current_ticket" ]; then
        new_ticket="$(url_without_query "$page_ticket")$(url_query "$current_ticket")"
    fi
    new_auth=$page_auth
    [ "$new_ticket" != "$current_ticket" ] || [ "$new_auth" != "$current_auth" ] || return 1
    if ! safe_portal_url "$new_ticket" || ! safe_portal_url "$new_auth"; then
        log_message 'Constructed portal URL contains unexpected characters; refusing to rewrite the configuration.'
        return 1
    fi
    cp -p "$config" "$config.bak-portal-$(date +%Y%m%d-%H%M%S)" || return 1
    tmp_config="$config.tmp.$$"
    if sed -e "s#^TICKET_URL=.*#TICKET_URL='$(sed_replacement_escape "$new_ticket")'#" \
           -e "s#^AUTH_URL=.*#AUTH_URL='$(sed_replacement_escape "$new_auth")'#" \
           "$config" > "$tmp_config" &&
        chmod 600 "$tmp_config" && mv "$tmp_config" "$config"; then
        log_message "Portal endpoints changed: TICKET_URL $(url_without_query "$current_ticket") -> $(url_without_query "$new_ticket"), AUTH_URL $current_auth -> $new_auth."
    endpoint_candidate="$runtime_dir/endpoints.conf"
    "$helper_bin" endpoint-prepare "$config" "$portal_page_file" "$endpoint_candidate" || return 1
    if activate_candidate "$endpoint_candidate"; then
        log_message 'Trusted portal endpoints activated after authentication and strict connectivity verification.'
        return 0
    fi
    log_message 'Endpoint candidate not activated; previous parameters and local session retained.'
    return 1
}

# Never trust a non-empty old cache. Download into a private random directory,
# fully decode and check the exact container UUID before publishing a new cache.
# helper and damod run sequentially (no simultaneous resident Go processes).
detect_portal_algorithm() {
    [ -x "$base_dir/damod" ] || { log_message 'DaMod decoder unavailable.'; return 1; }
    "$helper_bin" module-fetch "$config" "$algo_probe_file" || return 1
    algo_meta="$runtime_dir/module.json"
    algo_candidate="$runtime_dir/algorithm.conf"
    if ! "$base_dir/damod" -json "$algo_probe_file" > "$algo_meta"; then
        rm -f "$algo_probe_file" "$algo_meta"
        log_message 'Invalid module discarded; the next probe will download afresh.'
        return 1
    fi
    "$helper_bin" candidate-prepare "$config" "$algo_meta" "$algo_probe_file" "$algo_candidate" || return 1
    detected_algo=$("$helper_bin" config-get "$algo_candidate" ALGO_ID) || return 1
    # candidate-prepare guarantees UUID shape; cache-publish uses random atomic
    # staging and rejects symlinks. Failed downloads/unpacks never poison cache.
    "$helper_bin" cache-publish "$algo_probe_file" "$base_dir/damod-update.bin.$detected_algo" "$detected_algo" || return 1
    if activate_candidate "$algo_candidate"; then
        log_message "Portal algorithm $detected_algo activated; raw parameters now drive auth and keep."
        return 0
    fi
    log_message 'Algorithm candidate not activated; previous parameters and local session retained.'
    return 1
}

check_portal_configuration() {
    if refresh_portal_endpoints; then return 0; fi
    if detect_portal_algorithm; then return 0; fi
    return 1
}

current_retry_delay() {
    delay=$retry_delay
    remaining=$((consecutive_failures - 1))
    while [ "$remaining" -gt 0 ]; do
        delay=$((delay * 2))
        [ "$delay" -lt "$retry_delay_max" ] || { delay=$retry_delay_max; break; }
        remaining=$((remaining - 1))
    done
    printf '%s' "$delay"
}

backoff_retry() {
    consecutive_failures=$((consecutive_failures + 1))
    delay=$(current_retry_delay)
    log_message "$1 retrying in $delay seconds (consecutive failures: $consecutive_failures)."
    sleep_for "$delay"
}

keep_alive() {
    cd "$base_dir" || return 1
    sh "$client" "$config" keep
}

probe_online() {
    "$helper_bin" probe "$probe_url" "$probe_timeout" >/dev/null 2>&1
}

verify_online_with_retries() {
    verify_attempt=1
    while [ "$verify_attempt" -le "$post_auth_attempts" ]; do
        sleep_for "$post_auth_delay"
        if probe_online; then
            return 0
        fi
        verify_attempt=$((verify_attempt + 1))
    done
    return 1
}

authenticate() {
    load_credentials || { log_message 'Portal credentials are empty.'; return 1; }
    cd "$base_dir" || return 1
    sh "$client" "$config" auth
}

setup_credentials() {
    umask 077
export PORTAL_TIME_OFFSET="$(date +%z)"
    printf 'Portal account: ' >&2
    IFS= read -r setup_user
    printf 'Portal password: ' >&2
    IFS= read -r -s setup_password
    printf '\n' >&2
    [ -n "$setup_user" ] && [ -n "$setup_password" ] || {
        echo 'Account and password must not be empty.' >&2
        return 1
    }
    printf '%s\n' "$setup_user" > "$user_file"
    printf '%s\n' "$setup_password" > "$password_file"
    chmod 600 "$user_file" "$password_file"
    echo 'Credentials saved with mode 600.'
    if [ -x /etc/init.d/portal-auto-auth ]; then
        /etc/init.d/portal-auto-auth enable
        if /etc/init.d/portal-auto-auth running; then
            /etc/init.d/portal-auto-auth restart
        else
            /etc/init.d/portal-auto-auth start
        fi
        echo 'Automatic portal renewal started.'
    fi
}

accept_online_session() {
    consecutive_failures=0
    keep_seconds=$(read_keep_interval)
    next_keep=$(( $(date +%s) + keep_seconds ))
    need_auth=0
}

run_loop() {
    check_files || return 1
    validate_delays
    check_probe_tool || return 1
    acquire_lock || return 1
    sleep_pid=''
    trap 'release_lock' EXIT
    trap 'handle_signal' HUP INT TERM

    need_auth=1
    next_keep=0
    if session_available; then
        need_auth=0
    fi

    while :; do
        if refresh_wan_ip; then
            need_auth=1
        fi
        if [ "$need_auth" -eq 1 ]; then
            if authenticate; then
                if verify_online_with_retries; then
                    accept_online_session
                    log_message "Authentication accepted and connectivity verified; next keep-alive at $(format_time "$next_keep")."
                    sleep_for "$probe_interval"
                else
                    if check_portal_configuration; then
                        accept_online_session
                        log_message 'Verified migration activated; entering online keep-alive state without another authentication.'
                        sleep_for "$probe_interval"
                        continue
                    fi
                    backoff_retry 'Authentication response was accepted, but connectivity verification failed;'
                fi
            else
                if check_portal_configuration; then
                        accept_online_session
                        log_message 'Verified migration activated; entering online keep-alive state without another authentication.'
                        sleep_for "$probe_interval"
                        continue
                    fi
                backoff_retry 'Authentication failed;'
            fi
            continue
        fi

        now=$(date +%s)
        if [ "$now" -ge "$next_keep" ]; then
            if keep_alive; then
                if verify_online_with_retries; then
                    consecutive_failures=0
                    keep_seconds=$(read_keep_interval)
                    next_keep=$(( $(date +%s) + keep_seconds ))
                    log_message "Keep-alive accepted and connectivity verified; next keep-alive at $(format_time "$next_keep")."
                else
                    log_message 'Keep-alive response was accepted, but connectivity verification failed; re-authenticating immediately.'
                    need_auth=1
                    continue
                fi
            else
                log_message 'Keep-alive failed; re-authenticating immediately.'
                need_auth=1
                continue
            fi
        elif ! probe_online; then
            if ! verify_online_with_retries; then
                log_message 'Connectivity checks detected a captive portal or outage; re-authenticating immediately.'
                need_auth=1
                continue
            fi
        fi
        sleep_for "$probe_interval"
    done
}

trap 'rm -rf "$runtime_dir"' EXIT
trap 'exit 1' HUP INT TERM
case "${1:-run}" in
    run) run_loop ;;
    once) check_files && validate_delays && check_probe_tool && acquire_lock || exit 1; trap 'release_lock' EXIT; refresh_wan_ip || :; authenticate && verify_online_with_retries ;;
    keep) check_files && validate_delays && check_probe_tool && acquire_lock || exit 1; trap 'release_lock' EXIT; refresh_wan_ip || :; keep_alive ;;
    check) validate_delays; probe_online; check_result=$?; rm -f "$probe_file"; exit "$check_result" ;;
    refresh) check_files && validate_delays && check_probe_tool && acquire_lock || exit 1; trap 'release_lock' EXIT; if refresh_portal_endpoints; then echo 'Portal endpoints activated.'; else echo 'No verified endpoint update activated.'; exit 1; fi ;;
    algo) check_files && validate_delays && check_probe_tool && acquire_lock || exit 1; trap 'release_lock' EXIT; if detect_portal_algorithm; then echo 'Portal algorithm activated.'; else echo 'No verified algorithm update activated.'; exit 1; fi ;;
    setup) setup_credentials ;;
    *) echo "Usage: sh $0 [run|once|keep|check|refresh|algo|setup]" >&2; exit 2 ;;
esac

