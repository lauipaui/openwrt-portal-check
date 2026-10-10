#!/bin/sh
# Keep a CNDATA portal session alive with protocol keep-alives and fast recovery.
set -u

base_dir=${PORTAL_BASE_DIR:-/root/portal}
client="$base_dir/portal_client_openssl.sh"
config="$base_dir/portal.current.conf"
user_file="$base_dir/portal.user"
password_file="$base_dir/portal.password"
session_ticket_file="$base_dir/portal-session.ticket"
session_keep_url_file="$base_dir/portal-session.keep-url"
session_interval_file="$base_dir/portal-session.interval"
lock_dir=/tmp/portal-auto-auth.lock
lock_pid_file="$lock_dir/pid"
probe_file=/tmp/portal-auto-auth.probe.$$
probe_url=${PORTAL_PROBE_URL:-http://connect.rom.miui.com/generate_204}
probe_interval=${PORTAL_PROBE_SECONDS:-60}
probe_timeout=${PORTAL_PROBE_TIMEOUT_SECONDS:-10}
post_auth_delay=${PORTAL_POST_AUTH_DELAY_SECONDS:-3}
post_auth_attempts=${PORTAL_POST_AUTH_ATTEMPTS:-3}
default_keep_interval=${PORTAL_KEEP_SECONDS:-300}
retry_delay=${PORTAL_RETRY_SECONDS:-60}
retry_delay_max=${PORTAL_RETRY_MAX_SECONDS:-300}
portal_refresh_interval=${PORTAL_REFRESH_SECONDS:-300}
portal_page_file=/tmp/portal-auto-auth.page.$$
algo_probe_file=/tmp/portal-auto-auth.algo.$$
algo_probe_request_file=/tmp/portal-auto-auth.algo-request.$$
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
    old_ip=$(sed -n "s/^IPV4='\{0,1\}\([0-9.]*\)'\{0,1\}$/\1/p" "$config" | sed -n '1p')
    [ -n "$old_ip" ] && [ "$old_ip" != "$new_ip" ] || return 1
    cp -p "$config" "$config.bak-ip-$(date +%Y%m%d-%H%M%S)" || return 1
    tmp_config="$config.tmp.$$"
    if sed -e "s/^IPV4=.*/IPV4='$new_ip'/" \
           -e "s/\([?&]wlanuserip=\)[0-9.]*/\1$new_ip/" \
           -e "s/\([?&]clientip=\)[0-9.]*/\1$new_ip/" "$config" > "$tmp_config" &&
        chmod 600 "$tmp_config" && mv "$tmp_config" "$config"; then
        log_message "WAN IPv4 changed from $old_ip to $new_ip; updated $config and forcing re-authentication."
        return 0
    fi
    rm -f "$tmp_config"
    log_message "WAN IPv4 changed from $old_ip to $new_ip, but updating $config failed."
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
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || {
        log_message 'No curl or wget is available; refusing to start without a connectivity probe.'
        return 1
    }
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
    rm -f "$probe_file" "$portal_page_file" "$algo_probe_file" "$algo_probe_request_file"
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

config_value() {
    sed -n "s/^$1='\{0,1\}\([^']*\)'\{0,1\}$/\1/p" "$config" | sed -n '1p'
}

url_without_query() {
    printf '%s' "$1" | sed -n 's/^\([^?]*\).*$/\1/p'
}

url_query() {
    case "$1" in
        *\?*) printf '?%s' "${1#*\?}" ;;
        *) printf '' ;;
    esac
}

sed_replacement_escape() {
    printf '%s' "$1" | sed 's/[\\&#]/\\&/g'
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
}

fetch_portal_page() {
    page_agent=$(config_value USER_AGENT)
    [ -n "$page_agent" ] || page_agent='CCTP/android11_64/2104'
    : > "$portal_page_file" || return 1
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --connect-timeout "$probe_timeout" --max-time "$probe_timeout" \
            -A "$page_agent" -o "$portal_page_file" "$probe_url" >/dev/null 2>&1 || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T "$probe_timeout" -O "$portal_page_file" \
            --header="User-Agent: $page_agent" "$probe_url" >/dev/null 2>&1 || return 1
    else
        return 1
    fi
    [ -s "$portal_page_file" ]
}

# Re-read the captive portal configuration page and adopt a migrated ticket/auth
# server.  Only the scheme/host/port/path is taken from the portal; the query
# string of the local ticket URL is preserved because it carries the values that
# are known to work for this router (clientmac, iarmdst) plus the WAN address
# that refresh_wan_ip keeps current.
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
        return 0
    fi
    rm -f "$tmp_config"
    log_message 'Portal endpoint refresh could not rewrite the configuration file.'
    return 1
}

# A zero-UUID Algo-ID request makes the portal hand back the DaMod module it
# currently wants; the module carries exactly one algorithm UUID.  This detects
# an algorithm migration and says so in the log instead of retrying silently.
detect_portal_algorithm() {
    ticket_url=$(config_value TICKET_URL)
    configured_algo=$(config_value ALGO_ID)
    case "$ticket_url" in http://*|https://*) ;; *) return 1 ;; esac
    client_id=$(config_value CLIENT_ID)
    user_agent=$(config_value USER_AGENT)
    zero_algo='00000000-0000-0000-0000-000000000000'
    printf '%s' "$zero_algo" > "$algo_probe_request_file" || return 1
    algo_checksum=$(md5sum "$algo_probe_request_file" | awk '{ print toupper($1) }')
    rm -f "$algo_probe_file"
    if command -v curl >/dev/null 2>&1; then
        curl -sS --connect-timeout "$probe_timeout" --max-time "$probe_timeout" \
            -o "$algo_probe_file" -X POST --data-binary "@$algo_probe_request_file" \
            -H 'Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*' \
            -H 'Connection: close' -H 'Content-Type: text/plain; charset=utf-8' \
            -H "Client-ID: $client_id" -H "User-Agent: $user_agent" \
            -H "Algo-ID: $zero_algo" -H "CDC-Checksum: $algo_checksum" \
            "$ticket_url" >/dev/null 2>&1 || :
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T "$probe_timeout" -O "$algo_probe_file" \
            --header='Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*' \
            --header='Connection: close' \
            --header='Content-Type: text/plain; charset=utf-8' \
            --header="Client-ID: $client_id" \
            --header="User-Agent: $user_agent" \
            --header="Algo-ID: $zero_algo" \
            --header="CDC-Checksum: $algo_checksum" \
            --post-file="$algo_probe_request_file" "$ticket_url" >/dev/null 2>&1 || :
    else
        return 1
    fi
    detected_algo=$(grep -ao -E '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' "$algo_probe_file" 2>/dev/null | sort -u | sed -n '1p')
    case "$detected_algo" in
        '')
            log_message 'Portal algorithm probe returned no algorithm ID; the portal may be unreachable.'
            return 1
            ;;
        "$configured_algo") return 1 ;;
        *)
            log_message "Portal algorithm mismatch: the portal now serves $detected_algo but ALGO_ID is $configured_algo. Update ALGO_ID, CIPHER_SCHEME and the matching keys before retrying."
            module_copy="$base_dir/damod-update.bin.$detected_algo"
            if [ -s "$algo_probe_file" ] && [ ! -s "$module_copy" ]; then
                if cp "$algo_probe_file" "$module_copy" && chmod 600 "$module_copy"; then
                    log_message "Saved the portal algorithm module as $module_copy for analysis."
                fi
            fi
            # Unpack the module the portal just rotated to and record the
            # template plus its embedded key material.  The portal serves the
            # current module on demand, so this is what lets a migration be
            # followed without hand-analysing the download.
            if [ -x "$base_dir/damod" ] && [ -s "$module_copy" ]; then
                algo_env="$base_dir/algo-$detected_algo.env"
                if "$base_dir/damod" -env "$module_copy" > "$algo_env.tmp" 2>/dev/null; then
                    chmod 600 "$algo_env.tmp" && mv "$algo_env.tmp" "$algo_env"
                    algo_template=$(sed -n "s/^DAMOD_TEMPLATE='\(.*\)'$/\1/p" "$algo_env")
                    algo_keylen=$(sed -n "s/^DAMOD_KEYLEN=\(.*\)$/\1/p" "$algo_env")
                    log_message "Portal module $detected_algo uses $algo_template (key length $algo_keylen); parameters written to $algo_env."
                    if [ -x "$base_dir/cipher-helper" ]; then
                        algo_key=$(sed -n "s/^DAMOD_KEY='\(.*\)'$/\1/p" "$algo_env")
                        algo_iv=$(sed -n "s/^DAMOD_IV='\(.*\)'$/\1/p" "$algo_env")
                        if printf 'x' | "$base_dir/cipher-helper" encrypt-raw "$algo_template" "$algo_key" "$algo_iv" > /dev/null 2>&1; then
                            log_message "cipher-helper already drives $algo_template, so this migration only needs the new key material."
                        else
                            log_message "cipher-helper cannot drive $algo_template yet; that primitive has to be implemented before switching."
                        fi
                    fi
                else
                    rm -f "$algo_env.tmp"
                    log_message "Could not unpack portal module $module_copy."
                fi
            fi
            return 0
            ;;
    esac
}

check_portal_configuration() {
    changed=0
    if refresh_portal_endpoints; then
        changed=1
        log_message 'Portal endpoint configuration was updated; re-authenticating against the new endpoints.'
    fi
    detect_portal_algorithm || :
    return "$changed"
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
    : > "$probe_file" || return 1
    if command -v curl >/dev/null 2>&1; then
        curl -fLsS --connect-timeout "$probe_timeout" --max-time "$probe_timeout" -o "$probe_file" "$probe_url" >/dev/null 2>&1 || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T "$probe_timeout" -O "$probe_file" "$probe_url" >/dev/null 2>&1 || return 1
    else
        log_message 'No curl or wget is available for connectivity checks.'
        return 2
    fi
    [ ! -s "$probe_file" ]
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
    PORTAL_USER=$(sed -n '1p' "$user_file")
    PORTAL_PASSWORD=$(sed -n '1p' "$password_file")
    [ -n "$PORTAL_USER" ] && [ -n "$PORTAL_PASSWORD" ] || {
        log_message 'The portal account or password is empty.'
        return 1
    }
    export PORTAL_USER PORTAL_PASSWORD
    cd "$base_dir" || return 1
    sh "$client" "$config" auth
}

setup_credentials() {
    umask 077
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
                    consecutive_failures=0
                    keep_seconds=$(read_keep_interval)
                    next_keep=$(( $(date +%s) + keep_seconds ))
                    need_auth=0
                    log_message "Authentication accepted and connectivity verified; next keep-alive at $(format_time "$next_keep")."
                    sleep_for "$probe_interval"
                else
                    if check_portal_configuration; then
                        consecutive_failures=0
                    fi
                    backoff_retry 'Authentication response was accepted, but connectivity verification failed;'
                fi
            else
                if check_portal_configuration; then
                    consecutive_failures=0
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

case "${1:-run}" in
    run) run_loop ;;
    once) check_files && { refresh_wan_ip || :; authenticate; } ;;
    keep) check_files && { refresh_wan_ip || :; keep_alive; } ;;
    check) validate_delays; probe_online; check_result=$?; rm -f "$probe_file"; exit "$check_result" ;;
    refresh) check_files || exit 1; trap 'rm -f "$portal_page_file" "$algo_probe_file" "$algo_probe_request_file"' EXIT; if refresh_portal_endpoints; then echo 'Portal endpoints updated.'; else echo 'No portal endpoint change detected (or the portal page was unavailable).'; fi ;;
    algo) check_files || exit 1; trap 'rm -f "$portal_page_file" "$algo_probe_file" "$algo_probe_request_file"' EXIT; if detect_portal_algorithm; then echo 'Portal algorithm differs from the configured ALGO_ID.'; else echo 'Portal algorithm matches the configured ALGO_ID, or could not be determined.'; fi ;;
    setup) setup_credentials ;;
    *) echo "Usage: sh $0 [run|once|keep|check|refresh|algo|setup]" >&2; exit 2 ;;
esac

