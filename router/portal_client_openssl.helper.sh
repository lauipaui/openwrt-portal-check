#!/bin/sh
# CNDATA ticket/auth/keep client for OpenWrt systems with wget and openssl, but no Python.
set -eu
umask 077

config_file=${1:-portal.conf}
mode=${2:-auth}
session_ticket_file=${PORTAL_SESSION_TICKET_FILE:-portal-session.ticket}
session_keep_url_file=${PORTAL_SESSION_KEEP_URL_FILE:-portal-session.keep-url}
session_interval_file=${PORTAL_SESSION_INTERVAL_FILE:-portal-session.interval}
keep_response_file=${PORTAL_KEEP_RESPONSE_FILE:-/tmp/portal-keep-response.xml}
default_keep_interval=${PORTAL_KEEP_SECONDS:-300}

[ -r "$config_file" ] || { echo "Configuration file not found: $config_file" >&2; exit 2; }
case "$config_file" in
    */*) . "$config_file" ;;
    *) . "./$config_file" ;;
esac

# Maps a built-in CIPHER_SCHEME to the algorithm ID it implements.  An empty
# result means the scheme has no fixed algorithm ID (the legacy DaMod default).
scheme_algorithm_id() {
    case "$1" in
        9ABF4D29) echo '9ABF4D29-34DB-4CE9-BB8C-7E371D637758' ;;
        TEA3-CBC|TEA3-ECB) echo '3084D519-54D7-4434-9564-26A8615BCEF2' ;;
        *) echo '' ;;
    esac
}

required() {
    eval "value=\${$1:-}"
    [ -n "$value" ] || { echo "Missing $1 in $config_file" >&2; exit 2; }
}
for key in TICKET_URL AUTH_URL CLIENT_ID USER_AGENT HOST_NAME OSTAG IPV4 MAC GATEWAY SYSNAME MACHINE IFNAME SDK ALGO_ID; do required "$key"; done
# When the compiled cipher helper is present and knows this algorithm it takes
# over the whole crypto layer.  That is what makes the exotic algorithms (SM4,
# ZUC, SNOW3G, the XTEA variants) usable on a router whose OpenSSL cannot do
# them.  Otherwise the built-in shell/openssl implementations below are used.
helper_bin=${PORTAL_CIPHER_HELPER:-/root/portal/cipher-helper}
helper_ready=''
if [ -x "$helper_bin" ] && "$helper_bin" check "$ALGO_ID" >/dev/null 2>&1; then
    helper_ready=1
fi

CIPHER_SCHEME=${CIPHER_SCHEME:-3DES2}
if [ -z "$helper_ready" ]; then
# The shell fallback only implements a couple of schemes.  If ALGO_ID was
# bumped for a newer portal algorithm but CIPHER_SCHEME still points at an old
# one, the request would be encrypted with the wrong algorithm and the portal
# would only answer with an opaque rejection.  Refuse to run instead.
expected_algo=$(scheme_algorithm_id "$CIPHER_SCHEME")
if [ -n "$expected_algo" ] && [ "$expected_algo" != "$ALGO_ID" ]; then
    echo "ALGO_ID $ALGO_ID does not match CIPHER_SCHEME $CIPHER_SCHEME (that scheme implements $expected_algo)." >&2
    echo 'Update the configuration, or provide a cipher helper that supports this algorithm.' >&2
    exit 2
fi
case "$CIPHER_SCHEME" in    3DES2)
        required DES_KEY_FIRST; required DES_KEY_SECOND
        case "$DES_KEY_FIRST$DES_KEY_SECOND" in *[!0-9A-Fa-f]*) echo 'DaMod keys must be hexadecimal' >&2; exit 2;; esac
        [ "${#DES_KEY_FIRST}" -eq 48 ] && [ "${#DES_KEY_SECOND}" -eq 48 ] || { echo 'DaMod keys must be 48 hexadecimal characters each' >&2; exit 2; }
        ;;
    TEA3-CBC|TEA3-ECB)
        for key in TEA_KEY_0 TEA_KEY_1 TEA_KEY_2; do required "$key"; done
        case "$TEA_KEY_0$TEA_KEY_1$TEA_KEY_2" in *[!0-9A-Fa-f]*) echo 'TEA keys must be hexadecimal' >&2; exit 2;; esac
        [ "${#TEA_KEY_0}" -eq 32 ] && [ "${#TEA_KEY_1}" -eq 32 ] && [ "${#TEA_KEY_2}" -eq 32 ] || { echo 'TEA keys must be 32 hex characters each' >&2; exit 2; }
        if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
            required TEA_IV
            case "$TEA_IV" in *[!0-9A-Fa-f]*) echo 'TEA IV must be hexadecimal' >&2; exit 2;; esac
            [ "${#TEA_IV}" -eq 16 ] || { echo 'TEA IV must be 16 hex characters' >&2; exit 2; }
        fi
        ;;
    9ABF4D29)
        required DOUBLE_DES_KEY; required DOUBLE_DES_IV
        case "$DOUBLE_DES_KEY$DOUBLE_DES_IV" in *[!0-9A-Fa-f]*) echo 'Double 3DES keys must be hexadecimal' >&2; exit 2;; esac
        [ "${#DOUBLE_DES_KEY}" -eq 96 ] && [ "${#DOUBLE_DES_IV}" -eq 32 ] || { echo 'Double 3DES key must be 96 hex characters and IV 32 hex characters' >&2; exit 2; }
        ;;
    *) echo "Unsupported CIPHER_SCHEME: $CIPHER_SCHEME" >&2; exit 2 ;;
esac
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

xml_request() {
    output=$1; shift
    {
        printf '%s' '<?xml version="1.0" encoding="utf-8"?><request>'
        printf '<user-agent>%s</user-agent><client-id>%s</client-id><local-time>%s</local-time>' "$USER_AGENT" "$CLIENT_ID" "$(date '+%Y-%m-%d %H:%M:%S')"
        while [ "$#" -gt 0 ]; do tag=$1; value=$2; shift 2; printf '<%s>%s</%s>' "$tag" "$value" "$tag"; done
        printf '<sysinfo><sysname>%s</sysname><machine>%s</machine><ifname>%s</ifname>' "$SYSNAME" "$MACHINE" "$IFNAME"
        printf '<gsm.network.type>%s</gsm.network.type><ro.build.version.sdk>%s</ro.build.version.sdk></sysinfo></request>' "${GSM_NETWORK_TYPE:-}" "$SDK"
    } > "$output"
}

encrypt_xml_3des() {
    plain=$1; output=$2; padded="$tmp_dir/padded.bin"; stage_one="$tmp_dir/stage-one.bin"
    cp "$plain" "$padded"; printf '\000' >> "$padded"
    size=$(wc -c < "$padded"); padding=$(( (8 - (size % 8)) % 8 ))
    [ "$padding" -eq 0 ] || dd if=/dev/zero bs=1 count="$padding" 2>/dev/null >> "$padded"
    openssl enc -des-ede3-ecb -nosalt -nopad -K "$DES_KEY_SECOND" -in "$padded" -out "$stage_one"
    openssl enc -des-ede3-ecb -nosalt -nopad -K "$DES_KEY_FIRST" -in "$stage_one" -out "$tmp_dir/stage-two.bin"
    hexdump -v -e '/1 "%02X"' "$tmp_dir/stage-two.bin" > "$output"
}

split_tea_key() {
    tea_key_text=$1; tea_key_prefix=$2
    set -- $(printf '%s' "$tea_key_text" | sed 's/\(........\)/\1 /g')
    [ "$#" -eq 4 ] || { echo 'Could not split a TEA key' >&2; exit 2; }
    eval "${tea_key_prefix}_0=$((0x$1)); ${tea_key_prefix}_1=$((0x$2)); ${tea_key_prefix}_2=$((0x$3)); ${tea_key_prefix}_3=$((0x$4))"
}

prepare_tea_keys() {
    [ "${TEA_KEYS_READY:-}" = 1 ] && return
    split_tea_key "$TEA_KEY_0" TEA0
    split_tea_key "$TEA_KEY_1" TEA1
    split_tea_key "$TEA_KEY_2" TEA2
    TEA_IV_0=0; TEA_IV_1=0
    if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
        set -- $(printf '%s' "$TEA_IV" | sed 's/\(........\)/\1 /g')
        TEA_IV_0=$((0x$1)); TEA_IV_1=$((0x$2))
    fi
    TEA_KEYS_READY=1
}

tea_encrypt_rounds() {
    tea_v0=$1; tea_v1=$2; tea_k0=$3; tea_k1=$4; tea_k2=$5; tea_k3=$6
    tea_sum=0; tea_round=0
    while [ "$tea_round" -lt 32 ]; do
        case $((tea_sum & 3)) in 0) tea_k=$tea_k0;; 1) tea_k=$tea_k1;; 2) tea_k=$tea_k2;; 3) tea_k=$tea_k3;; esac
        tea_mix=$(( ((tea_v1 << 4) ^ (tea_v1 >> 5)) & 0xFFFFFFFF ))
        tea_v0=$(( (tea_v0 + tea_mix + ((tea_v1 ^ tea_sum) & 0xFFFFFFFF) + tea_k) & 0xFFFFFFFF ))
        tea_sum=$(( (tea_sum + 0x9E3779B9) & 0xFFFFFFFF ))
        case $(((tea_sum >> 11) & 3)) in 0) tea_k=$tea_k0;; 1) tea_k=$tea_k1;; 2) tea_k=$tea_k2;; 3) tea_k=$tea_k3;; esac
        tea_mix=$(( ((tea_v0 << 4) ^ (tea_v0 >> 5)) & 0xFFFFFFFF ))
        tea_v1=$(( (tea_v1 + tea_k + ((tea_v0 ^ tea_sum) & 0xFFFFFFFF) + tea_mix) & 0xFFFFFFFF ))
        tea_round=$((tea_round + 1))
    done
}

tea_decrypt_rounds() {
    tea_v0=$1; tea_v1=$2; tea_k0=$3; tea_k1=$4; tea_k2=$5; tea_k3=$6
    tea_sum=0xC6EF3720; tea_round=0
    while [ "$tea_round" -lt 32 ]; do
        case $(((tea_sum >> 11) & 3)) in 0) tea_k=$tea_k0;; 1) tea_k=$tea_k1;; 2) tea_k=$tea_k2;; 3) tea_k=$tea_k3;; esac
        tea_mix=$(( ((tea_v0 << 4) ^ (tea_v0 >> 5)) & 0xFFFFFFFF ))
        tea_v1=$(( (tea_v1 - tea_k - ((tea_v0 ^ tea_sum) & 0xFFFFFFFF) - tea_mix) & 0xFFFFFFFF ))
        tea_sum=$(( (tea_sum - 0x9E3779B9) & 0xFFFFFFFF ))
        case $((tea_sum & 3)) in 0) tea_k=$tea_k0;; 1) tea_k=$tea_k1;; 2) tea_k=$tea_k2;; 3) tea_k=$tea_k3;; esac
        tea_mix=$(( ((tea_v1 << 4) ^ (tea_v1 >> 5)) & 0xFFFFFFFF ))
        tea_v0=$(( (tea_v0 - tea_mix - ((tea_v1 ^ tea_sum) & 0xFFFFFFFF) - tea_k) & 0xFFFFFFFF ))
        tea_round=$((tea_round + 1))
    done
}

encrypt_xml_tea() {
    plain=$1; output=$2; padded="$tmp_dir/padded.bin"
    prepare_tea_keys
    cp "$plain" "$padded"; printf '\000' >> "$padded"
    size=$(wc -c < "$padded"); padding=$(( (8 - (size % 8)) % 8 ))
    [ "$padding" -eq 0 ] || dd if=/dev/zero bs=1 count="$padding" 2>/dev/null >> "$padded"
    : > "$output"
    tea_prev0=$TEA_IV_0; tea_prev1=$TEA_IV_1
    hexdump -v -e '4/1 "%02X" " " 4/1 "%02X" "\n"' "$padded" | while IFS=' ' read -r tea_left tea_right; do
        tea_v0=$((0x$tea_left)); tea_v1=$((0x$tea_right))
        if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
            tea_v0=$(( (tea_v0 ^ tea_prev0) & 0xFFFFFFFF )); tea_v1=$(( (tea_v1 ^ tea_prev1) & 0xFFFFFFFF ))
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA2_0" "$TEA2_1" "$TEA2_2" "$TEA2_3"
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA1_0" "$TEA1_1" "$TEA1_2" "$TEA1_3"
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA0_0" "$TEA0_1" "$TEA0_2" "$TEA0_3"
        else
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA0_0" "$TEA0_1" "$TEA0_2" "$TEA0_3"
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA1_0" "$TEA1_1" "$TEA1_2" "$TEA1_3"
            tea_encrypt_rounds "$tea_v0" "$tea_v1" "$TEA2_0" "$TEA2_1" "$TEA2_2" "$TEA2_3"
        fi
        printf '%08X%08X' "$tea_v0" "$tea_v1" >> "$output"
        if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
            tea_prev0=$tea_v0; tea_prev1=$tea_v1
        fi
    done
}

decrypt_response_tea() {
    input=$1; output=$2; compact="$tmp_dir/tea-response.compact"; plain_hex="$tmp_dir/tea-response-plain.hex"
    prepare_tea_keys
    tr -d '[:space:]' < "$input" > "$compact"; : > "$plain_hex"
    tea_prev0=$TEA_IV_0; tea_prev1=$TEA_IV_1
    sed 's/\(........\)\(........\)/\1 \2\n/g' "$compact" | while IFS=' ' read -r tea_left tea_right; do
        [ -n "$tea_left" ] || continue
        tea_cipher0=$((0x$tea_left)); tea_cipher1=$((0x$tea_right)); tea_v0=$tea_cipher0; tea_v1=$tea_cipher1
        if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA0_0" "$TEA0_1" "$TEA0_2" "$TEA0_3"
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA1_0" "$TEA1_1" "$TEA1_2" "$TEA1_3"
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA2_0" "$TEA2_1" "$TEA2_2" "$TEA2_3"
            tea_v0=$(( (tea_v0 ^ tea_prev0) & 0xFFFFFFFF )); tea_v1=$(( (tea_v1 ^ tea_prev1) & 0xFFFFFFFF ))
        else
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA2_0" "$TEA2_1" "$TEA2_2" "$TEA2_3"
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA1_0" "$TEA1_1" "$TEA1_2" "$TEA1_3"
            tea_decrypt_rounds "$tea_v0" "$tea_v1" "$TEA0_0" "$TEA0_1" "$TEA0_2" "$TEA0_3"
        fi
        printf '%08X%08X' "$tea_v0" "$tea_v1" >> "$plain_hex"
        if [ "$CIPHER_SCHEME" = TEA3-CBC ]; then
            tea_prev0=$tea_cipher0; tea_prev1=$tea_cipher1
        fi
    done
    hex_to_bin "$plain_hex" "$tmp_dir/response-plain.bin"
    tr -d '\000' < "$tmp_dir/response-plain.bin" > "$output"
}

encrypt_xml() {
    if [ -n "$helper_ready" ]; then
        "$helper_bin" encrypt "$ALGO_ID" < "$1" > "$2" || {
            echo 'The cipher helper failed to encrypt the request body.' >&2
            exit 1
        }
        return 0
    fi
    case "$CIPHER_SCHEME" in
        TEA3-CBC|TEA3-ECB) encrypt_xml_tea "$@" ;;
        9ABF4D29) encrypt_xml_double_des_cbc "$@" ;;
        *) encrypt_xml_3des "$@" ;;
    esac
}

double_des_key_first() { printf '%s' "$DOUBLE_DES_KEY" | cut -c1-48; }
double_des_key_second() { printf '%s' "$DOUBLE_DES_KEY" | cut -c49-96; }
double_des_iv_first() { printf '%s' "$DOUBLE_DES_IV" | cut -c1-16; }

encrypt_xml_double_des_cbc() {
    plain=$1; output=$2; padded="$tmp_dir/double-des-padded.bin"
    cp "$plain" "$padded"
    size=$(wc -c < "$padded")
    remainder=$((size % 8))
    if [ "$remainder" -ne 0 ]; then
        dd if=/dev/zero bs=1 count=$((8 - remainder)) 2>/dev/null >> "$padded"
    fi
    openssl enc -des-ede3-cbc -nosalt -nopad -K "$(double_des_key_second)" -iv "$(double_des_iv_first)" -in "$padded" -out "$tmp_dir/double-des-one.bin"
    openssl enc -des-ede3-cbc -nosalt -nopad -K "$(double_des_key_first)" -iv "$(double_des_iv_first)" -in "$tmp_dir/double-des-one.bin" -out "$tmp_dir/double-des-two.bin"
    hexdump -v -e '/1 "%02X"' "$tmp_dir/double-des-two.bin" > "$output"
}

decrypt_response_double_des_cbc() {
    input=$1; output=$2
    hex_to_bin "$input" "$tmp_dir/double-des-response.bin"
    openssl enc -d -des-ede3-cbc -nosalt -nopad -K "$(double_des_key_first)" -iv "$(double_des_iv_first)" -in "$tmp_dir/double-des-response.bin" -out "$tmp_dir/double-des-one.bin"
    openssl enc -d -des-ede3-cbc -nosalt -nopad -K "$(double_des_key_second)" -iv "$(double_des_iv_first)" -in "$tmp_dir/double-des-one.bin" -out "$tmp_dir/double-des-two.bin"
    tr -d '\000' < "$tmp_dir/double-des-two.bin" > "$output"
}

hex_to_bin() {
    tr -d '[:space:]' < "$1" | sed 's/../&\n/g' | while IFS= read -r byte; do [ -z "$byte" ] || printf '%b' "\\x$byte"; done > "$2"
}

decrypt_response() {
    if [ -n "$helper_ready" ]; then
        "$helper_bin" decrypt "$ALGO_ID" < "$1" > "$2" || {
            echo 'The cipher helper failed to decrypt the portal response.' >&2
            exit 1
        }
        return 0
    fi
    case "$CIPHER_SCHEME" in
        TEA3-CBC|TEA3-ECB) decrypt_response_tea "$@"; return ;;
        9ABF4D29) decrypt_response_double_des_cbc "$@"; return ;;
    esac
    hex_to_bin "$1" "$tmp_dir/response.bin"
    openssl enc -d -des-ede3-ecb -nosalt -nopad -K "$DES_KEY_FIRST" -in "$tmp_dir/response.bin" -out "$tmp_dir/response-one.bin"
    openssl enc -d -des-ede3-ecb -nosalt -nopad -K "$DES_KEY_SECOND" -in "$tmp_dir/response-one.bin" -out "$tmp_dir/response-plain.bin"
    tr -d '\000' < "$tmp_dir/response-plain.bin" > "$2"
}

self_test() {
    case "$CIPHER_SCHEME" in
    TEA3-CBC)
        expected='0894926F8222EFF75492D30ABA6D6206A3793D277DD2E07705D64621C145DE3898AB0AEA3A2960AE9D0FF5CC1A54E454C681C33E2A9E05A9C42646716D064704EDE00128E63727C0522A52C643BA300E289B6872A01523DCEF50D2FA0AA349D1DCDD2FA9D390771996620B2941BEADB92DB2FD34F688EAA4A6BC3820612F5789D2DE4B2053A9AE41352458478B7947653FC65D40FCC21EE785094F434CFF61CC52C7960C070C02E07788E3946856C8C7A63DFE9116718FDAF29447AB2183CCB40FB89AECB12B08A8600385B94EEC7793EEB231EE2829165F19ABAF8FD6CA309439F4F62D6E1879C98DC1D3B354E8AB1326B4AC1F6AE192A4DBC0F3C7DEF0A4F85EAA501C0DBA6FFA19F84079F45841B4AD50A04613F18444'
        ;;
    TEA3-ECB)
        expected='14EE5E6CE94C3D7486BE753EBCE76216E421E57307F4111AB45F94A8E94E77FF5428157727B61AF99193CA713D245724DB6DBC5A63D7133E709272F4401490B6560A780B0A194C3EEC5DEF33C77EF0DEE54469EF3EB445585E72E55E0A74B3E3DEE49D70421C026452DE4B60ADAE2A1E54ACF8F8075171C506F3B580ADF489E3DEB6E161A8EFB5387BD43D9A2D9E32D29D616F9E8F5729B5B5D6EF30CC45C60B5D38CCD03E38CD7E897040CC37DF5BDEE9D3B1882080F85A0E17BA18B5D38E2BD6AE2D3C546B70CAD1E1BE2AA016F3834E475505D8AB6C054D635721017963B242A02412D4100AD35DF7138E96273887E31CCA2248CD412C341B93A6725E8E0E35629B264AB1BE5162AC0522E6469A3AECC8E61183FFA7AE'
        ;;
    9ABF4D29)
        expected='99B73AF1104BFF01BA8968F04324A654594D54F4C206116093819D625E3B0845BAF7E57387220F317E68D8E7C61829A056AC0DB9986E5B139B5AB69C04BA4ABA3A2790699037B1E1D64E9B7D9B34D3A05E2308858B82CACF0DE6A397E3937F63ED26204B79CEF105D298CF00B99F776D5E87FCC5DB5A78965DD74A7039C2B3DD1AAC14341EB3E81503809721B572DC623A7103637B7410DCAC685EB65565469BEEBD0CD876CBDA97C19E2B6CB88D6A4EF7612966BE09064F7C3D16F32BE634D4E3DF45AFED36BE5C0D6F82A68153D76CBD2730D0E66A3751A34A17188F5BC6D9772F3CBD3B99F300378D3AE0CC7A7AA64B051B17C5919CB65DACA0A9D33E8FD0E3EBC0A0AB513FEE1AD27FED381AB59203FBE8E50D15B8A7'
        ;;
    *)
        expected='C93ECA2235DABE67105095716C7F5F60A5F32914011C998A383D91FAC9B8799E48118D94EC80042CA256BBA60820ACF20424C8E4D4DB40B79A300F94DC9B6DF0BF35A6D3E8CD255BBAF477AF8C405EA9A71DFC591B0CFC2F20A7CF452931FF1CD82C647977CE50FA6FA8C870C297385FE4C081898D1A875739AE7B460449EAF0009E43E64E69ABC8E5A74B97931ADE9A2BB08DC5B26F49E7DA653BB81FE6395050582FC666E698FC58B538C2A398A08ADCE95292354966CDF23B181C565AEC31E1E7703D58624CEC129EDB08BB96B7B3B7B19A3DAB3B3DF3F207C2BD4E5C6DA62A7385717066293B8621707937FA102D4F3B49A3923163824DF96232EF11CC04BC6A6DAEC74792BEFEB4AD948D1D4F49F76F5BAC96589277'
        ;;
    esac
    printf '%s' '<?xml version="1.0" encoding="utf-8"?><request><sample>portal-analysis</sample><sysinfo><sysname>Linux</sysname><machine>aarch64</machine><ifname>wlan0</ifname><gsm.network.type>NR_SA,NR_SA</gsm.network.type><ro.build.version.sdk>36</ro.build.version.sdk></sysinfo></request>' > "$tmp_dir/self-test.xml"
    encrypt_xml "$tmp_dir/self-test.xml" "$tmp_dir/self-test.hex"
    actual=$(tr -d '\r\n' < "$tmp_dir/self-test.hex")
    [ "$actual" = "$expected" ] || { echo 'DaMod self-test failed.' >&2; exit 1; }
    decrypt_response "$tmp_dir/self-test.hex" "$tmp_dir/self-test.decoded.xml"
    cmp -s "$tmp_dir/self-test.xml" "$tmp_dir/self-test.decoded.xml" || { echo 'DaMod decrypt self-test failed.' >&2; exit 1; }
    echo 'DaMod self-test passed.'
}

split_http_response() {
    raw=$1; headers=$2; body=$3
    cr=$(printf '\r')
    : > "$headers"
    exec 3< "$raw"
    found=''
    while IFS= read -r line <&3; do
        printf '%s\n' "$line" >> "$headers"
        if [ -z "$line" ] || [ "$line" = "$cr" ]; then
            found=1
            break
        fi
    done
    if [ -z "$found" ]; then
        exec 3<&-
        echo 'The portal response did not contain a complete HTTP header.' >&2
        return 1
    fi
    cat <&3 > "$body"
    exec 3<&-
}

post_with_nc() {
    url=$1; body_file=$2; checksum=$3; response_name=$4
    case "$url" in
        http://*) target=${url#http://} ;;
        *) echo "nc transport supports only http:// URLs: $url" >&2; return 1 ;;
    esac
    authority=${target%%/*}
    if [ "$target" = "$authority" ]; then path=/; else path=/${target#*/}; fi
    case "$authority" in
        *:*) host=${authority%%:*}; port=${authority##*:} ;;
        *) host=$authority; port=80 ;;
    esac
    content_length=$(wc -c < "$body_file" | tr -d '[:space:]')
    {
        printf 'POST %s HTTP/1.1\r\n' "$path"
        printf 'Host: %s\r\n' "$authority"
        printf 'Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*\r\n'
        printf 'Connection: close\r\n'
        printf 'Content-Type: text/plain; charset=utf-8\r\n'
        printf 'Content-Length: %s\r\n' "$content_length"
        printf 'Client-ID: %s\r\n' "$CLIENT_ID"
        printf 'User-Agent: %s\r\n' "$USER_AGENT"
        printf 'Algo-ID: %s\r\n' "$ALGO_ID"
        printf 'CDC-Checksum: %s\r\n' "$checksum"
        [ -z "${SCHOOL_ID:-}" ] || printf 'CDC-SchoolId: %s\r\n' "$SCHOOL_ID"
        [ -z "${DOMAIN:-}" ] || printf 'CDC-Domain: %s\r\n' "$DOMAIN"
        [ -z "${AREA:-}" ] || printf 'CDC-Area: %s\r\n' "$AREA"
        printf '\r\n'
        cat "$body_file"
    } > "$tmp_dir/request.http"

    # Use input redirection instead of a producer pipeline.  Several small
    # BusyBox nc builds close a POST pipeline before the final input bytes have
    # reached the socket.  Keeping both wire files also makes an empty or
    # truncated response diagnosable after the temporary directory is removed.
    cp "$tmp_dir/request.http" "$response_name.request.http"
    if ! nc "$host" "$port" < "$tmp_dir/request.http" > "$tmp_dir/response.http"; then
        cp "$tmp_dir/response.http" "$response_name.http"
        echo "nc failed; raw request and response are in $response_name.request.http and $response_name.http." >&2
        return 1
    fi
    cp "$tmp_dir/response.http" "$response_name.http"
    if [ ! -s "$tmp_dir/response.http" ]; then
        echo "The portal closed the connection without a response; inspect $response_name.request.http." >&2
        return 1
    fi
    if ! split_http_response "$tmp_dir/response.http" "$tmp_dir/response.headers" "$tmp_dir/response.hex"; then
        response_size=$(wc -c < "$tmp_dir/response.http" | tr -d '[:space:]')
        echo "Saved the $response_size-byte raw response as $response_name.http." >&2
        echo 'First 256 response bytes:' >&2
        dd if="$tmp_dir/response.http" bs=1 count=256 2>/dev/null | hexdump -C >&2
        return 1
    fi
}

response_header() {
    wanted=$1
    awk -F ': *' -v wanted="$wanted" '
        { name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name) }
        tolower(name) == tolower(wanted) { value=$2; gsub(/\r$/, "", value) }
        END { print value }
    ' "$tmp_dir/response.headers"
}

post_xml() {
    url=$1; xml=$2; response=$3
    encrypt_xml "$xml" "$tmp_dir/body.hex"
    checksum=$(md5sum "$tmp_dir/body.hex" | awk '{ print toupper($1) }')
    if [ "$response" = ticket-response.xml ]; then
        cp "$xml" ticket-request.xml
        cp "$tmp_dir/body.hex" ticket-request.hex
    fi
    if command -v curl >/dev/null 2>&1; then
        set -- curl -sS --connect-timeout 10 --max-time 30 -D "$tmp_dir/response.headers" -o "$tmp_dir/response.hex" -X POST -H 'Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*' -H 'Connection: close' -H 'Content-Type: text/plain; charset=utf-8' -H "Client-ID: $CLIENT_ID" -H "User-Agent: $USER_AGENT" -H "Algo-ID: $ALGO_ID" -H "CDC-Checksum: $checksum"
        [ -z "${SCHOOL_ID:-}" ] || set -- "$@" -H "CDC-SchoolId: $SCHOOL_ID"
        [ -z "${DOMAIN:-}" ] || set -- "$@" -H "CDC-Domain: $DOMAIN"
        [ -z "${AREA:-}" ] || set -- "$@" -H "CDC-Area: $AREA"
        "$@" --data-binary "@$tmp_dir/body.hex" "$url" || { echo 'Portal request failed before a response was received.' >&2; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        set -- wget -q -T 15 -O "$tmp_dir/response.hex" --header='Accept: text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*' --header='Connection: close' --header='Content-Type: text/plain; charset=utf-8' --header="Client-ID: $CLIENT_ID" --header="User-Agent: $USER_AGENT" --header="Algo-ID: $ALGO_ID" --header="CDC-Checksum: $checksum"
        [ -z "${SCHOOL_ID:-}" ] || set -- "$@" --header="CDC-SchoolId: $SCHOOL_ID"
        [ -z "${DOMAIN:-}" ] || set -- "$@" --header="CDC-Domain: $DOMAIN"
        [ -z "${AREA:-}" ] || set -- "$@" --header="CDC-Area: $AREA"
        "$@" --post-file="$tmp_dir/body.hex" "$url" || { echo 'Portal request through wget failed before a response was received.' >&2; exit 1; }
        error_code=''
    elif command -v nc >/dev/null 2>&1; then
        post_with_nc "$url" "$tmp_dir/body.hex" "$checksum" "$response" || { echo 'Portal request failed through nc.' >&2; exit 1; }
    else
        echo 'Neither curl, wget, nor nc is available.' >&2
        exit 1
    fi
    if [ -r "$tmp_dir/response.headers" ]; then
        cp "$tmp_dir/response.headers" "$response.headers"
        error_code=$(response_header Error-Code)
        sub_error=$(response_header Sub-Error)
        echo "Portal Error-Code: ${error_code:-<missing>}"
        [ -z "$sub_error" ] || echo "Portal Sub-Error: $sub_error"
    fi
    cp "$tmp_dir/response.hex" "$response.raw"
    signature=$(dd if="$tmp_dir/response.hex" bs=1 count=4 2>/dev/null)
    case "${error_code:-}:$signature" in
        200:* | *:[0-9][0-9][0-9]@)
            cp "$tmp_dir/response.hex" damod-update.bin
            echo 'The portal returned a new DaMod module; saved it as damod-update.bin.' >&2
            echo 'Its algorithm ID and keys must be extracted before retrying.' >&2
            exit 4
            ;;
    esac
    if [ -n "${error_code:-}" ] && [ "$error_code" != 0 ]; then
        echo "Portal rejected the request with Error-Code $error_code; inspect $response.headers and $response.raw." >&2
        exit 1
    fi
    tr -d '[:space:]' < "$tmp_dir/response.hex" > "$tmp_dir/response.compact"
    compact_size=$(wc -c < "$tmp_dir/response.compact")
    case "$compact_size" in
        ''|*[!0-9]*) echo 'Portal response could not be measured; inspect the .raw file.' >&2; exit 1 ;;
    esac
    if grep -q '[^0-9A-Fa-f]' "$tmp_dir/response.compact" || [ $((compact_size % 16)) -ne 0 ]; then
        echo "Portal response is not hexadecimal 3DES data ($compact_size characters); inspect $response.raw." >&2
        echo 'First 128 response bytes:' >&2
        dd if="$tmp_dir/response.hex" bs=1 count=128 2>/dev/null | hexdump -C >&2
        exit 1
    fi
    decrypt_response "$tmp_dir/response.hex" "$response"
}

xml_value() {
    tr '\r\n' '  ' < "$2" |
        sed 's/<!\[CDATA\[//g; s/]]>//g' |
        sed -n "s#.*<$1>[[:space:]]*\\([^<]*\\)[[:space:]]*</$1>.*#\\1#p"
}

valid_response() {
    grep -q '<response>' "$1" && grep -q '</response>' "$1"
}

positive_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *[1-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

save_session_value() {
    target=$1
    value=$2
    current=''
    [ ! -r "$target" ] || current=$(sed -n '1p' "$target")
    [ "$current" != "$value" ] || return 0
    temporary="${target}.tmp.$$"
    printf '%s\n' "$value" > "$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" "$target"
}

if [ "$mode" = self-test ]; then
    self_test
    exit 0
fi

url_host() {
    printf '%s' "$1" | sed -n 's#^http[s]\{0,1\}://\([^/:]*\).*#\1#p'
}

if [ "$mode" = keep ]; then
    [ -s "$session_ticket_file" ] || { echo "Session ticket not found: $session_ticket_file" >&2; exit 1; }
    [ -s "$session_keep_url_file" ] || { echo "Session keep URL not found: $session_keep_url_file" >&2; exit 1; }
    ticket=$(sed -n '1p' "$session_ticket_file")
    keep_url=$(sed -n '1p' "$session_keep_url_file")
    [ -n "$ticket" ] && [ -n "$keep_url" ] || { echo 'Saved portal session is incomplete.' >&2; exit 1; }
    xml_request "$tmp_dir/keep.xml" ticket "$ticket" ipv4 "$IPV4" ipv6 "${IPV6:-}" mac "$MAC"
    auth_host=$(url_host "$AUTH_URL")
    keep_attempt_url=$keep_url
    keep_ok=''
    keep_attempt=1
    while [ "$keep_attempt" -le 2 ]; do
        if post_xml "$keep_attempt_url" "$tmp_dir/keep.xml" "$keep_response_file"; then
            if valid_response "$keep_response_file"; then
                response_interval=$(xml_value interval "$keep_response_file")
                if positive_integer "$response_interval"; then
                    keep_ok=1
                    break
                fi
            fi
            echo "Keep-alive response from $keep_attempt_url was not usable." >&2
        else
            echo "Keep-alive request to $keep_attempt_url failed." >&2
        fi
        if [ "$keep_attempt" -eq 1 ]; then
            keep_host=$(url_host "$keep_url")
            if [ -z "$auth_host" ] || [ "$auth_host" = "$keep_host" ]; then
                break
            fi
            keep_alternate=$(printf '%s' "$keep_url" | sed "s#^http\(s\{0,1\}\)://[^/:]*#http\1://$auth_host#")
            if [ -z "$keep_alternate" ] || [ "$keep_alternate" = "$keep_url" ]; then
                break
            fi
            echo "Falling back to alternate keep-alive server: $keep_alternate" >&2
            keep_attempt_url=$keep_alternate
        fi
        keep_attempt=$((keep_attempt + 1))
    done
    [ -n "$keep_ok" ] || { echo 'Keep-alive failed on the portal-provided and alternate servers.' >&2; exit 1; }
    if [ "$keep_attempt_url" != "$keep_url" ]; then
        save_session_value "$session_keep_url_file" "$keep_attempt_url"
        echo "Saved alternate keep-alive URL: $keep_attempt_url" >&2
    fi
    save_session_value "$session_interval_file" "$response_interval"
    printf 'Keep-alive response accepted; interval %s seconds.\n' "$response_interval"
    exit 0
fi

xml_request "$tmp_dir/ticket.xml" host-name "$HOST_NAME" ipv4 "$IPV4" ipv6 "${IPV6:-}" mac "$MAC" ostag "$OSTAG" gwip "$GATEWAY"
post_xml "$TICKET_URL" "$tmp_dir/ticket.xml" ticket-response.xml
ticket=$(xml_value ticket ticket-response.xml)
[ -n "$ticket" ] || { echo 'Ticket was not returned; inspect ticket-response.xml.' >&2; exit 1; }
printf 'Ticket acquired.\n'
[ "$mode" = ticket ] && exit 0
[ "$mode" = auth ] || { echo 'Usage: sh portal_client_openssl.sh [portal.conf] [ticket|auth]' >&2; exit 2; }
if [ -z "${PORTAL_USER:-}" ]; then
    printf 'Portal account: ' >&2
    IFS= read -r PORTAL_USER
fi
if [ -z "${PORTAL_PASSWORD:-}" ]; then
    printf 'Portal password: ' >&2
    IFS= read -r -s PORTAL_PASSWORD
    printf '\n' >&2
fi
xml_request "$tmp_dir/auth.xml" ticket "$ticket" userid "$PORTAL_USER" passwd "$PORTAL_PASSWORD"
post_xml "$AUTH_URL" "$tmp_dir/auth.xml" auth-response.xml
valid_response auth-response.xml || { echo 'Authentication response was not valid; inspect auth-response.xml.' >&2; exit 1; }
keep_url=$(xml_value keep-url auth-response.xml)
case "$keep_url" in
    http://*|https://*) ;;
    '') echo 'Authentication was not accepted: the portal returned no keep URL.' >&2; exit 1 ;;
    *) echo 'Authentication returned an unsupported keep URL.' >&2; exit 1 ;;
esac
keep_interval=$(xml_value keep-interval auth-response.xml)
positive_integer "$keep_interval" || keep_interval=$(xml_value keep-retry auth-response.xml)
positive_integer "$keep_interval" || keep_interval=$default_keep_interval
positive_integer "$keep_interval" || keep_interval=300
save_session_value "$session_keep_url_file" "$keep_url"
save_session_value "$session_interval_file" "$keep_interval"
save_session_value "$session_ticket_file" "$ticket"
printf 'Authentication exchange accepted; keep-alive interval %s seconds.\n' "$keep_interval"

