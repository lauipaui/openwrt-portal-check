package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const configLimit = 64 << 10

var configKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields("TICKET_URL AUTH_URL CLIENT_ID USER_AGENT SCHOOL_ID DOMAIN AREA HOST_NAME OSTAG IPV4 IPV6 MAC GATEWAY SYSNAME MACHINE IFNAME GSM_NETWORK_TYPE SDK ALGO_ID CIPHER_SCHEME DOUBLE_DES_KEY DOUBLE_DES_IV DES_KEY_FIRST DES_KEY_SECOND TEA_KEY_0 TEA_KEY_1 TEA_KEY_2 TEA_IV RAW_TEMPLATE RAW_KEY RAW_IV TRUSTED_PORTAL_HOSTS") {
		m[k] = true
	}
	return m
}()

type configData map[string]string

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func readLimited(r io.Reader, n int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, int64(n)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > n {
		return nil, errors.New("input exceeds size limit")
	}
	return b, nil
}
func readFileLimited(p string, n int) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return readLimited(f, n)
}
func parseConfig(b []byte) (configData, error) {
	if len(b) > configLimit {
		return nil, errors.New("configuration too large")
	}
	m := configData{}
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		// Token decoding catches duplicate JSON fields rather than last-value wins.
		d := json.NewDecoder(bytes.NewReader(b))
		tok, e := d.Token()
		if e != nil || tok != json.Delim('{') {
			return nil, errors.New("invalid JSON configuration")
		}
		for d.More() {
			tok, e = d.Token()
			if e != nil {
				return nil, e
			}
			k, ok := tok.(string)
			if !ok {
				return nil, errors.New("invalid configuration key")
			}
			if _, ok = m[k]; ok {
				return nil, errors.New("duplicate configuration key")
			}
			var v string
			if e = d.Decode(&v); e != nil {
				return nil, errors.New("configuration values must be strings")
			}
			m[k] = v
		}
		if tok, e = d.Token(); e != nil || tok != json.Delim('}') {
			return nil, errors.New("invalid JSON configuration")
		}
		if _, e = d.Token(); e != io.EOF {
			return nil, errors.New("trailing configuration data")
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 1024), configLimit)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != k {
				return nil, errors.New("expected literal KEY=value")
			}
			if _, ok = m[k]; ok {
				return nil, errors.New("duplicate configuration key")
			}
			if strings.HasPrefix(v, "'") {
				if len(v) < 2 || !strings.HasSuffix(v, "'") || strings.Contains(v[1:len(v)-1], "'") {
					return nil, errors.New("invalid single-quoted literal")
				}
				v = v[1 : len(v)-1]
			} else {
				if strings.ContainsAny(v, "\"'`$;()\\<>|& \t") {
					return nil, errors.New("unquoted value must be a plain literal")
				}
			}
			m[k] = v
		}
		if e := sc.Err(); e != nil {
			return nil, e
		}
	}
	if e := validateConfig(m); e != nil {
		return nil, e
	}
	return m, nil
}
func readConfig(p string) (configData, error) {
	b, e := readFileLimited(p, configLimit)
	if e != nil {
		return nil, e
	}
	return parseConfig(b)
}
func validateConfig(m configData) error {
	for k, v := range m {
		if !configKeys[k] {
			return fmt.Errorf("unknown configuration field %s", k)
		}
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid configuration field %s", k)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return fmt.Errorf("control character in %s", k)
			}
		}
		if (k == "TICKET_URL" || k == "AUTH_URL") && v != "" {
			if _, e := portalURL(v); e != nil {
				return fmt.Errorf("invalid URL in %s", k)
			}
		}
		if k == "ALGO_ID" && v != "" && !uuidPattern.MatchString(v) {
			return errors.New("invalid ALGO_ID")
		}
	}
	return nil
}
func portalURL(s string) (*url.URL, error) {
	if len(s) > 4096 || strings.ContainsAny(s, "\r\n\x00'\"`\\<> ") {
		return nil, errors.New("invalid portal URL")
	}
	u, e := url.Parse(s)
	if e != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid portal URL")
	}
	h := u.Hostname()
	if net.ParseIP(h) == nil {
		if len(h) > 253 || strings.ContainsAny(h, "%/_") {
			return nil, errors.New("invalid URL hostname")
		}
		for _, c := range h {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return nil, errors.New("invalid URL hostname")
			}
		}
	}
	if p := u.Port(); p != "" {
		var port int
		if _, e := fmt.Sscanf(p, "%d", &port); e != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid port")
		}
	}
	return u, nil
}
func trustedURL(c configData, s, role string) error {
	u, e := portalURL(s)
	if e != nil {
		return e
	}
	trusted := false
	for _, k := range []string{"TICKET_URL", "AUTH_URL"} {
		v, e := portalURL(c[k])
		if e == nil && strings.EqualFold(v.Hostname(), u.Hostname()) {
			trusted = true
		}
	}
	for _, h := range strings.Split(c["TRUSTED_PORTAL_HOSTS"], ",") {
		if strings.EqualFold(strings.TrimSpace(h), u.Hostname()) {
			trusted = true
		}
	}
	if !trusted {
		return errors.New("portal host not trusted; configure TRUSTED_PORTAL_HOSTS explicitly")
	}
	if role == "keep" {
		// If either configured credential-bearing endpoint is HTTPS, a portal
		// response or saved session must not move its ticket to a cleartext keep URL.
		// Independent hosts remain possible via the explicit trust whitelist.
		for _, key := range []string{"TICKET_URL", "AUTH_URL"} {
			endpoint, err := portalURL(c[key])
			if err != nil {
				return errors.New("keep TLS policy requires valid ticket/auth endpoints")
			}
			if endpoint.Scheme == "https" && u.Scheme != "https" {
				return errors.New("keep endpoint TLS downgrade refused")
			}
		}
		if u.EscapedPath() != "/keep.cgi" {
			return errors.New("untrusted keep endpoint path")
		}
	} else if role != "" {
		old, e := portalURL(c[role])
		if e != nil || u.EscapedPath() != old.EscapedPath() {
			return errors.New("portal endpoint path changed; manual approval required")
		}
	}
	return nil
}
func encodeConfig(c configData) ([]byte, error) {
	if e := validateConfig(c); e != nil {
		return nil, e
	}
	b, e := json.MarshalIndent(c, "", "  ")
	return append(b, '\n'), e
}
func cloneConfig(c configData) configData {
	n := configData{}
	for k, v := range c {
		n[k] = v
	}
	return n
}

// Random private temporary files plus rename: never follow a preplaced target symlink.
func atomicWrite(p string, b []byte) error {
	if st, e := os.Lstat(p); e == nil {
		if !st.Mode().IsRegular() {
			return errors.New("refusing non-regular output target")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".portal-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, p)
}
func writeConfig(p string, c configData) error {
	b, e := encodeConfig(c)
	if e != nil {
		return e
	}
	return atomicWrite(p, b)
}
func configLines(c configData) string {
	ks := []string{}
	for k := range c {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%s\n", k, c[k])
	}
	return b.String()
}
