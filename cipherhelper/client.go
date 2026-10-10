package main

import (
	"bytes"
	"cipherhelper/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type portalCipher struct {
	impl      cipher.Cipher
	legacyNUL bool
}

func decodeKey(c configData, k string, n ...int) ([]byte, error) {
	b, e := hex.DecodeString(c[k])
	if e != nil {
		return nil, fmt.Errorf("invalid %s hex", k)
	}
	ok := false
	for _, l := range n {
		if len(b) == l {
			ok = true
		}
	}
	nonzero := false
	for _, v := range b {
		if v != 0 {
			nonzero = true
		}
	}
	if !ok || !nonzero {
		return nil, fmt.Errorf("missing or invalid %s", k)
	}
	return b, nil
}
func configCipher(c configData) (portalCipher, error) {
	raw := c["RAW_TEMPLATE"] != "" || c["RAW_KEY"] != "" || c["RAW_IV"] != "" || c["CIPHER_SCHEME"] == "RAW"
	if raw {
		k, e := hex.DecodeString(c["RAW_KEY"])
		if e != nil {
			return portalCipher{}, errors.New("invalid raw key hex")
		}
		v, e := hex.DecodeString(c["RAW_IV"])
		if e != nil {
			return portalCipher{}, errors.New("invalid raw IV hex")
		}
		impl, e := cipher.NewCipherRaw(c["RAW_TEMPLATE"], k, v)
		return portalCipher{impl, false}, e
	}
	if impl, e := cipher.NewCipher(c["ALGO_ID"]); e == nil {
		return portalCipher{impl, false}, nil
	}
	scheme := c["CIPHER_SCHEME"]
	if scheme == "" {
		scheme = "3DES2"
	}
	var impl cipher.Cipher
	legacyNUL := false
	switch scheme {
	case "9ABF4D29":
		if !strings.EqualFold(c["ALGO_ID"], "9ABF4D29-34DB-4CE9-BB8C-7E371D637758") {
			return portalCipher{}, errors.New("CIPHER_SCHEME does not match ALGO_ID")
		}
		k, e := decodeKey(c, "DOUBLE_DES_KEY", 48)
		if e != nil {
			return portalCipher{}, e
		}
		v, e := hex.DecodeString(c["DOUBLE_DES_IV"])
		if e != nil || len(v) != 16 {
			return portalCipher{}, errors.New("invalid DOUBLE_DES_IV")
		}
		impl = cipher.NewDESedeDoubleCBCAndroid(k, v)
	case "3DES2":
		legacyNUL = true
		a, e := decodeKey(c, "DES_KEY_FIRST", 24)
		if e != nil {
			return portalCipher{}, e
		}
		b, e := decodeKey(c, "DES_KEY_SECOND", 24)
		if e != nil {
			return portalCipher{}, e
		}
		impl = legacyDES{a, b}
	case "TEA3-CBC", "TEA3-ECB":
		legacyNUL = true
		if !strings.EqualFold(c["ALGO_ID"], "3084D519-54D7-4434-9564-26A8615BCEF2") {
			return portalCipher{}, errors.New("CIPHER_SCHEME does not match ALGO_ID")
		}
		key := []byte{}
		for _, name := range []string{"TEA_KEY_0", "TEA_KEY_1", "TEA_KEY_2"} {
			b, e := decodeKey(c, name, 16)
			if e != nil {
				return portalCipher{}, e
			}
			key = append(key, b...)
		}
		if scheme == "TEA3-CBC" {
			v, e := hex.DecodeString(c["TEA_IV"])
			if e != nil || len(v) != 8 {
				return portalCipher{}, errors.New("invalid TEA_IV")
			}
			impl = cipher.NewTEATripleCBCAndroid(key, v)
		} else {
			impl = cipher.NewTEATripleECBAndroid(key)
		}
	default:
		return portalCipher{}, errors.New("algorithm/key material not ready")
	}
	// The baseline 9ABF4D29 CBC fallback aligns only, unlike 3DES2/TEA.
	return portalCipher{impl, legacyNUL}, nil
}

// Legacy OpenSSL fallback padded with a mandatory NUL then to 8-byte blocks.
// Preserve its layer ordering and padding instead of substituting a different primitive.
type legacyDES struct{ first, second []byte }

func (d legacyDES) Encrypt(s string) string {
	b := []byte(s)
	if len(b)%8 != 0 {
		b = append(b, make([]byte, 8-len(b)%8)...)
	}
	a, _ := des.NewTripleDESCipher(d.second)
	z, _ := des.NewTripleDESCipher(d.first)
	for i := 0; i < len(b); i += 8 {
		a.Encrypt(b[i:i+8], b[i:i+8])
		z.Encrypt(b[i:i+8], b[i:i+8])
	}
	return strings.ToUpper(hex.EncodeToString(b))
}
func (d legacyDES) Decrypt(s string) string {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) == 0 || len(b)%8 != 0 {
		return ""
	}
	a, _ := des.NewTripleDESCipher(d.first)
	z, _ := des.NewTripleDESCipher(d.second)
	for i := 0; i < len(b); i += 8 {
		a.Decrypt(b[i:i+8], b[i:i+8])
		z.Decrypt(b[i:i+8], b[i:i+8])
	}
	return string(bytes.TrimRight(b, "\x00"))
}
func transform(c portalCipher, encrypt bool, s string) (out string, err error) {
	defer func() {
		if recover() != nil {
			out = ""
			err = errors.New("invalid cipher input")
		}
	}()
	if c.impl == nil {
		return "", errors.New("cipher not ready")
	}
	if len(s) > responseLimit {
		return "", errors.New("cipher input too large")
	}
	if encrypt {
		if c.legacyNUL {
			s += "\x00"
		}
		out = c.impl.Encrypt(s)
	} else {
		out = c.impl.Decrypt(stripSpace(s))
	}
	if out == "" {
		return "", errors.New("cipher produced no output")
	}
	return out, nil
}
func validateClient(c configData) error {
	for _, k := range strings.Fields("TICKET_URL AUTH_URL CLIENT_ID USER_AGENT HOST_NAME OSTAG IPV4 MAC GATEWAY SYSNAME MACHINE IFNAME SDK ALGO_ID") {
		if c[k] == "" {
			return fmt.Errorf("missing configuration field %s", k)
		}
	}
	_, e := configCipher(c)
	return e
}
func postRequest(c configData, target string, fields []field) (map[string]string, error) {
	xml, e := requestXML(c, fields)
	if e != nil {
		return nil, e
	}
	crypt, e := configCipher(c)
	if e != nil {
		return nil, e
	}
	body, e := transform(crypt, true, string(xml))
	if e != nil {
		return nil, e
	}
	b, h, e := httpExchange("POST", target, []byte(body), protocolHeaders(c, []byte(body)), 30*time.Second, responseLimit)
	if e != nil {
		return nil, e
	}
	if e = protocolError(h); e != nil {
		return nil, e
	}
	if len(b) > 3 && string(b[:3]) == "001" {
		return nil, errors.New("portal returned a module; algorithm refresh required")
	}
	plain, e := transform(crypt, false, string(b))
	if e != nil {
		return nil, e
	}
	return parseResponse([]byte(plain))
}

type portalSession struct{ ticket, keepURL, interval string }
type sessionPaths struct{ ticket, keepURL, interval string }

func envDefault(k, v string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return v
}
func pathsFor(config string) sessionPaths {
	d := filepath.Dir(config)
	return sessionPaths{envDefault("PORTAL_SESSION_TICKET_FILE", filepath.Join(d, "portal-session.ticket")), envDefault("PORTAL_SESSION_KEEP_URL_FILE", filepath.Join(d, "portal-session.keep-url")), envDefault("PORTAL_SESSION_INTERVAL_FILE", filepath.Join(d, "portal-session.interval"))}
}
func positiveSeconds(s string) bool { n, e := strconv.Atoi(s); return e == nil && n > 0 && n <= 86400 }
func authSession(c configData, user, password string, ticketOnly bool) (portalSession, error) {
	if e := validateClient(c); e != nil {
		return portalSession{}, e
	}
	r, e := postRequest(c, c["TICKET_URL"], []field{{"host-name", c["HOST_NAME"]}, {"ipv4", c["IPV4"]}, {"ipv6", c["IPV6"]}, {"mac", c["MAC"]}, {"ostag", c["OSTAG"]}, {"gwip", c["GATEWAY"]}})
	if e != nil {
		return portalSession{}, e
	}
	ticket := r["ticket"]
	if ticket == "" || len(ticket) > 4096 || strings.ContainsAny(ticket, "\r\n\x00") {
		return portalSession{}, errors.New("portal returned no valid ticket")
	}
	if ticketOnly {
		return portalSession{ticket: ticket}, nil
	}
	if user == "" || password == "" {
		return portalSession{}, errors.New("portal credentials missing")
	}
	r, e = postRequest(c, c["AUTH_URL"], []field{{"ticket", ticket}, {"userid", user}, {"passwd", password}})
	if e != nil {
		return portalSession{}, e
	}
	if e = trustedURL(c, r["keep-url"], "keep"); e != nil {
		return portalSession{}, e
	}
	interval := r["keep-interval"]
	if !positiveSeconds(interval) {
		interval = r["keep-retry"]
	}
	if !positiveSeconds(interval) {
		interval = envDefault("PORTAL_KEEP_SECONDS", "300")
	}
	if !positiveSeconds(interval) {
		interval = "300"
	}
	return portalSession{ticket, r["keep-url"], interval}, nil
}
func readSessionValue(p string) (string, error) {
	b, e := readFileLimited(p, 4096)
	if e != nil {
		return "", e
	}
	s := strings.TrimSuffix(string(b), "\n")
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("invalid saved session")
	}
	return s, nil
}

// A keep fallback only replaces the host/port; never lower the original scheme.
// Both original and alternate must pass the same active-config TLS/trust policy.
func keepAlternate(c configData, target string) (string, error) {
	if e := trustedURL(c, target, "keep"); e != nil {
		return "", e
	}
	old, e := portalURL(target)
	if e != nil {
		return "", e
	}
	auth, e := portalURL(c["AUTH_URL"])
	if e != nil {
		return "", e
	}
	if old.Host == auth.Host {
		return "", nil
	}
	old.Host = auth.Host
	alternate := old.String()
	if e = trustedURL(c, alternate, "keep"); e != nil {
		return "", e
	}
	return alternate, nil
}
func keepSession(c configData, p sessionPaths) error {
	if e := validateClient(c); e != nil {
		return e
	}
	ticket, e := readSessionValue(p.ticket)
	if e != nil || ticket == "" {
		return errors.New("session ticket missing")
	}
	target, e := readSessionValue(p.keepURL)
	if e != nil {
		return e
	}
	if e = trustedURL(c, target, "keep"); e != nil {
		return e
	}
	f := []field{{"ticket", ticket}, {"ipv4", c["IPV4"]}, {"ipv6", c["IPV6"]}, {"mac", c["MAC"]}}
	r, e := postRequest(c, target, f)
	if e != nil || !positiveSeconds(r["interval"]) {
		alternate, policyErr := keepAlternate(c, target)
		if policyErr != nil {
			return policyErr
		}
		if alternate != "" {
			r, e = postRequest(c, alternate, f)
			if e == nil && positiveSeconds(r["interval"]) {
				target = alternate
			}
		}
	}
	if e != nil {
		return e
	}
	if !positiveSeconds(r["interval"]) {
		return errors.New("keep response contains no valid interval")
	}
	return writeBundle([]fileUpdate{{p.keepURL, []byte(target + "\n")}, {p.interval, []byte(r["interval"] + "\n")}})
}
