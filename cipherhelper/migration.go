package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type fileUpdate struct {
	path string
	data []byte
}
type fileSnapshot struct {
	path   string
	data   []byte
	exists bool
}

func snapshot(p string) (fileSnapshot, error) {
	s := fileSnapshot{path: p}
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if !st.Mode().IsRegular() {
		return s, errors.New("refusing non-regular state file")
	}
	s.data, e = readFileLimited(p, configLimit)
	s.exists = true
	return s, e
}
func unchanged(s fileSnapshot) bool {
	now, e := snapshot(s.path)
	return e == nil && now.exists == s.exists && bytes.Equal(now.data, s.data)
}

// All targets are checked before the first write. Configuration is written last,
// and an ordinary write failure restores previous parameters and local session.
// Power-loss recovery remains a deployment backup concern (see security docs).
func writeBundle(updates []fileUpdate) error { return writeBundleUsing(updates, nil, atomicWrite) }

// writer is the filesystem boundary; tests use a deterministic competing writer.
func writeBundleUsing(updates []fileUpdate, expected []fileSnapshot, writer func(string, []byte) error) error {
	snapshots := []fileSnapshot{}
	seen := map[string]bool{}
	for i, u := range updates {
		if seen[u.path] {
			return errors.New("duplicate state output")
		}
		seen[u.path] = true
		s, e := snapshot(u.path)
		if e != nil {
			return e
		}
		if expected != nil {
			if len(expected) != len(updates) || expected[i].path != u.path {
				return errors.New("invalid transaction preconditions")
			}
			s = expected[i]
		}
		snapshots = append(snapshots, s)
	}
	rollback := func(written int, cause error) error {
		incomplete := false
		for j := written - 1; j >= 0; j-- {
			old := snapshots[j]
			owned := fileSnapshot{old.path, updates[j].data, true}
			if !unchanged(owned) {
				incomplete = true
				continue
			} // Do not overwrite an external edit.
			if old.exists {
				if atomicWrite(old.path, old.data) != nil {
					incomplete = true
				}
			} else if os.Remove(old.path) != nil {
				incomplete = true
			}
		}
		if incomplete {
			return fmt.Errorf("%w; rollback incomplete because state was externally changed or could not be restored", cause)
		}
		return cause
	}
	for i, u := range updates {
		if !unchanged(snapshots[i]) {
			return rollback(i, errors.New("state changed concurrently"))
		}
		if e := writer(u.path, u.data); e != nil {
			return rollback(i, e)
		}
	}
	return nil
}

type moduleMetadata struct {
	UUID       string `json:"uuid"`
	Template   string `json:"template"`
	Algorithm  string `json:"algorithm"`
	ModuleType int    `json:"module_type"`
	UncompSize int    `json:"uncompressed_size"`
	ELFSize    int    `json:"elf_size"`
	BlockSize  int    `json:"block_size"`
	KeyLen     int    `json:"key_len"`
	KeyOff     int    `json:"key_off"`
	KeyHex     string `json:"key_hex"`
	IVLen      int    `json:"iv_len"`
	IVHex      string `json:"iv_hex"`
}

func prepareCandidate(active configData, b []byte) (configData, error) {
	if len(b) > 16<<10 {
		return nil, errors.New("module metadata too large")
	}
	var m moduleMetadata
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return nil, errors.New("invalid module metadata")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return nil, errors.New("trailing module metadata")
	}
	if !uuidPattern.MatchString(m.UUID) || m.UUID == "00000000-0000-0000-0000-000000000000" || m.ModuleType != 0 || m.ELFSize <= 0 || m.ELFSize > 1<<20 || m.UncompSize != m.ELFSize || m.KeyLen <= 0 || m.KeyLen > 64 || m.KeyOff < 0 || m.KeyOff > 249 || m.KeyOff+m.KeyLen+m.BlockSize > 249 || m.IVLen != 16 || (m.BlockSize != 8 && m.BlockSize != 16) {
		return nil, errors.New("invalid module metadata bounds")
	}
	key, e := hex.DecodeString(m.KeyHex)
	if e != nil || len(key) != m.KeyLen {
		return nil, errors.New("module key length mismatch")
	}
	iv, e := hex.DecodeString(m.IVHex)
	if e != nil || len(iv) != m.IVLen {
		return nil, errors.New("module IV length mismatch")
	}
	// Only independently verified extracted module shapes can be activated.
	expected := map[string]string{"tpl_des_iv.so": "double-3des-cbc", "tpl_des_cbc.so": "double-3des-cbc", "tpl_des.so": "six-layer-des-ecb", "tpl_des_ecb.so": "six-layer-des-ecb", "tpl_aes_cbc.so": "double-aes128-cbc", "tpl_aes_ecb.so": "double-aes128-ecb"}
	algo, ok := expected[m.Template]
	if !ok || m.Algorithm != algo {
		return nil, errors.New("unverified module template")
	}
	if strings.Contains(algo, "aes") {
		if m.KeyLen != 32 || m.BlockSize != 16 {
			return nil, errors.New("AES metadata mismatch")
		}
	} else if m.KeyLen != 48 || m.BlockSize != 8 {
		return nil, errors.New("DES metadata mismatch")
	}
	c := cloneConfig(active)
	c["ALGO_ID"] = strings.ToUpper(m.UUID)
	c["CIPHER_SCHEME"] = "RAW"
	c["RAW_TEMPLATE"] = m.Template
	c["RAW_KEY"] = m.KeyHex
	c["RAW_IV"] = m.IVHex
	crypt, e := configCipher(c)
	if e != nil {
		return nil, e
	}
	plain := "candidate capability & roundtrip"
	encrypted, e := transform(crypt, true, plain)
	if e != nil {
		return nil, e
	}
	decoded, e := transform(crypt, false, encrypted)
	if e != nil || decoded != plain {
		return nil, errors.New("candidate cipher roundtrip failed")
	}
	return c, nil
}

type activationOptions struct {
	user, password, probeURL string
	attempts                 int
	delay, timeout           time.Duration
	paths                    sessionPaths
}

func activateCandidate(activePath, candidatePath string, o activationOptions) error {
	before, e := snapshot(activePath)
	if e != nil || !before.exists {
		return errors.New("active configuration missing")
	}
	active, e := parseConfig(before.data)
	if e != nil {
		return e
	}
	c, e := readConfig(candidatePath)
	if e != nil {
		return e
	}
	allowed := map[string]bool{"ALGO_ID": true, "CIPHER_SCHEME": true, "RAW_TEMPLATE": true, "RAW_KEY": true, "RAW_IV": true, "TICKET_URL": true, "AUTH_URL": true}
	for k, v := range active {
		if !allowed[k] && c[k] != v {
			return errors.New("candidate changes outside migration boundary")
		}
	}
	for k, v := range c {
		if !allowed[k] && active[k] != v {
			return errors.New("candidate adds unauthorized configuration")
		}
	}
	for _, k := range []string{"TICKET_URL", "AUTH_URL"} {
		if c[k] != active[k] {
			if e = trustedURL(active, c[k], k); e != nil {
				return e
			}
			old, _ := portalURL(active[k])
			n, _ := portalURL(c[k])
			if old.Scheme == "https" && n.Scheme != "https" {
				return errors.New("endpoint TLS downgrade refused")
			}
		}
	}
	oldBytes, _ := encodeConfig(active)
	newBytes, e := encodeConfig(c)
	if e != nil {
		return e
	}
	if bytes.Equal(oldBytes, newBytes) {
		return errors.New("candidate unchanged")
	}
	// No active state is modified until candidate authentication and independent
	// strict HTTP 204 verification both succeed. Sessions stay in memory here.
	expected := []fileSnapshot{}
	for _, p := range []string{o.paths.ticket, o.paths.keepURL, o.paths.interval, activePath} {
		ss, e := snapshot(p)
		if e != nil {
			return e
		}
		expected = append(expected, ss)
	}
	expected[3] = before
	state, e := authSession(c, o.user, o.password, false)
	if e != nil {
		return e
	}
	online := false
	if o.attempts < 1 {
		o.attempts = 1
	}
	if o.attempts > 10 {
		o.attempts = 10
	}
	if o.timeout <= 0 {
		o.timeout = 10 * time.Second
	}
	for i := 0; i < o.attempts; i++ {
		if o.delay > 0 {
			time.Sleep(o.delay)
		}
		if probe204(o.probeURL, o.timeout) == nil {
			online = true
			break
		}
	}
	if !online {
		return errors.New("candidate authentication exchange accepted but connectivity not verified; active state retained")
	}
	if !unchanged(before) {
		return errors.New("active configuration changed during verification")
	}
	updates := []fileUpdate{{o.paths.ticket, []byte(state.ticket + "\n")}, {o.paths.keepURL, []byte(state.keepURL + "\n")}, {o.paths.interval, []byte(state.interval + "\n")}, {activePath, newBytes}}
	return writeBundleUsing(updates, expected, atomicWrite)
}
func wanConfig(c configData, ip string) (configData, bool, error) {
	if net.ParseIP(ip) == nil || strings.Contains(ip, ":") {
		return nil, false, errors.New("invalid WAN IPv4")
	}
	if c["IPV4"] == "" || c["IPV4"] == ip {
		return c, false, nil
	}
	n := cloneConfig(c)
	n["IPV4"] = ip
	for _, k := range []string{"TICKET_URL", "AUTH_URL"} {
		u, e := portalURL(n[k])
		if e != nil {
			return nil, false, e
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			return nil, false, e
		}
		for _, f := range []string{"wlanuserip", "clientip"} {
			if _, ok := q[f]; ok {
				q.Set(f, ip)
			}
		}
		u.RawQuery = q.Encode()
		n[k] = u.String()
	}
	return n, true, nil
}

// The real portal is HTML with embedded CCTP scalar fields, not necessarily XML.
// Extract exactly one matching pair per named field as bounded DATA. CDATA is
// handled literally; normal scalar XML uses the standard entity decoder.
var endpointTag = regexp.MustCompile(`<\s*/?\s*(ticket-url|auth-url)\b[^>]*>`)

func endpointScalar(b []byte, name string) (string, error) {
	open := []byte("<" + name + ">")
	close := []byte("</" + name + ">")
	tags := endpointTag.FindAll(b, 5)
	if len(tags) > 4 {
		return "", errors.New("duplicate or excess endpoint fields")
	}
	opens, closes := 0, 0
	for _, tag := range tags {
		if bytes.Contains(tag, []byte(name)) {
			if bytes.Equal(tag, open) {
				opens++
			} else if bytes.Equal(tag, close) {
				closes++
			} else {
				return "", errors.New("non-literal endpoint tag")
			}
		}
	}
	if opens != 1 || closes != 1 {
		return "", errors.New("missing or duplicate endpoint field")
	}
	start := bytes.Index(b, open) + len(open)
	end := bytes.Index(b, close)
	if end < start || end-start > 8192 {
		return "", errors.New("invalid endpoint field bounds")
	}
	v := bytes.TrimSpace(b[start:end])
	if bytes.HasPrefix(v, []byte("<![CDATA[")) {
		if !bytes.HasSuffix(v, []byte("]]>")) {
			return "", errors.New("unclosed endpoint CDATA")
		}
		inner := v[9 : len(v)-3]
		if bytes.Contains(inner, []byte("]]>")) {
			return "", errors.New("ambiguous endpoint CDATA")
		}
		if len(inner) > 4096 {
			return "", errors.New("endpoint URL too long")
		}
		return string(inner), nil
	}
	wrapped := append(append([]byte("<value>"), v...), []byte("</value>")...)
	d := xml.NewDecoder(bytes.NewReader(wrapped))
	depth := 0
	var text strings.Builder
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", errors.New("invalid scalar endpoint XML")
		}
		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			if depth != 1 || x.Name.Local != "value" || len(x.Attr) != 0 {
				return "", errors.New("nested endpoint field")
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			text.Write(x)
		default:
			return "", errors.New("unexpected scalar XML token")
		}
	}
	if text.Len() > 4096 {
		return "", errors.New("endpoint URL too long")
	}
	return text.String(), nil
}
func endpointCandidate(c configData, b []byte) (configData, error) {
	if len(b) > configLimit {
		return nil, errors.New("portal page too large")
	}
	n := cloneConfig(c)
	for _, p := range [][2]string{{"ticket-url", "TICKET_URL"}, {"auth-url", "AUTH_URL"}} {
		v, e := endpointScalar(b, p[0])
		if e != nil {
			return nil, e
		}
		if e = trustedURL(c, v, p[1]); e != nil {
			return nil, e
		}
		u, _ := portalURL(v)
		old, _ := portalURL(c[p[1]])
		if old.Scheme == "https" && u.Scheme != "https" {
			return nil, errors.New("endpoint TLS downgrade refused")
		}
		if p[1] == "TICKET_URL" {
			u.RawQuery = old.RawQuery
		}
		n[p[1]] = u.String()
	}
	return n, nil
}
