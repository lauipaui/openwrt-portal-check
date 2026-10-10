package main

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Fixed vectors from independent Node/OpenSSL DES and a standalone translation
// of the baseline shell TEA rounds. Synthetic key bytes are 1..48, IV 1..16.
// The baseline: double-3DES CBC only aligns; 3DES2/TEA add a mandatory NUL.
func TestLegacyFallbackPaddingVectors(t *testing.T) {
	key := make([]byte, 48)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	cases := []struct{ scheme, plain, want string }{
		{"9ABF4D29", "1234567", "364E185DB02FAFAE"},
		{"9ABF4D29", "12345678", "C64E9B0A6334694E"},
		{"9ABF4D29", "123456789", "C64E9B0A6334694EEFCF73D899012E97"},
		{"9ABF4D29", "1234567812345678", "C64E9B0A6334694E1C0412E474862F4F"},
		{"3DES2", "1234567", "53126D72C3E5DA4F"},
		{"3DES2", "12345678", "316561F2A19A5CF6E93C7285E311378B"},
		{"3DES2", "123456789", "316561F2A19A5CF6243A606EC9C2551A"},
		{"3DES2", "1234567812345678", "316561F2A19A5CF6316561F2A19A5CF6E93C7285E311378B"},
		{"TEA3-CBC", "1234567", "CBBF4865232E6F44"},
		{"TEA3-CBC", "12345678", "DCB0C37B2FA36530DBB4D5CE7BC41B77"},
		{"TEA3-CBC", "123456789", "DCB0C37B2FA36530CE60B6C31887363E"},
		{"TEA3-CBC", "1234567812345678", "DCB0C37B2FA365300BD0FDCFC08BFE827F725E0393276627"},
		{"TEA3-ECB", "1234567", "D426CF2E0D86932F"},
		{"TEA3-ECB", "12345678", "A6B643C9151B7524B620E20E8041598F"},
		{"TEA3-ECB", "123456789", "A6B643C9151B7524ACB7B97A0FD891F6"},
		{"TEA3-ECB", "1234567812345678", "A6B643C9151B7524A6B643C9151B7524B620E20E8041598F"},
	}
	for _, tc := range cases {
		t.Run(tc.scheme+"/"+tc.plain, func(t *testing.T) {
			c := configData{"ALGO_ID": "22222222-2222-2222-2222-222222222222", "CIPHER_SCHEME": tc.scheme, "DOUBLE_DES_KEY": hex.EncodeToString(key), "DOUBLE_DES_IV": hex.EncodeToString(iv), "DES_KEY_FIRST": hex.EncodeToString(key[:24]), "DES_KEY_SECOND": hex.EncodeToString(key[24:]), "TEA_KEY_0": hex.EncodeToString(key[:16]), "TEA_KEY_1": hex.EncodeToString(key[16:32]), "TEA_KEY_2": hex.EncodeToString(key[32:]), "TEA_IV": hex.EncodeToString(iv[:8])}
			if tc.scheme == "9ABF4D29" {
				c["ALGO_ID"] = "9ABF4D29-34DB-4CE9-BB8C-7E371D637758"
			}
			if strings.HasPrefix(tc.scheme, "TEA3") {
				c["ALGO_ID"] = "3084D519-54D7-4434-9564-26A8615BCEF2"
			}
			crypt, e := configCipher(c)
			if e != nil {
				t.Fatal(e)
			}
			got, e := transform(crypt, true, tc.plain)
			if e != nil || got != tc.want {
				t.Fatalf("old padding vector mismatch: got %s want %s error=%v", got, tc.want, e)
			}
		})
	}
}
func TestKeepTLSDowngradePolicy(t *testing.T) {
	for _, tc := range []struct {
		ticket, auth, keep string
		allow              bool
	}{{"https", "https", "http", false}, {"http", "https", "http", false}, {"https", "http", "http", false}, {"https", "https", "https", true}, {"http", "http", "http", true}, {"http", "http", "https", true}} {
		t.Run(tc.ticket+"/"+tc.auth+"/"+tc.keep, func(t *testing.T) {
			c := configData{"TICKET_URL": tc.ticket + "://ticket.invalid/ticket.cgi", "AUTH_URL": tc.auth + "://auth.invalid/auth.cgi", "TRUSTED_PORTAL_HOSTS": "independent-keep.invalid"}
			e := trustedURL(c, tc.keep+"://independent-keep.invalid/keep.cgi", "keep")
			if (e == nil) != tc.allow {
				t.Fatalf("TLS scheme policy not enforced: error=%v", e)
			}
		})
	}
}
func TestKeepDowngradeRefusedBeforeNetwork(t *testing.T) {
	t.Setenv("PORTAL_TIME_OFFSET", "+0800")
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	c := fixtureConfig()
	c["TICKET_URL"] = strings.Replace(srv.URL, "http:", "https:", 1) + "/ticket.cgi"
	c["AUTH_URL"] = strings.Replace(srv.URL, "http:", "https:", 1) + "/auth.cgi"
	dir := t.TempDir()
	p := sessionPaths{filepath.Join(dir, "ticket"), filepath.Join(dir, "keep"), filepath.Join(dir, "interval")}
	os.WriteFile(p.ticket, []byte("fixture-ticket\n"), 0600)
	os.WriteFile(p.keepURL, []byte(srv.URL+"/keep.cgi\n"), 0600)
	e := keepSession(c, p)
	if e == nil || !strings.Contains(e.Error(), "TLS downgrade") {
		t.Fatalf("insecure keep must fail with explicit policy error, got %v", e)
	}
	if requests.Load() != 0 {
		t.Fatal("insecure keep request was sent before rejecting downgrade")
	}
}

func TestKeepAlternateNeverDowngrades(t *testing.T) {
	for _, tc := range []struct {
		ticket, auth, keep, wantScheme string
		allow                          bool
	}{{"https", "https", "https", "https", true}, {"https", "http", "https", "https", true}, {"http", "http", "https", "https", true}, {"http", "http", "http", "http", true}, {"https", "https", "http", "", false}, {"http", "https", "http", "", false}} {
		t.Run(tc.ticket+"/"+tc.auth+"/"+tc.keep, func(t *testing.T) {
			c := configData{"TICKET_URL": tc.ticket + "://ticket.invalid/ticket.cgi", "AUTH_URL": tc.auth + "://auth.invalid:7001/auth.cgi", "TRUSTED_PORTAL_HOSTS": "independent-keep.invalid"}
			target := tc.keep + "://independent-keep.invalid:7002/keep.cgi?a=1&b=2"
			alternate, e := keepAlternate(c, target)
			if !tc.allow {
				if e == nil || alternate != "" {
					t.Fatal("alternate bypassed active TLS policy", alternate, e)
				}
				return
			}
			want := tc.wantScheme + "://auth.invalid:7001/keep.cgi?a=1&b=2"
			if e != nil || alternate != want {
				t.Fatalf("fallback changed scheme/path/query: got %s want %s error=%v", alternate, want, e)
			}
		})
	}
	c := configData{"TICKET_URL": "http://ticket.invalid/ticket.cgi", "AUTH_URL": "http://auth.invalid/auth.cgi"}
	if _, e := keepAlternate(c, "https://untrusted.invalid/keep.cgi"); e == nil {
		t.Fatal("fallback used untrusted original endpoint")
	}
}
