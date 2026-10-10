package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureConfig() configData {
	return configData{"ALGO_ID": "11111111-1111-1111-1111-111111111111", "CIPHER_SCHEME": "RAW", "RAW_TEMPLATE": "tpl_des_iv.so", "RAW_KEY": strings.Repeat("0123456789abcdef", 6), "RAW_IV": strings.Repeat("0123456789abcdef", 2), "CLIENT_ID": "AUDIT", "USER_AGENT": "AUDIT", "HOST_NAME": "test", "OSTAG": "Android", "IPV4": "192.0.2.1", "MAC": "02:00:00:00:00:01", "GATEWAY": "192.0.2.254", "SYSNAME": "Linux", "MACHINE": "mips", "IFNAME": "wlan0", "SDK": "36"}
}
func TestCandidateAuthProbeRollback(t *testing.T) {
	t.Setenv("PORTAL_TIME_OFFSET", "+0800")
	online := false
	reject := false
	keeps := 0
	c := fixtureConfig()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			if online {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(200)
			}
			return
		}
		if reject {
			w.Header().Set("Error-Code", "123")
			fmt.Fprint(w, "rejected")
			return
		}
		if r.Header.Get("Algo-ID") != c["ALGO_ID"] {
			t.Error("candidate ALGO_ID not sent")
		}
		if r.Header.Get("CDC-SchoolId") != "AUDIT-SCHOOL" {
			t.Error("legacy SCHOOL_ID lost")
		}
		plain := `<response><ticket>fixture-ticket</ticket><expire>60</expire></response>`
		if r.URL.Path == "/auth.cgi" {
			plain = `<response><keep-url>` + srv.URL + `/keep.cgi</keep-url><keep-retry>120</keep-retry><userid>fixture</userid><user-config/><domain-config/></response>`
		}
		if r.URL.Path == "/keep.cgi" {
			keeps++
			plain = `<response><interval>90</interval></response>`
		}
		crypt, e := configCipher(c)
		if e != nil {
			t.Fatal(e)
		}
		enc, e := transform(crypt, true, plain)
		if e != nil {
			t.Fatal(e)
		}
		w.Header().Set("Error-Code", "0")
		fmt.Fprint(w, enc)
	}))
	defer srv.Close()
	c["TICKET_URL"] = srv.URL + "/ticket.cgi"
	c["AUTH_URL"] = srv.URL + "/auth.cgi"
	c["SCHOOL_ID"] = "AUDIT-SCHOOL"
	dir := t.TempDir()
	active := filepath.Join(dir, "portal.conf")
	candidate := filepath.Join(dir, "candidate.conf")
	old := cloneConfig(c)
	old["ALGO_ID"] = "22222222-2222-2222-2222-222222222222"
	if e := writeConfig(active, old); e != nil {
		t.Fatal(e)
	}
	writeConfig(candidate, c)
	paths := sessionPaths{filepath.Join(dir, "ticket"), filepath.Join(dir, "url"), filepath.Join(dir, "interval")}
	atomicWrite(paths.ticket, []byte("old-ticket\n"))
	atomicWrite(paths.keepURL, []byte("old-url\n"))
	atomicWrite(paths.interval, []byte("60\n"))
	before, _ := os.ReadFile(active)
	opts := activationOptions{"fixture", "a&b<c>", srv.URL + "/generate_204", 1, 0, time.Second, paths}
	if e := activateCandidate(active, candidate, opts); e == nil {
		t.Fatal("empty200 candidate was activated")
	}
	after, _ := os.ReadFile(active)
	ticket, _ := os.ReadFile(paths.ticket)
	if !bytes.Equal(before, after) || string(ticket) != "old-ticket\n" {
		t.Fatal("failed candidate changed active configuration/session")
	}
	reject = true
	online = true
	if e := activateCandidate(active, candidate, opts); e == nil || !strings.Contains(e.Error(), "123") {
		t.Fatal("explicit portal rejection lost", e)
	}
	reject = false
	if e := activateCandidate(active, candidate, opts); e != nil {
		t.Fatal(e)
	}
	now, _ := readConfig(active)
	ticket, _ = os.ReadFile(paths.ticket)
	if now["ALGO_ID"] != c["ALGO_ID"] || string(ticket) != "fixture-ticket\n" {
		t.Fatal("new runtime parameters/session not activated")
	}
	if e := keepSession(c, paths); e != nil {
		t.Fatal(e)
	}
	if keeps != 1 {
		t.Fatal("raw cipher not used for keep")
	}
}
