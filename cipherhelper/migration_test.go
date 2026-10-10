package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointPageHTMLData(t *testing.T) {
	c := configData{"TICKET_URL": "http://old.invalid/ticket.cgi?clientip=192.0.2.1", "AUTH_URL": "http://old.invalid/auth.cgi", "TRUSTED_PORTAL_HOSTS": "new.invalid"}
	html := `<!doctype html><html><head><meta name="x"></head><body><br><ticket-url><![CDATA[http://new.invalid/ticket.cgi?unused=x]]></ticket-url><auth-url><![CDATA[http://new.invalid/auth.cgi]]></auth-url><script>not xml && no execution</script></body></html>`
	n, e := endpointCandidate(c, []byte(html))
	if e != nil {
		t.Fatal(e)
	}
	if n["TICKET_URL"] != "http://new.invalid/ticket.cgi?clientip=192.0.2.1" {
		t.Fatal(n)
	}
	for _, bad := range []string{strings.Replace(html, "http://new.invalid/auth.cgi", "http://new.invalid/auth.cgi';MARKER=executed;#", 1), strings.Replace(html, "new.invalid/auth.cgi", "evil.invalid/auth.cgi", 1), html + `<auth-url>http://new.invalid/auth.cgi</auth-url>`, strings.Replace(html, `]]></auth-url>`, `</auth-url>`, 1), strings.Replace(html, "/auth.cgi", "/other.cgi", 1)} {
		if _, e = endpointCandidate(c, []byte(bad)); e == nil {
			t.Fatal("unsafe or ambiguous HTML accepted")
		}
	}
	if e = trustedURL(c, "http://new.invalid/keep.cgi?a=1&b=2", "keep"); e != nil {
		t.Fatal(e)
	}
	if e = trustedURL(c, "http://untrusted.invalid/keep.cgi", "keep"); e == nil {
		t.Fatal("untrusted independent keep host accepted")
	}
}
func TestBundleWriteFailureRollback(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "ticket")
	b := filepath.Join(dir, "missing", "url")
	os.WriteFile(a, []byte("old"), 0600)
	if e := writeBundle([]fileUpdate{{a, []byte("new")}, {b, []byte("value")}}); e == nil {
		t.Fatal("failure hidden")
	}
	v, _ := os.ReadFile(a)
	if string(v) != "old" {
		t.Fatal("partial write retained")
	}
}

func TestBundleConcurrentConflictRollback(t *testing.T) {
	for _, at := range []int{1, 2} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			dir := t.TempDir()
			paths := []string{filepath.Join(dir, "ticket"), filepath.Join(dir, "url"), filepath.Join(dir, "interval")}
			updates := []fileUpdate{}
			for _, p := range paths {
				os.WriteFile(p, []byte("old"), 0600)
				updates = append(updates, fileUpdate{p, []byte("new")})
			}
			count := 0
			writer := func(p string, b []byte) error {
				e := atomicWrite(p, b)
				count++
				if count == at {
					os.WriteFile(paths[at], []byte("user-edit"), 0600)
				}
				return e
			}
			e := writeBundleUsing(updates, nil, writer)
			if e == nil || !strings.Contains(e.Error(), "concurrently") {
				t.Fatal(e)
			}
			for i, p := range paths {
				b, _ := os.ReadFile(p)
				expected := "old"
				if i == at {
					expected = "user-edit"
				}
				if string(b) != expected {
					t.Fatalf("file %d got %s want %s", i, b, expected)
				}
			}
		})
	}
}
func TestBundlePreservesExternalEditOnIncompleteRollback(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "ticket")
	b := filepath.Join(dir, "url")
	os.WriteFile(a, []byte("old"), 0600)
	os.WriteFile(b, []byte("old"), 0600)
	writer := func(p string, data []byte) error {
		if p == a {
			if e := atomicWrite(p, data); e != nil {
				return e
			}
			os.WriteFile(a, []byte("user-ticket"), 0600)
			os.WriteFile(b, []byte("user-url"), 0600)
		}
		return nil
	}
	e := writeBundleUsing([]fileUpdate{{a, []byte("new")}, {b, []byte("new")}}, nil, writer)
	if e == nil || !strings.Contains(e.Error(), "rollback incomplete") {
		t.Fatal(e)
	}
	v, _ := os.ReadFile(a)
	w, _ := os.ReadFile(b)
	if string(v) != "user-ticket" || string(w) != "user-url" {
		t.Fatal("external edit overwritten")
	}
}
func TestSymlinkOutputRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "predictable")
	os.WriteFile(target, []byte("do-not-truncate"), 0600)
	if e := os.Symlink(target, link); e != nil {
		t.Skip("OS cannot create symlink:", e)
	}
	if e := atomicWrite(link, []byte("bad")); e == nil {
		t.Fatal("symlink output accepted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "do-not-truncate" {
		t.Fatal("target clobbered")
	}
}
