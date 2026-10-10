package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "portal.conf")
	os.WriteFile(p, []byte("TICKET_URL='http://old.invalid/ticket.cgi'\nAUTH_URL='http://old.invalid/auth.cgi'\nCLIENT_ID='AUDIT'\n"), 0600)
	c, e := readConfig(p)
	if e != nil || c["CLIENT_ID"] != "AUDIT" {
		t.Fatal(c, e)
	}
	for _, s := range []string{"AUTH_URL='http://evil.invalid/a';AUDIT_MARKER=executed;#\n", "CLIENT_ID=$(touch marker)\n", "CLIENT_ID='one'\nCLIENT_ID='two'\n", "UNKNOWN='x'\n"} {
		os.WriteFile(p, []byte(s), 0600)
		if _, e := readConfig(p); e == nil {
			t.Fatal("accepted executable or ambiguous config")
		}
	}
	for _, k := range strings.Fields("TICKET_URL AUTH_URL CLIENT_ID USER_AGENT SCHOOL_ID DOMAIN AREA HOST_NAME OSTAG IPV4 IPV6 MAC GATEWAY SYSNAME MACHINE IFNAME GSM_NETWORK_TYPE SDK ALGO_ID CIPHER_SCHEME DOUBLE_DES_KEY DOUBLE_DES_IV DES_KEY_FIRST DES_KEY_SECOND TEA_KEY_0 TEA_KEY_1 TEA_KEY_2 TEA_IV") {
		if !configKeys[k] {
			t.Fatal("lost legacy field", k)
		}
	}
}
