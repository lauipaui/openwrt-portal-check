package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExplicitRouterTimeOffset(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 30, 0, 0, time.UTC)
	for _, tc := range [][2]string{{"+0800", "2026-10-10 08:30:00"}, {"-0530", "2026-10-09 19:00:00"}, {"-0030", "2026-10-10 00:00:00"}} {
		t.Setenv("PORTAL_TIME_OFFSET", tc[0])
		got, e := portalLocalTime(now)
		if e != nil || got != tc[1] {
			t.Fatal(tc, got, e)
		}
	}
	for _, bad := range []string{"UTC", "+08:00", "+2460", "+0800;echo bad", "+000", "+0800\n", "++0800"} {
		t.Setenv("PORTAL_TIME_OFFSET", bad)
		if _, e := portalLocalTime(now); e == nil {
			t.Fatal("invalid time offset accepted", bad)
		}
	}
	t.Setenv("PORTAL_TIME_OFFSET", "+0800")
	b, e := requestXML(configData{}, nil)
	if e != nil || !strings.Contains(string(b), "<local-time>") {
		t.Fatal(e)
	}
}

func TestOffsetNeverSilentlyFallsBack(t *testing.T) {
	t.Setenv("PORTAL_TIME_OFFSET", "")
	if _, e := portalLocalTime(time.Now()); e == nil {
		t.Fatal("empty explicit offset accepted")
	}
	t.Setenv("PATH", t.TempDir())
	old, ok := os.LookupEnv("PORTAL_TIME_OFFSET")
	os.Unsetenv("PORTAL_TIME_OFFSET")
	t.Cleanup(func() {
		if ok {
			os.Setenv("PORTAL_TIME_OFFSET", old)
		} else {
			os.Unsetenv("PORTAL_TIME_OFFSET")
		}
	})
	if _, e := portalLocalTime(time.Now()); e == nil {
		t.Fatal("missing date silently fell back to Go UTC")
	}
	var out tinyOutput
	if _, e := out.Write(make([]byte, 33)); e == nil {
		t.Fatal("date output size cap not enforced")
	}
}
