package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// OpenWrt libc's /etc/TZ POSIX string is not necessarily Go's time.Local.
// Use an explicit validated numeric offset, or query the same bounded date
// command the old shell client used. Missing/invalid time information fails.
type tinyOutput struct{ b bytes.Buffer }

func (b *tinyOutput) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > 32 {
		return 0, errors.New("date output exceeds limit")
	}
	return b.b.Write(p)
}
func portalLocalTime(now time.Time) (string, error) {
	s, explicit := os.LookupEnv("PORTAL_TIME_OFFSET")
	if !explicit {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "date", "+%z")
		cmd.WaitDelay = time.Second
		var b tinyOutput
		cmd.Stdout = &b
		cmd.Stderr = io.Discard
		if e := cmd.Run(); e != nil {
			return "", errors.New("cannot determine router local offset; provide PORTAL_TIME_OFFSET from date +%z")
		}
		s = strings.TrimSuffix(b.b.String(), "\n")
		s = strings.TrimSuffix(s, "\r")
	}
	if len(s) != 5 || (s[0] != '+' && s[0] != '-') {
		return "", errors.New("invalid PORTAL_TIME_OFFSET; expected signed HHMM")
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return "", errors.New("invalid time offset digits")
		}
	}
	h, _ := strconv.Atoi(s[1:3])
	m, _ := strconv.Atoi(s[3:])
	if h > 23 || m > 59 {
		return "", errors.New("time offset out of range")
	}
	offset := (h*60 + m) * 60
	if s[0] == '-' {
		offset = -offset
	}
	return now.In(time.FixedZone("router", offset)).Format("2006-01-02 15:04:05"), nil
}
