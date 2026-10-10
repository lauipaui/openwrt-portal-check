package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func secondsArg(s string, def, max int) time.Duration {
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > max {
		n = def
	}
	return time.Duration(n) * time.Second
}
func portalCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	a := args[1:]
	need := func(n int) error {
		if len(a) != n {
			return errors.New("invalid command arguments")
		}
		return nil
	}
	if len(a) > 0 && (args[0] == "client" || args[0] == "candidate-activate" || args[0] == "config-set" || args[0] == "config-wan") {
		unlock, e := stateLock(a[0])
		if e != nil {
			return true, e
		}
		defer unlock()
	}
	switch args[0] {
	case "config-get":
		if e := need(2); e != nil {
			return true, e
		}
		if !configKeys[a[1]] {
			return true, errors.New("unknown field")
		}
		c, e := readConfig(a[0])
		if e == nil {
			fmt.Print(c[a[1]])
		}
		return true, e
	case "config-normalize":
		if e := need(2); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e == nil {
			e = writeConfig(a[1], c)
		}
		return true, e
	case "config-set":
		if len(a) < 3 || len(a)%2 != 1 {
			return true, errors.New("usage: config-set file KEY value ...")
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		for i := 1; i < len(a); i += 2 {
			c[a[i]] = a[i+1]
		}
		return true, writeConfig(a[0], c)
	case "config-wan":
		if e := need(2); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		n, changed, e := wanConfig(c, a[1])
		if e != nil {
			return true, e
		}
		if !changed {
			return true, errors.New("WAN configuration unchanged")
		}
		return true, writeConfig(a[0], n)
	case "probe":
		if e := need(2); e != nil {
			return true, e
		}
		return true, probe204(a[0], secondsArg(a[1], 10, 60))
	case "portal-page":
		if e := need(3); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		h := http.Header{}
		h.Set("User-Agent", c["USER_AGENT"])
		b, _, e := httpExchange("GET", a[1], nil, h, 15*time.Second, configLimit)
		if e == nil {
			e = atomicWrite(a[2], b)
		}
		return true, e
	case "module-fetch":
		if e := need(2); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		b, e := moduleFetch(c)
		if e == nil {
			e = atomicWrite(a[1], b)
		}
		return true, e
	case "candidate-prepare":
		if e := need(4); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		meta, e := readFileLimited(a[1], 16<<10)
		if e != nil {
			return true, e
		}
		n, e := prepareCandidate(c, meta)
		if e != nil {
			return true, e
		}
		b, e := readFileLimited(a[2], moduleLimit)
		if e != nil {
			return true, e
		}
		id, e := moduleUUID(b)
		if e != nil || id != n["ALGO_ID"] {
			return true, errors.New("container and candidate UUID mismatch")
		}
		return true, writeConfig(a[3], n)
	case "endpoint-prepare":
		if e := need(3); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		b, e := readFileLimited(a[1], configLimit)
		if e != nil {
			return true, e
		}
		n, e := endpointCandidate(c, b)
		if e != nil {
			return true, e
		}
		return true, writeConfig(a[2], n)
	case "candidate-activate":
		if e := need(6); e != nil {
			return true, e
		}
		attempts, e := strconv.Atoi(a[4])
		if e != nil || attempts < 1 || attempts > 10 {
			return true, errors.New("invalid verification attempts")
		}
		delay, e := strconv.Atoi(a[5])
		if e != nil || delay < 0 || delay > 60 {
			return true, errors.New("invalid verification delay")
		}
		o := activationOptions{os.Getenv("PORTAL_USER"), os.Getenv("PORTAL_PASSWORD"), a[2], attempts, time.Duration(delay) * time.Second, secondsArg(a[3], 10, 60), pathsFor(a[0])}
		return true, activateCandidate(a[0], a[1], o)
	case "cache-publish":
		if e := need(3); e != nil {
			return true, e
		}
		b, e := readFileLimited(a[0], moduleLimit)
		if e != nil {
			return true, e
		}
		id, e := moduleUUID(b)
		if e != nil || id != strings.ToUpper(a[2]) {
			return true, errors.New("invalid cache container")
		}
		return true, atomicWrite(a[1], b)
	case "xml-validate", "xml-get":
		if (args[0] == "xml-validate" && len(a) != 0) || (args[0] == "xml-get" && len(a) != 1) {
			return true, errors.New("invalid XML command arguments")
		}
		b, e := readLimited(os.Stdin, configLimit)
		if e != nil {
			return true, e
		}
		m, e := parseResponse(b)
		if e == nil && args[0] == "xml-get" {
			fmt.Print(m[a[0]])
		}
		return true, e
	case "client":
		if e := need(2); e != nil {
			return true, e
		}
		c, e := readConfig(a[0])
		if e != nil {
			return true, e
		}
		p := pathsFor(a[0])
		if a[1] == "keep" {
			e = keepSession(c, p)
			if e == nil {
				fmt.Println("Keep-alive exchange accepted.")
			}
			return true, e
		}
		if a[1] == "self-test" {
			crypt, e := configCipher(c)
			if e != nil {
				return true, e
			}
			sample := "<?xml version=\"1.0\"?><request><sample>portal-analysis</sample></request>"
			enc, e := transform(crypt, true, sample)
			if e != nil {
				return true, e
			}
			dec, e := transform(crypt, false, enc)
			if e != nil || dec != sample {
				return true, errors.New("cipher self-test failed")
			}
			fmt.Println("Cipher roundtrip self-test passed (not a protocol vector or online validation).")
			return true, nil
		}
		if a[1] != "auth" && a[1] != "ticket" {
			return true, errors.New("mode must be ticket, auth, keep or self-test")
		}
		s, e := authSession(c, os.Getenv("PORTAL_USER"), os.Getenv("PORTAL_PASSWORD"), a[1] == "ticket")
		if e != nil {
			return true, e
		}
		if a[1] == "ticket" {
			fmt.Println("Ticket acquired.")
			return true, nil
		}
		e = writeBundle([]fileUpdate{{p.ticket, []byte(s.ticket + "\n")}, {p.keepURL, []byte(s.keepURL + "\n")}, {p.interval, []byte(s.interval + "\n")}})
		if e == nil {
			fmt.Printf("Authentication exchange accepted; keep interval %s seconds. Connectivity is not yet verified.\n", s.interval)
		}
		return true, e
	}
	return false, nil
}
func moduleUUID(b []byte) (string, error) {
	if len(b) < 6 || len(b) > moduleLimit || !bytes.Equal(b[:3], []byte("001")) {
		return "", errors.New("invalid module container")
	}
	n := int(b[3])
	if n == 0 || n%2 != 0 || 4+n+38 >= len(b) {
		return "", errors.New("truncated container")
	}
	if _, e := hex.DecodeString(string(b[4 : 4+n])); e != nil {
		return "", errors.New("invalid container header")
	}
	at := 4 + n
	if b[at] != '$' || b[at+37] != ']' {
		return "", errors.New("invalid module UUID delimiters")
	}
	s := strings.ToUpper(string(b[at+1 : at+37]))
	if !uuidPattern.MatchString(s) || s == "00000000-0000-0000-0000-000000000000" {
		return "", errors.New("invalid container UUID")
	}
	return s, nil
}
