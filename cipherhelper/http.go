package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const moduleLimit = 512 << 10
const responseLimit = 128 << 10

func httpExchange(method, target string, body []byte, headers http.Header, timeout time.Duration, limit int) ([]byte, http.Header, error) {
	if _, e := portalURL(target); e != nil {
		return nil, nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if e != nil {
		return nil, nil, errors.New("invalid HTTP request")
	}
	req.Header = headers
	req.Close = true
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return nil, nil, errors.New("HTTP exchange failed or timed out")
	}
	defer resp.Body.Close()
	// Redirects are never followed, including credential-bearing portal POSTs.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if limit == 0 {
		if resp.StatusCode != 204 {
			return nil, resp.Header, fmt.Errorf("probe requires HTTP 204, got %d", resp.StatusCode)
		}
		return nil, resp.Header, nil
	}
	b, e := readLimited(resp.Body, limit)
	return b, resp.Header, e
}
func probe204(target string, timeout time.Duration) error {
	_, _, e := httpExchange("GET", target, nil, nil, timeout, 0)
	return e
}
func protocolHeaders(c configData, body []byte) http.Header {
	h := http.Header{}
	h.Set("Accept", "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Client-ID", c["CLIENT_ID"])
	h.Set("User-Agent", c["USER_AGENT"])
	h.Set("Algo-ID", c["ALGO_ID"])
	sum := md5.Sum(body)
	h.Set("CDC-Checksum", strings.ToUpper(hex.EncodeToString(sum[:])))
	for _, p := range [][2]string{{"SCHOOL_ID", "CDC-SchoolId"}, {"DOMAIN", "CDC-Domain"}, {"AREA", "CDC-Area"}} {
		if c[p[0]] != "" {
			h.Set(p[1], c[p[0]])
		}
	}
	return h
}

// Error-Code and Sub-Error are the legacy HTTP header protocol, not imagined
// XML success fields. Keep logs numeric; never print a server-supplied body.
func protocolError(h http.Header) error {
	codes := h.Values("Error-Code")
	if len(codes) > 1 {
		return errors.New("duplicate portal Error-Code")
	}
	s := h.Get("Error-Code")
	if s == "" || s == "0" {
		return nil
	}
	if len(s) > 12 || strings.Trim(s, "0123456789-") != "" {
		return errors.New("invalid portal Error-Code")
	}
	sub := h.Get("Sub-Error")
	if len(sub) > 12 || strings.Trim(sub, "0123456789-") != "" {
		sub = "<redacted>"
	}
	if sub != "" {
		return fmt.Errorf("portal rejected request: Error-Code %s Sub-Error %s", s, sub)
	}
	return fmt.Errorf("portal rejected request: Error-Code %s", s)
}
func moduleFetch(c configData) ([]byte, error) {
	n := cloneConfig(c)
	n["ALGO_ID"] = "00000000-0000-0000-0000-000000000000"
	body := []byte(n["ALGO_ID"])
	b, h, e := httpExchange("POST", n["TICKET_URL"], body, protocolHeaders(n, body), 15*time.Second, moduleLimit)
	if e != nil {
		return nil, e
	}
	if h.Get("Error-Code") != "200" {
		if e = protocolError(h); e != nil {
			return nil, e
		}
	}
	if len(b) < 6 || string(b[:3]) != "001" {
		return nil, errors.New("module response is not a DaMod container")
	}
	return b, nil
}
