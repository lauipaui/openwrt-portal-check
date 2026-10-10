package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type field struct{ name, value string }

func requestXML(c configData, fields []field) ([]byte, error) {
	localTime, err := portalLocalTime(time.Now())
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><request>`)
	write := func(k, v string) error {
		if !xmlName(k) {
			return errors.New("invalid XML field")
		}
		b.WriteByte('<')
		b.WriteString(k)
		b.WriteByte('>')
		if e := xml.EscapeText(&b, []byte(v)); e != nil {
			return e
		}
		fmt.Fprintf(&b, "</%s>", k)
		return nil
	}
	for _, f := range append([]field{{"user-agent", c["USER_AGENT"]}, {"client-id", c["CLIENT_ID"]}, {"local-time", localTime}}, fields...) {
		if e := write(f.name, f.value); e != nil {
			return nil, e
		}
	}
	b.WriteString("<sysinfo>")
	for _, f := range []field{{"sysname", c["SYSNAME"]}, {"machine", c["MACHINE"]}, {"ifname", c["IFNAME"]}, {"gsm.network.type", c["GSM_NETWORK_TYPE"]}, {"ro.build.version.sdk", c["SDK"]}} {
		if e := write(f.name, f.value); e != nil {
			return nil, e
		}
	}
	b.WriteString("</sysinfo></request>")
	if b.Len() > configLimit {
		return nil, errors.New("XML request exceeds size limit")
	}
	return b.Bytes(), nil
}
func xmlName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// Parse one complete response document. Only direct child values are exposed;
// entities/CDATA are decoded, duplicate fields, scalar nesting and DTDs rejected.
func parseResponse(b []byte) (map[string]string, error) {
	if len(b) > configLimit {
		return nil, errors.New("XML response too large")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	result := map[string]string{}
	depth := 0
	roots := 0
	current := ""
	var text strings.Builder
	tokens := 0
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("malformed portal XML")
		}
		tokens++
		if tokens > 4096 {
			return nil, errors.New("XML token limit exceeded")
		}
		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > 16 {
				return nil, errors.New("XML nesting limit exceeded")
			}
			if x.Name.Space != "" {
				return nil, errors.New("XML namespaces not supported")
			}
			if depth == 1 {
				roots++
				if roots != 1 || x.Name.Local != "response" || len(x.Attr) != 0 {
					return nil, errors.New("expected one response root")
				}
			}
			if depth == 2 {
				current = x.Name.Local
				if _, ok := result[current]; ok {
					return nil, errors.New("duplicate response field")
				}
				if len(result) >= 128 {
					return nil, errors.New("XML field limit exceeded")
				}
				result[current] = ""
				text.Reset()
				if len(x.Attr) != 0 {
					return nil, errors.New("unexpected scalar attributes")
				}
			}
			if depth > 2 && current != "user-config" && current != "domain-config" {
				return nil, errors.New("nested scalar response field")
			}
		case xml.EndElement:
			if depth == 2 {
				result[current] = text.String()
				current = ""
			}
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(x)) != "" {
				return nil, errors.New("data outside response root")
			}
			if depth == 1 && strings.TrimSpace(string(x)) != "" {
				return nil, errors.New("unexpected response text")
			}
			if depth >= 2 {
				text.Write(x)
			}
		case xml.Directive:
			return nil, errors.New("XML directives forbidden")
		case xml.ProcInst:
			if depth != 0 || roots != 0 || x.Target != "xml" {
				return nil, errors.New("unexpected XML processing instruction")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return nil, errors.New("incomplete response XML")
	}
	return result, nil
}
