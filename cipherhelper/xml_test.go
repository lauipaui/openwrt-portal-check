package main

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestXMLBoundary(t *testing.T) {
	t.Setenv("PORTAL_TIME_OFFSET", "+0800")
	c := configData{"CLIENT_ID": "a&b", "USER_AGENT": "a<b", "SYSNAME": "x", "SDK": "36"}
	b, e := requestXML(c, []field{{"passwd", "a&b<c>\"'"}})
	if e != nil {
		t.Fatal(e)
	}
	d := xml.NewDecoder(strings.NewReader(string(b)))
	found := ""
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if st, ok := tok.(xml.StartElement); ok && st.Name.Local == "passwd" {
			if e = d.DecodeElement(&found, &st); e != nil {
				t.Fatal(e)
			}
		}
	}
	if found != "a&b<c>\"'" {
		t.Fatal(found)
	}
	good := `<?xml version="1.0"?><response><keep-url><![CDATA[http://portal.invalid/keep.cgi?a=1&b=2]]></keep-url><interval>60</interval></response>`
	r, e := parseResponse([]byte(good))
	if e != nil || r["interval"] != "60" {
		t.Fatal(r, e)
	}
	r, e = parseResponse([]byte(`<response><keep-url>http://portal.invalid/keep.cgi?a=1&amp;b=2</keep-url></response>`))
	if e != nil || r["keep-url"] != "http://portal.invalid/keep.cgi?a=1&b=2" {
		t.Fatal(r, e)
	}
	for _, s := range []string{`<keep-url>http://evil.invalid/keep.cgi</keep-url><response></response>`, `<response><ticket>x</ticket></response><response/>`, `<response><ticket>x</ticket><ticket>y</ticket></response>`, `<response><ticket><nested>x</nested></ticket></response>`, `<!DOCTYPE response><response/>`, `<response><ticket>a&b</ticket></response>`} {
		if _, e := parseResponse([]byte(s)); e == nil {
			t.Fatal("accepted invalid XML", s)
		}
	}
}
