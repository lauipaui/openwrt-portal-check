package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestContainerRejectsUntrustedUUID(t *testing.T) {
	for _, id := range []string{strings.Repeat("G", 36), "';INJECTION=executed;#0000000000000000"} {
		raw := append([]byte{'0', '0', '1', 2, '0', '0', '$'}, []byte(id)...)
		raw = append(raw, ']', 1, 2, 3)
		if _, e := parseContainer(raw); e == nil {
			t.Fatal("untrusted UUID accepted")
		}
	}
	if _, e := parseContainer(make([]byte, (512<<10)+1)); e == nil {
		t.Fatal("oversized container accepted")
	}
}
func TestSectionTableRejectsUndersizedEntries(t *testing.T) {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	binary.LittleEndian.PutUint64(b[0x28:], 63)
	binary.LittleEndian.PutUint16(b[0x3a:], 1)
	binary.LittleEndian.PutUint16(b[0x3c:], 1)
	defer func() {
		if recover() != nil {
			t.Error("undersized entry panicked")
		}
	}()
	if _, e := parseSections(b); e == nil {
		t.Fatal("undersized entries accepted")
	}
}
func TestDecodeLimits(t *testing.T) {
	for _, pair := range [][2]uint32{{2 << 20, 32}, {4096, 2 << 20}, {4096, 0}} {
		b := make([]byte, 9)
		binary.LittleEndian.PutUint32(b, pair[0])
		binary.LittleEndian.PutUint32(b[4:], pair[1])
		if _, _, _, e := decodeModule(b); e == nil {
			t.Fatal("invalid decode limits accepted")
		}
	}
}
func FuzzUntrustedContainer(f *testing.F) {
	f.Add([]byte("001@audit"))
	f.Add(fixtureModule(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, e := parseContainer(b); e == nil {
			_, _, _, _ = decodeModule(c.Payload)
		}
	})
}
func FuzzELFSectionTable(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Add(fixtureELF())
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseSections(b); _, _ = extract(b) })
}
