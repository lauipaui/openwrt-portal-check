package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// A small synthetic ELF: even the pre-fix path allocates <300KiB of names.
// Never construct/run the real ~1GiB amplification case on a router.
func sectionNamesELF(table []byte, offsets []uint32) []byte {
	n := len(offsets)
	at := 64 + n*64
	b := make([]byte, at+len(table))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	binary.LittleEndian.PutUint64(b[0x28:], 64)
	binary.LittleEndian.PutUint16(b[0x3a:], 64)
	binary.LittleEndian.PutUint16(b[0x3c:], uint16(n))
	binary.LittleEndian.PutUint16(b[0x3e:], 0)
	for i, o := range offsets {
		binary.LittleEndian.PutUint32(b[64+i*64:], o)
	}
	binary.LittleEndian.PutUint64(b[64+0x18:], uint64(at))
	binary.LittleEndian.PutUint64(b[64+0x20:], uint64(len(table)))
	copy(b[at:], table)
	return b
}
func TestSectionNameLengthRejectedBeforeCopies(t *testing.T) {
	table := append([]byte{0}, []byte(strings.Repeat("A", 257)+"\x00")...)
	offsets := make([]uint32, 1024)
	for i := 1; i < len(offsets); i++ {
		offsets[i] = 1
	}
	b := sectionNamesELF(table, offsets)
	out, e := parseSections(b)
	if e == nil || out != nil || !strings.Contains(e.Error(), "section name length") {
		t.Fatalf("overlong section name not rejected before copies: error=%v", e)
	}
	// Failure must happen on the first long name, not after copying every alias.
	allocations := testing.AllocsPerRun(3, func() { _, _ = parseSections(b) })
	if allocations > 16 {
		t.Fatalf("name copies allocated before rejection: %.0f allocations", allocations)
	}
}
func TestSectionNameAggregateBudget(t *testing.T) {
	for _, same := range []bool{true, false} {
		label := "distinct offsets"
		if same {
			label = "same offset"
		}
		t.Run(label, func(t *testing.T) {
			table := []byte{0}
			offsets := make([]uint32, 131)
			for i := 1; i < len(offsets); i++ {
				if same && i > 1 {
					offsets[i] = 1
					continue
				}
				offsets[i] = uint32(len(table))
				table = append(table, []byte(strings.Repeat("A", 128)+"\x00")...)
			}
			if out, e := parseSections(sectionNamesELF(table, offsets)); e == nil || out != nil || !strings.Contains(e.Error(), "section name budget") {
				t.Fatalf("aggregate name budget not enforced: %v", e)
			}
		})
	}
}
func TestSectionNameBoundariesAndInvalidOffsets(t *testing.T) {
	table := append([]byte{0}, []byte(strings.Repeat("A", 128)+"\x00")...)
	if s, e := parseSections(sectionNamesELF(table, []uint32{0, 1})); e != nil || len(s[1].Name) != 128 {
		t.Fatal("legal boundary name rejected", e)
	}
	for _, tc := range []struct {
		table   []byte
		offsets []uint32
	}{{[]byte{0, 'x'}, []uint32{0, 1}}, {[]byte{0}, []uint32{0, 1}}} {
		if _, e := parseSections(sectionNamesELF(tc.table, tc.offsets)); e == nil {
			t.Fatal("unterminated/out-of-range name accepted")
		}
	}
}
