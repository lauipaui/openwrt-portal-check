package main

import (
	"bytes"
	"encoding/binary"
	"github.com/ulikunitz/xz/lzma"
	"os"
	"strings"
	"testing"
)

func fixtureELF() []byte {
	b := make([]byte, 768)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	binary.LittleEndian.PutUint64(b[0x28:], 512)
	binary.LittleEndian.PutUint16(b[0x3a:], 64)
	binary.LittleEndian.PutUint16(b[0x3c:], 4)
	binary.LittleEndian.PutUint16(b[0x3e:], 3)
	names := []byte("\x00.data\x00.dynstr\x00.shstrtab\x00")
	copy(b[432:], names)
	tpl := []byte("tpl_des_iv.so\x00")
	copy(b[400:], tpl)
	for i := 0; i < 48; i++ {
		b[128+32+i] = byte(i + 1)
	}
	for i := 0; i < 16; i++ {
		b[128+80+i] = byte(i + 1)
	}
	b[128+249] = 8
	b[128+251] = 48
	b[128+254] = 32
	for i, v := range [][3]uint64{{1, 128, 256}, {7, 400, uint64(len(tpl))}, {15, 432, uint64(len(names))}} {
		at := 512 + (i+1)*64
		binary.LittleEndian.PutUint32(b[at:], uint32(v[0]))
		binary.LittleEndian.PutUint64(b[at+0x18:], v[1])
		binary.LittleEndian.PutUint64(b[at+0x20:], v[2])
	}
	return b
}
func fixturePayload(t testing.TB, plain []byte, dict uint32) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w, e := (lzma.WriterConfig{DictCap: 4096, Size: int64(len(plain)), SizeInHeader: true}).NewWriter(&compressed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(plain); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	stream := compressed.Bytes()
	payload := make([]byte, 8+len(stream)-13)
	binary.LittleEndian.PutUint32(payload, dict)
	binary.LittleEndian.PutUint32(payload[4:], uint32(len(plain)))
	data := append([]byte(nil), stream[13:]...)
	for i := 0; i < len(data)-1; i++ {
		data[i] ^= data[i+1]
	}
	copy(payload[8:], data)
	return payload
}
func fixtureModule(t testing.TB) []byte {
	p := fixturePayload(t, fixtureELF(), 16<<20)
	b := []byte("001@")
	b = append(b, []byte(strings.Repeat("00", 32))...)
	b = append(b, []byte("$11111111-1111-1111-1111-111111111111]")...)
	return append(b, p...)
}
func TestDeclared16MiBDictionaryWithSmallOutput(t *testing.T) {
	b := fixtureELF()
	out, _, _, e := decodeModule(fixturePayload(t, b, 16<<20))
	if e != nil || !bytes.Equal(out, b) {
		t.Fatal(e)
	}
	res, e := extract(out)
	if e != nil || res.Algorithm != "double-3des-cbc" || res.KeyLen != 48 {
		t.Fatal(res, e)
	}
	if p := os.Getenv("PORTAL_TEST_MODULE_OUT"); p != "" {
		if e = os.WriteFile(p, fixtureModule(t), 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestDeclaredDictionaryAndOutputLimits(t *testing.T) {
	p := fixturePayload(t, []byte("small"), 32<<20)
	if _, _, _, e := decodeModule(p); e == nil {
		t.Fatal("oversized dictionary declaration accepted")
	}
	p = fixturePayload(t, []byte("small"), 16<<20)
	binary.LittleEndian.PutUint32(p[4:], (1<<20)+1)
	if _, _, _, e := decodeModule(p); e == nil {
		t.Fatal("oversized declared output accepted")
	}
}
