package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ulikunitz/xz/lzma"
)

func main() {
	in := os.Args[1]
	out := os.Args[2]
	raw, err := os.ReadFile(in)
	if err != nil {
		panic(err)
	}
	hexLen := int(raw[3])
	at := 4 + hexLen
	uuid := string(raw[at+1 : at+37])
	sep := raw[at+37]
	payload := raw[at+38:]

	props := make([]byte, 5)
	props[0] = sep
	copy(props[1:], payload[0:4])
	szField := binary.LittleEndian.Uint32(payload[4:8])
	modType := szField >> 28
	modSize := szField & 0x0FFFFFFF

	fmt.Printf("file=%s uuid=%s hexlen=%d props=%s type=%d size=%d payload=%d\n",
		filepath.Base(in), uuid, hexLen, hex.EncodeToString(props), modType, modSize, len(payload))
	if modType != 0 {
		fmt.Println("unsupported type", modType)
		return
	}
	data := append([]byte{}, payload[8:]...)
	n := len(data)
	for i := n - 2; i >= 0; i-- {
		data[i] ^= data[i+1]
	}
	hdr := make([]byte, 13)
	copy(hdr[0:5], props)
	binary.LittleEndian.PutUint64(hdr[5:13], uint64(modSize))
	stream := append(hdr, data...)
	r, err := lzma.NewReader(bytes.NewReader(stream))
	if err != nil {
		fmt.Println("lzma reader error:", err)
		return
	}
	outb, err := io.ReadAll(r)
	fmt.Printf("decompressed=%d (expected %d) err=%v\n", len(outb), modSize, err)
	if len(outb) > 0 {
		os.WriteFile(out, outb, 0o644)
		h := outb
		if len(h) > 16 {
			h = h[:16]
		}
		fmt.Printf("head=%s\n", hex.EncodeToString(h))
	}
}
