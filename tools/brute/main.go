package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"
)

func tryDecode(name string, data []byte, props []byte, size int64) {
	hdr := make([]byte, 13)
	copy(hdr[0:5], props)
	binary.LittleEndian.PutUint64(hdr[5:13], uint64(size))
	stream := append(append([]byte{}, hdr...), data...)
	r, err := lzma.NewReader(bytes.NewReader(stream))
	if err != nil {
		return
	}
	out, err := io.ReadAll(r)
	if len(out) > 512 {
		h := out
		if len(h) > 16 { h = h[:16] }
		fmt.Printf("HIT %s props=%x size=%d -> %d bytes head=%x\n", name, props, size, len(out), h)
		os.WriteFile("hit-"+name+".bin", out, 0o644)
	}
}

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	hexLen := int(raw[3])
	payload := raw[4+hexLen+38:]
	szField := binary.LittleEndian.Uint32(payload[4:8])
	modSize := int64(szField & 0x0FFFFFFF)
	fmt.Printf("modSize=%d type=%d payload=%d\n", modSize, szField>>28, len(payload))

	type variant struct {
		name string
		data []byte
	}
	var variants []variant
	for _, start := range []int{0, 4, 8, 9, 12} {
		if start >= len(payload) { continue }
		base := append([]byte{}, payload[start:]...)
		bw := append([]byte{}, base...)
		for i := len(bw) - 2; i >= 0; i-- { bw[i] ^= bw[i+1] }
		variants = append(variants, variant{fmt.Sprintf("xorBW_start%d", start), bw})
		variants = append(variants, variant{fmt.Sprintf("raw_start%d", start), base})
		fw := append([]byte{}, base...)
		for i := 1; i < len(fw); i++ { fw[i] ^= fw[i-1] }
		variants = append(variants, variant{fmt.Sprintf("xorFW_start%d", start), fw})
	}

	propss := [][]byte{
		{0x5d, 0x00, 0x00, 0x00, 0x01},
		{0x5d, 0x00, 0x00, 0x01, 0x00},
		{0x5d, 0x00, 0x00, 0x10, 0x00},
		{0x5d, 0x00, 0x00, 0x00, 0x00},
	}
	sizes := []int64{modSize, -1}

	for _, v := range variants {
		n := len(v.data)
		pads := []int{0, int(v.data[n-1])}
		for _, pad := range pads {
			if pad < 0 || pad >= n { continue }
			body := v.data[:n-pad]
			for _, pr := range propss {
				for _, sz := range sizes {
					tryDecode(fmt.Sprintf("%s_pad%d_p%x_s%d", v.name, pad, pr[1:], sz), body, pr, sz)
				}
			}
		}
	}
	fmt.Println("done")
}
