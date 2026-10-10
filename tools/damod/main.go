package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ulikunitz/xz/lzma"
)

type container struct {
	Ver     string
	HexLen  int
	Blob    []byte
	UUID    string
	Payload []byte
}

func parseContainer(raw []byte) (*container, error) {
	if len(raw) < 6 {
		return nil, fmt.Errorf("too short: %d bytes", len(raw))
	}
	c := &container{Ver: string(raw[0:3]), HexLen: int(raw[3])}
	if c.Ver != "001" {
		return nil, fmt.Errorf("unexpected magic %q", c.Ver)
	}
	if c.HexLen%2 != 0 || 4+c.HexLen > len(raw) {
		return nil, fmt.Errorf("bad hex length %d", c.HexLen)
	}
	blob, err := hex.DecodeString(string(raw[4 : 4+c.HexLen]))
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	c.Blob = blob
	at := 4 + c.HexLen
	if at+38 > len(raw) {
		return nil, errors.New("truncated header")
	}
	if raw[at] != '$' {
		return nil, fmt.Errorf("missing '$' at offset %d", at)
	}
	c.UUID = string(raw[at+1 : at+37])
	if raw[at+37] != ']' {
		return nil, fmt.Errorf("missing ']' at offset %d", at+37)
	}
	c.Payload = raw[at+38:]
	return c, nil
}

// decodeModule reverses ZsmModDeCode's type-0 path: a backwards XOR chain
// followed by raw LZMA whose 5-byte properties are rebuilt from the payload.
func decodeModule(payload []byte) ([]byte, int, int, error) {
	if len(payload) < 9 {
		return nil, 0, 0, errors.New("payload too short")
	}
	props := payload[0:4]
	szField := binary.LittleEndian.Uint32(payload[4:8])
	modType := int(szField >> 28)
	modSize := int(szField & 0x0FFFFFFF)
	if modType != 0 {
		return nil, modType, modSize, fmt.Errorf("unsupported module type %d (only type 0 is implemented)", modType)
	}
	data := append([]byte(nil), payload[8:]...)
	for i := len(data) - 2; i >= 0; i-- {
		data[i] ^= data[i+1]
	}
	hdr := make([]byte, 13)
	hdr[0] = 0x5d
	copy(hdr[1:5], props)
	binary.LittleEndian.PutUint64(hdr[5:13], uint64(modSize))
	r, err := lzma.NewReader(bytes.NewReader(append(hdr, data...)))
	if err != nil {
		return nil, modType, modSize, fmt.Errorf("lzma reader: %w", err)
	}
	// The module is attacker-controlled (the portal hands it out over plain
	// HTTP), so cap decompression to defend against a decompression bomb that
	// would otherwise exhaust memory on a small router.  maxDecoded comfortably
	// exceeds any real module while staying well inside available RAM.
	const maxDecoded = 16 << 20
	out, err := io.ReadAll(io.LimitReader(r, maxDecoded+1))
	if err != nil {
		return nil, modType, modSize, fmt.Errorf("lzma read: %w", err)
	}
	if len(out) > maxDecoded {
		return nil, modType, modSize, fmt.Errorf("decompressed module exceeds %d bytes; refusing", maxDecoded)
	}
	return out, modType, modSize, nil
}

type section struct {
	Name string
	Addr uint64
	Off  uint64
	Size uint64
}

func parseSections(b []byte) ([]section, error) {
	if len(b) < 64 || !bytes.Equal(b[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, errors.New("not an ELF image")
	}
	if b[4] != 2 || b[5] != 1 {
		return nil, fmt.Errorf("unsupported ELF class/data (%d/%d)", b[4], b[5])
	}
	shoff := binary.LittleEndian.Uint64(b[0x28:])
	shentsize := uint64(binary.LittleEndian.Uint16(b[0x3a:]))
	shnum := uint64(binary.LittleEndian.Uint16(b[0x3c:]))
	shstrndx := uint64(binary.LittleEndian.Uint16(b[0x3e:]))
	if shentsize == 0 || shoff+shnum*shentsize > uint64(len(b)) {
		return nil, errors.New("section table out of range")
	}
	type rawSec struct {
		nameOff       uint32
		addr, off, sz uint64
	}
	raw := make([]rawSec, shnum)
	for i := uint64(0); i < shnum; i++ {
		o := shoff + i*shentsize
		raw[i] = rawSec{
			nameOff: binary.LittleEndian.Uint32(b[o:]),
			addr:    binary.LittleEndian.Uint64(b[o+0x10:]),
			off:     binary.LittleEndian.Uint64(b[o+0x18:]),
			sz:      binary.LittleEndian.Uint64(b[o+0x20:]),
		}
	}
	if shstrndx >= shnum {
		return nil, errors.New("bad shstrndx")
	}
	st := raw[shstrndx]
	if st.off+st.sz > uint64(len(b)) {
		return nil, errors.New("shstrtab out of range")
	}
	nameAt := func(off uint32) string {
		i := st.off + uint64(off)
		if i >= uint64(len(b)) {
			return ""
		}
		j := i
		for j < uint64(len(b)) && b[j] != 0 {
			j++
		}
		return string(b[i:j])
	}
	out := make([]section, shnum)
	for i := range raw {
		out[i] = section{Name: nameAt(raw[i].nameOff), Addr: raw[i].addr, Off: raw[i].off, Size: raw[i].sz}
	}
	return out, nil
}

func findTemplate(dynstr []byte) string {
	for _, f := range bytes.Split(dynstr, []byte{0}) {
		s := string(f)
		if strings.HasPrefix(s, "tpl_") && strings.HasSuffix(s, ".so") {
			return s
		}
	}
	return ""
}

func algorithmFor(tpl string, keyLen, blockSize int) string {
	has := func(s string) bool { return strings.Contains(tpl, s) }
	switch {
	case has("aes") && has("cbc") && keyLen == 32:
		return "double-aes128-cbc"
	case has("aes") && has("ecb") && keyLen == 32:
		return "double-aes128-ecb"
	case has("des") && has("iv") && keyLen == 48:
		return "double-3des-cbc"
	case has("des") && keyLen == 48:
		return "six-layer-des-ecb"
	}
	return "unknown"
}

type result struct {
	UUID       string `json:"uuid"`
	Template   string `json:"template"`
	Algorithm  string `json:"algorithm"`
	ModuleType int    `json:"module_type"`
	UncompSize int    `json:"uncompressed_size"`
	ELFSize    int    `json:"elf_size"`
	BlockSize  int    `json:"block_size"`
	KeyLen     int    `json:"key_len"`
	KeyOff     int    `json:"key_off"`
	KeyHex     string `json:"key_hex"`
	IVLen      int    `json:"iv_len"`
	IVHex      string `json:"iv_hex"`
}

// extract reads the module's own metadata block.  The template's init code
// hard-codes .data+249 and pulls the key location straight out of it:
//
//	meta[0] = block/IV size (8 for DES, 16 for AES)
//	meta[2] = key length   (48 double-3DES, 32 double-AES)
//	meta[5] = key offset inside .data; the IV follows the key
//
// The module also self-checks meta[0]+meta[2]+meta[5] <= 249, which we mirror
// so a corrupted download is rejected instead of silently misparsed.
func extract(elf []byte) (*result, error) {
	secs, err := parseSections(elf)
	if err != nil {
		return nil, err
	}
	var data, dynstr []byte
	for _, s := range secs {
		if s.Off+s.Size > uint64(len(elf)) {
			continue
		}
		switch s.Name {
		case ".data":
			data = elf[s.Off : s.Off+s.Size]
		case ".dynstr":
			dynstr = elf[s.Off : s.Off+s.Size]
		}
	}
	if data == nil {
		return nil, errors.New("no .data section")
	}
	if len(data) < 256 {
		return nil, fmt.Errorf(".data too small: %d bytes", len(data))
	}
	meta := data[249:256]
	blockSize := int(meta[0])
	keyLen := int(meta[2])
	keyOff := int(meta[5])
	if blockSize+keyLen+keyOff > 0xf9 {
		return nil, fmt.Errorf("metadata self-check failed (block=%d keyLen=%d keyOff=%d)", blockSize, keyLen, keyOff)
	}
	if keyOff+keyLen+16 > len(data) {
		return nil, fmt.Errorf("key/iv range out of .data (off=%d len=%d)", keyOff, keyLen)
	}
	key := data[keyOff : keyOff+keyLen]
	iv := data[keyOff+keyLen : keyOff+keyLen+16]
	tpl := findTemplate(dynstr)
	return &result{
		Template:  tpl,
		Algorithm: algorithmFor(tpl, keyLen, blockSize),
		BlockSize: blockSize,
		KeyLen:    keyLen,
		KeyOff:    keyOff,
		KeyHex:    hex.EncodeToString(key),
		IVLen:     16,
		IVHex:     hex.EncodeToString(iv),
	}, nil
}

func main() {
	asJSON := flag.Bool("json", false, "emit JSON")
	asEnv := flag.Bool("env", false, "emit shell variable assignments for the OpenWrt client")
	outPath := flag.String("o", "", "write the unpacked ELF here")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: damod [-json|-env] [-o out.so] <module.bin>")
		os.Exit(2)
	}
	in := flag.Arg(0)
	raw, err := os.ReadFile(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	c, err := parseContainer(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "container:", err)
		os.Exit(1)
	}
	elf, modType, modSize, err := decodeModule(c.Payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}
	res, err := extract(elf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "extract:", err)
		os.Exit(1)
	}
	res.UUID = c.UUID
	res.ModuleType = modType
	res.UncompSize = modSize
	res.ELFSize = len(elf)
	if *outPath != "" {
		if err := os.WriteFile(*outPath, elf, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	}
	if *asEnv {
		fmt.Printf("DAMOD_UUID='%s'\n", res.UUID)
		fmt.Printf("DAMOD_TEMPLATE='%s'\n", res.Template)
		fmt.Printf("DAMOD_ALGORITHM='%s'\n", res.Algorithm)
		fmt.Printf("DAMOD_BLOCK_SIZE=%d\n", res.BlockSize)
		fmt.Printf("DAMOD_KEYLEN=%d\n", res.KeyLen)
		fmt.Printf("DAMOD_KEY='%s'\n", res.KeyHex)
		fmt.Printf("DAMOD_IV='%s'\n", res.IVHex)
		return
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, "json:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Printf("uuid        %s\n", res.UUID)
	fmt.Printf("template    %s\n", res.Template)
	fmt.Printf("algorithm   %s\n", res.Algorithm)
	fmt.Printf("module_type %d   uncompressed %d   elf %d\n", res.ModuleType, res.UncompSize, res.ELFSize)
	fmt.Printf("block_size  %d   key_len %d   key_off %d\n", res.BlockSize, res.KeyLen, res.KeyOff)
	fmt.Printf("key         %s\n", res.KeyHex)
	fmt.Printf("iv          %s\n", res.IVHex)
}
