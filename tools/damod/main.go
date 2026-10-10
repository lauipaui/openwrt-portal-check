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
	"regexp"
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

const maxContainer = 512 << 10
const maxELF = 1 << 20
const maxDictionary = 16 << 20

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func parseContainer(raw []byte) (*container, error) {
	if len(raw) > maxContainer {
		return nil, errors.New("container size limit exceeded")
	}
	if len(raw) < 6 {
		return nil, fmt.Errorf("too short: %d bytes", len(raw))
	}
	c := &container{Ver: string(raw[0:3]), HexLen: int(raw[3])}
	if c.Ver != "001" {
		return nil, fmt.Errorf("unexpected magic %q", c.Ver)
	}
	if c.HexLen == 0 || c.HexLen%2 != 0 || 4+c.HexLen > len(raw) {
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
	c.UUID = strings.ToUpper(string(raw[at+1 : at+37]))
	if !uuidPattern.MatchString(c.UUID) || c.UUID == "00000000-0000-0000-0000-000000000000" {
		return nil, errors.New("invalid module UUID")
	}
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
	if len(payload) > maxContainer {
		return nil, 0, 0, errors.New("payload size limit exceeded")
	}
	props := payload[0:4]
	dictionary := binary.LittleEndian.Uint32(props)
	if dictionary < 4096 || dictionary > maxDictionary {
		return nil, 0, 0, errors.New("LZMA dictionary size limit exceeded")
	}
	szField := binary.LittleEndian.Uint32(payload[4:8])
	modType := int(szField >> 28)
	modSize := int(szField & 0x0FFFFFFF)
	if modSize <= 0 || modSize > maxELF {
		return nil, modType, modSize, errors.New("uncompressed size limit exceeded")
	}
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
	// A known bounded stream size reduces actual dictionary allocation to max(size,4096).
	r, err := (lzma.ReaderConfig{DictCap: maxDictionary}).NewReader(bytes.NewReader(append(hdr, data...)))
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
	out, err := io.ReadAll(io.LimitReader(r, int64(modSize)+1))
	if err != nil {
		return nil, modType, modSize, fmt.Errorf("lzma read: %w", err)
	}
	if len(out) != modSize {
		return nil, modType, modSize, errors.New("uncompressed size mismatch")
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
	if len(b) > maxELF || len(b) < 64 || !bytes.Equal(b[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, errors.New("not an ELF image")
	}
	if b[4] != 2 || b[5] != 1 {
		return nil, fmt.Errorf("unsupported ELF class/data (%d/%d)", b[4], b[5])
	}
	shoff := binary.LittleEndian.Uint64(b[0x28:])
	shentsize := uint64(binary.LittleEndian.Uint16(b[0x3a:]))
	shnum := uint64(binary.LittleEndian.Uint16(b[0x3c:]))
	shstrndx := uint64(binary.LittleEndian.Uint16(b[0x3e:]))
	if shentsize < 64 || shnum == 0 || shnum > 1024 || shoff > uint64(len(b)) || shnum > (uint64(len(b))-shoff)/shentsize {
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
	if st.off > uint64(len(b)) || st.sz > uint64(len(b))-st.off {
		return nil, errors.New("shstrtab out of range")
	}
	// Charge every reference (including aliases), not only distinct offsets.
	// Bound the search window before scanning, and reserve the aggregate budget
	// before string conversion, so a tiny ELF cannot amplify into huge retained names.
	const maxSectionNameLength = 128
	const maxSectionNameBudget = 16 << 10
	nameBudget := maxSectionNameBudget
	nameAt := func(off uint32) (string, error) {
		if uint64(off) >= st.sz {
			return "", errors.New("section name offset out of range")
		}
		start := st.off + uint64(off)
		window := st.sz - uint64(off)
		if window > maxSectionNameLength+1 {
			window = maxSectionNameLength + 1
		}
		length := bytes.IndexByte(b[start:start+window], 0)
		if length < 0 {
			return "", errors.New("section name length limit exceeded or missing NUL")
		}
		cost := length + 1
		if cost > nameBudget {
			return "", errors.New("section name budget exceeded")
		}
		nameBudget -= cost
		return string(b[start : start+uint64(length)]), nil
	}

	out := make([]section, shnum)
	for i := range raw {
		name, err := nameAt(raw[i].nameOff)
		if err != nil {
			return nil, err
		}
		out[i] = section{Name: name, Addr: raw[i].addr, Off: raw[i].off, Size: raw[i].sz}
	}
	return out, nil
}

func findTemplate(dynstr []byte) string {
	found := ""
	count := 0
	// Scan without bytes.Split: a hostile all-NUL string table must not allocate
	// an array of up to a million slices on a memory-constrained router.
	for len(dynstr) > 0 {
		at := bytes.IndexByte(dynstr, 0)
		if at < 0 {
			return ""
		}
		f := dynstr[:at]
		dynstr = dynstr[at+1:]
		if bytes.HasPrefix(f, []byte("tpl_")) && bytes.HasSuffix(f, []byte(".so")) {
			if len(f) > 64 {
				return ""
			}
			count++
			if count > 1 {
				return ""
			}
			found = string(f)
		}
	}
	if count != 1 {
		return ""
	}
	return found
}

func algorithmFor(tpl string, keyLen, blockSize int) string {
	switch tpl {
	case "tpl_aes_cbc.so":
		if keyLen == 32 && blockSize == 16 {
			return "double-aes128-cbc"
		}
	case "tpl_aes_ecb.so":
		if keyLen == 32 && blockSize == 16 {
			return "double-aes128-ecb"
		}
	case "tpl_des_iv.so", "tpl_des_cbc.so":
		if keyLen == 48 && blockSize == 8 {
			return "double-3des-cbc"
		}
	case "tpl_des.so", "tpl_des_ecb.so":
		if keyLen == 48 && blockSize == 8 {
			return "six-layer-des-ecb"
		}
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
		if s.Off > uint64(len(elf)) || s.Size > uint64(len(elf))-s.Off {
			if s.Name == ".data" || s.Name == ".dynstr" {
				return nil, errors.New("required section out of range")
			}
			continue
		}
		switch s.Name {
		case ".data":
			if data != nil {
				return nil, errors.New("duplicate .data section")
			}
			data = elf[s.Off : s.Off+s.Size]
		case ".dynstr":
			if dynstr != nil {
				return nil, errors.New("duplicate .dynstr section")
			}
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
	if (blockSize != 8 && blockSize != 16) || keyLen == 0 || keyLen > 64 || blockSize+keyLen+keyOff > 0xf9 {
		return nil, fmt.Errorf("metadata self-check failed (block=%d keyLen=%d keyOff=%d)", blockSize, keyLen, keyOff)
	}
	if keyOff+keyLen+16 > len(data) {
		return nil, fmt.Errorf("key/iv range out of .data (off=%d len=%d)", keyOff, keyLen)
	}
	key := data[keyOff : keyOff+keyLen]
	iv := data[keyOff+keyLen : keyOff+keyLen+16]
	tpl := findTemplate(dynstr)
	if tpl == "" || algorithmFor(tpl, keyLen, blockSize) == "unknown" {
		return nil, errors.New("missing, ambiguous or unverified module template")
	}
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
	f, err := os.Open(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxContainer+1))
	f.Close()
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
		if strings.ContainsAny(res.Template, "'\r\n") {
			fmt.Fprintln(os.Stderr, "invalid template literal")
			os.Exit(1)
		}
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
