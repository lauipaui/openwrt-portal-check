package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"disasm/arm64asm"
)

func main() {
	path := os.Args[1]
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	f, err := elf.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	v2o := func(vaddr uint64) int64 {
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Filesz {
				return int64(p.Off + (vaddr - p.Vaddr))
			}
		}
		return -1
	}
	start, _ := strconv.ParseUint(os.Args[2], 0, 64)
	length, _ := strconv.ParseUint(os.Args[3], 0, 64)
	for pc := start; pc < start+length; pc += 4 {
		off := v2o(pc)
		if off < 0 || off+4 > int64(len(data)) {
			fmt.Printf("0x%x  <no mapping>\n", pc)
			continue
		}
		buf := data[off : off+4]
		w := binary.LittleEndian.Uint32(buf)
		inst, err := arm64asm.Decode(buf)
		s := inst.String()
		if err != nil {
			s = "?? " + err.Error()
		}
		fmt.Printf("0x%x  %08x  %s\n", pc, w, s)
	}
}
