package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func tn(d *dwarf.Data, off dwarf.Offset) string {
	t, err := d.Type(off)
	if err != nil || t == nil {
		return "?"
	}
	return t.String()
}

func main() {
	f, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	d, err := f.DWARF()
	if err != nil {
		panic(err)
	}
	mode := os.Args[2]

	if mode == "lines" {
		start, _ := strconv.ParseUint(os.Args[3], 0, 64)
		end, _ := strconv.ParseUint(os.Args[4], 0, 64)
		r := d.Reader()
		for {
			cu, err := r.Next()
			if err != nil || cu == nil {
				break
			}
			if cu.Tag != dwarf.TagCompileUnit {
				continue
			}
			lr, err := d.LineReader(cu)
			if err != nil || lr == nil {
				continue
			}
			var le dwarf.LineEntry
			for {
				if err := lr.Next(&le); err != nil {
					break
				}
				if le.Address >= start && le.Address <= end {
					fmt.Printf("0x%x %s:%d\n", le.Address, le.File.Name, le.Line)
				}
			}
		}
		return
	}

	filter := os.Args[3]
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}
		if e.Tag == 0 {
			continue
		}
		parts := []string{}
		if v, ok := e.Val(dwarf.AttrName).(string); ok {
			parts = append(parts, "name="+v)
		}
		if v, ok := e.Val(dwarf.AttrDeclFile).(int64); ok {
			parts = append(parts, fmt.Sprintf("file=%d", v))
		}
		if v, ok := e.Val(dwarf.AttrDeclLine).(int64); ok {
			parts = append(parts, fmt.Sprintf("line=%d", v))
		}
		if v, ok := e.Val(dwarf.AttrType).(dwarf.Offset); ok {
			parts = append(parts, "type="+tn(d, v))
		}
		if v, ok := e.Val(dwarf.AttrDataMemberLoc).(int64); ok {
			parts = append(parts, fmt.Sprintf("offset=%d", v))
		}
		if v, ok := e.Val(dwarf.AttrByteSize).(int64); ok {
			parts = append(parts, fmt.Sprintf("size=%d", v))
		}
		if v, ok := e.Val(dwarf.AttrLowpc).(uint64); ok {
			parts = append(parts, fmt.Sprintf("lowpc=0x%x", v))
		}
		if v, ok := e.Val(dwarf.AttrHighpc).(uint64); ok {
			parts = append(parts, fmt.Sprintf("highpc=0x%x", v))
		}
		s := fmt.Sprintf("%s %s", e.Tag, strings.Join(parts, " "))
		if strings.Contains(s, filter) {
			fmt.Println(s)
		}
	}
}
