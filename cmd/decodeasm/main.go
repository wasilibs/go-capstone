package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/wasilibs/go-capstone"
)

func main() {
	var archFlag string

	flag.StringVar(&archFlag, "arch", "", "architecture to decode. supported values: arm64, amd64")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: decodeasm <hex opcode>\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	hexcode := flag.Arg(0)
	hexcode = strings.TrimPrefix(hexcode, "0x")
	hexcode = strings.TrimPrefix(hexcode, "0X")
	opcode, err := hex.DecodeString(hexcode)
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid hex opcode: %s\n", hexcode)
		flag.Usage()
		os.Exit(1)
	}

	var arch capstone.Arch
	var mode capstone.Mode
	switch archFlag {
	case "arm64":
		arch = capstone.ARCH_AARCH64
		mode = capstone.MODE_ARM
	case "amd64":
		arch = capstone.ARCH_X86
		mode = capstone.MODE_64
	default:
		flag.Usage()
		os.Exit(1)
	}

	cp := capstone.NewCapstone(arch, mode)
	defer cp.Close()
	res := cp.Decode(opcode)
	if len(res) == 0 {
		fmt.Fprintf(flag.CommandLine.Output(), "expected at least 1 instruction, got %d\n", len(res))
		os.Exit(1)
	}
	for _, d := range res {
		fmt.Println(d)
	}
}
