package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
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

	var ops []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "[]byte{")
		if idx == -1 {
			continue
		}
		line = line[idx+len("[]byte{"):]
		idx = strings.Index(line, "}")
		if idx == -1 {
			continue
		}
		line = line[:idx]
		b := strings.Split(line, ",")
		for i := range b {
			b[i] = strings.TrimPrefix(strings.TrimSpace(b[i]), "0x")
			if len(b[i]) == 1 {
				b[i] = "0" + b[i]
			}
		}
		op, err := hex.DecodeString(strings.Join(b, ""))
		if err != nil {
			log.Fatal(err)
		}
		ops = append(ops, op...)
	}

	for _, s := range cp.Decode(ops) {
		fmt.Println(s)
	}
}
