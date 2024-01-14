package capstone

import "testing"

func TestARM64(t *testing.T) {
	cp := NewCapstone(ARCH_AARCH64, MODE_ARM)
	defer cp.Close()

	tests := []struct {
		asm string
		op  []byte
	}{
		{
			asm: "ldaddal wzr, wzr, [sp]",
			op:  []byte{0xff, 0x3, 0xff, 0xb8},
		},
		{
			asm: "sub wzr, w30, w30",
			op:  []byte{0xdf, 0x3, 0x1e, 0x4b},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.asm, func(t *testing.T) {
			res := cp.Decode(tc.op)
			if len(res) != 1 {
				t.Errorf("expected 1 instruction, got %d", len(res))
			}
			if res[0] != tc.asm {
				t.Errorf("expected %s, got %s", tc.asm, res[0])
			}
		})
	}
}

func TestAMD64(t *testing.T) {
	cp := NewCapstone(ARCH_X86, MODE_64)
	defer cp.Close()

	tests := []struct {
		asm string
		op  []byte
	}{
		{
			asm: "got movb %sil, 1(%r8)",
			op:  []byte{0x41, 0x88, 0x70, 0x1},
		},
		{
			asm: "movb $0x9c, 0x4db(%r8)",
			op:  []byte{0x41, 0xc6, 0x80, 0xdb, 0x4, 0x0, 0x0, 0x9c},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.asm, func(t *testing.T) {
			res := cp.Decode(tc.op)
			if len(res) != 1 {
				t.Errorf("expected 1 instruction, got %d", len(res))
			}
			if res[0] != tc.asm {
				t.Errorf("expected %s, got %s", tc.asm, res[0])
			}
		})
	}
}
