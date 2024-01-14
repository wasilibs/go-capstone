package capstone

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/wasilibs/go-capstone/internal/wasm"
)

var (
	wasmRT       wazero.Runtime
	wasmCompiled wazero.CompiledModule
)

func init() {
	ctx := context.Background()
	rtCfg := wazero.NewRuntimeConfig()
	uc, err := os.UserCacheDir()
	if err == nil {
		cache, err := wazero.NewCompilationCacheWithDir(filepath.Join(uc, "com.github.wasilibs"))
		if err == nil {
			rtCfg = rtCfg.WithCompilationCache(cache)
		}
	}
	rt := wazero.NewRuntimeWithConfig(ctx, rtCfg)

	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	code, err := rt.CompileModule(ctx, wasm.LibCapstone)
	if err != nil {
		log.Fatal(err)
	}
	wasmRT = rt
	wasmCompiled = code
}

type Arch uint16

const (
	ARCH_ARM        Arch = iota ///< ARM architecture (including Thumb, Thumb-2)
	ARCH_AARCH64                ///< AArch64
	ARCH_MIPS                   ///< Mips architectureq
	ARCH_X86                    ///< X86 architecture (including x86 & x86-64)
	ARCH_PPC                    ///< PowerPC architecture
	ARCH_SPARC                  ///< Sparc architecture
	ARCH_SYSZ                   ///< SystemZ architecture
	ARCH_XCORE                  ///< XCore architecture
	ARCH_M68K                   ///< 68K architecture
	ARCH_TMS320C64X             ///< TMS320C64x architecture
	ARCH_M680X                  ///< 680X architecture
	ARCH_EVM                    ///< Ethereum architecture
	ARCH_MOS65XX                ///< MOS65XX architecture (including MOS6502)
	ARCH_WASM                   ///< WebAssembly architecture
	ARCH_BPF                    ///< Berkeley Packet Filter architecture (including eBPF)
	ARCH_RISCV                  ///< RISCV architecture
	ARCH_SH                     ///< SH architecture
	ARCH_TRICORE                ///< TriCore architecture
	ARCH_ALPHA                  ///< Alpha architecture
	ARCH_MAX
	ARCH_ALL = 0xFFFF // All architectures - for cs_support()
)

type Mode uint32

const (
	MODE_LITTLE_ENDIAN Mode = 0             ///< little-endian mode (default mode)
	MODE_ARM           Mode = 0             ///< 32-bit ARM
	MODE_16            Mode = 1 << 1        ///< 16-bit mode (X86)
	MODE_32            Mode = 1 << 2        ///< 32-bit mode (X86)
	MODE_64            Mode = 1 << 3        ///< 64-bit mode (X86, PPC)
	MODE_THUMB         Mode = 1 << 4        ///< ARM's Thumb mode, including Thumb-2
	MODE_MCLASS        Mode = 1 << 5        ///< ARM's Cortex-M series
	MODE_V8            Mode = 1 << 6        ///< ARMv8 A32 encodings for ARM
	MODE_MICRO         Mode = 1 << 4        ///< MicroMips mode (MIPS)
	MODE_MIPS3         Mode = 1 << 5        ///< Mips III ISA
	MODE_MIPS32R6      Mode = 1 << 6        ///< Mips32r6 ISA
	MODE_MIPS2         Mode = 1 << 7        ///< Mips II ISA
	MODE_V9            Mode = 1 << 4        ///< SparcV9 mode (Sparc)
	MODE_QPX           Mode = 1 << 4        ///< Quad Processing eXtensions mode (PPC)
	MODE_SPE           Mode = 1 << 5        ///< Signal Processing Engine mode (PPC)
	MODE_BOOKE         Mode = 1 << 6        ///< Book-E mode (PPC)
	MODE_PS            Mode = 1 << 7        ///< Paired-singles mode (PPC)
	MODE_M68K_000      Mode = 1 << 1        ///< M68K 68000 mode
	MODE_M68K_010      Mode = 1 << 2        ///< M68K 68010 mode
	MODE_M68K_020      Mode = 1 << 3        ///< M68K 68020 mode
	MODE_M68K_030      Mode = 1 << 4        ///< M68K 68030 mode
	MODE_M68K_040      Mode = 1 << 5        ///< M68K 68040 mode
	MODE_M68K_060      Mode = 1 << 6        ///< M68K 68060 mode
	MODE_BIG_ENDIAN    Mode = Mode(1) << 31 ///< big-endian mode
	MODE_MIPS32        Mode = MODE_32       ///< Mips32 ISA (Mips)
	MODE_MIPS64        Mode = MODE_64       ///< Mips64 ISA (Mips)
	MODE_M680X_6301    Mode = 1 << 1        ///< M680X Hitachi 6301,6303 mode
	MODE_M680X_6309    Mode = 1 << 2        ///< M680X Hitachi 6309 mode
	MODE_M680X_6800    Mode = 1 << 3        ///< M680X Motorola 6800,6802 mode
	MODE_M680X_6801    Mode = 1 << 4        ///< M680X Motorola 6801,6803 mode
	MODE_M680X_6805    Mode = 1 << 5        ///< M680X Motorola/Freescale 6805 mode
	MODE_M680X_6808    Mode = 1 << 6        ///< M680X Motorola/Freescale/NXP 68HC08 mode
	MODE_M680X_6809    Mode = 1 << 7        ///< M680X Motorola 6809 mode
	MODE_M680X_6811    Mode = 1 << 8        ///< M680X Motorola/Freescale/NXP 68HC11 mode
	MODE_M680X_CPU12   Mode = 1 << 9        ///< M680X Motorola/Freescale/NXP CPU12
	///< used on M68HC12/HCS12
	MODE_M680X_HCS08           Mode = 1 << 10  ///< M680X Freescale/NXP HCS08 mode
	MODE_BPF_CLASSIC           Mode = 0        ///< Classic BPF mode (default)
	MODE_BPF_EXTENDED          Mode = 1 << 0   ///< Extended BPF mode
	MODE_RISCV32               Mode = 1 << 0   ///< RISCV RV32G
	MODE_RISCV64               Mode = 1 << 1   ///< RISCV RV64G
	MODE_RISCVC                Mode = 1 << 2   ///< RISCV compressed instructure mode
	MODE_MOS65XX_6502          Mode = 1 << 1   ///< MOS65XXX MOS 6502
	MODE_MOS65XX_65C02         Mode = 1 << 2   ///< MOS65XXX WDC 65c02
	MODE_MOS65XX_W65C02        Mode = 1 << 3   ///< MOS65XXX WDC W65c02
	MODE_MOS65XX_65816         Mode = 1 << 4   ///< MOS65XXX WDC 65816, 8-bit m/x
	MODE_MOS65XX_65816_LONG_M  Mode = (1 << 5) ///< MOS65XXX WDC 65816, 16-bit m, 8-bit x
	MODE_MOS65XX_65816_LONG_X  Mode = (1 << 6) ///< MOS65XXX WDC 65816, 8-bit m, 16-bit x
	MODE_MOS65XX_65816_LONG_MX Mode = MODE_MOS65XX_65816_LONG_M | MODE_MOS65XX_65816_LONG_X
	MODE_SH2                   Mode = 1 << 1 ///< SH2
	MODE_SH2A                  Mode = 1 << 2 ///< SH2A
	MODE_SH3                   Mode = 1 << 3 ///< SH3
	MODE_SH4                   Mode = 1 << 4 ///< SH4
	MODE_SH4A                  Mode = 1 << 5 ///< SH4A
	MODE_SHFPU                 Mode = 1 << 6 ///< w/ FPU
	MODE_SHDSP                 Mode = 1 << 7 ///< w/ DSP
	MODE_TRICORE_110           Mode = 1 << 1 ///< Tricore 1.1
	MODE_TRICORE_120           Mode = 1 << 2 ///< Tricore 1.2
	MODE_TRICORE_130           Mode = 1 << 3 ///< Tricore 1.3
	MODE_TRICORE_131           Mode = 1 << 4 ///< Tricore 1.3.1
	MODE_TRICORE_160           Mode = 1 << 5 ///< Tricore 1.6
	MODE_TRICORE_161           Mode = 1 << 6 ///< Tricore 1.6.1
	MODE_TRICORE_162           Mode = 1 << 7 ///< Tricore 1.6.2
)

type OptType uint16

const (
	OPT_INVALID          OptType = iota ///< No option specified
	OPT_SYNTAX                          ///< Assembly output syntax
	OPT_DETAIL                          ///< Break down instruction structure into details
	OPT_MODE                            ///< Change engine's mode at run-time
	OPT_MEM                             ///< User-defined dynamic memory related functions
	OPT_SKIPDATA                        ///< Skip data when disassembling. Then engine is in SKIPDATA mode.
	OPT_SKIPDATA_SETUP                  ///< Setup user-defined function for SKIPDATA option
	OPT_MNEMONIC                        ///< Customize instruction mnemonic
	OPT_UNSIGNED                        ///< print immediate operands in unsigned form
	OPT_NO_BRANCH_OFFSET                ///< ARM, prints branch immediates without offset.
)

type OptValue uint16

const (
	OPT_OFF                 OptValue = 0      ///< Turn OFF an option - default for OPT_DETAIL, OPT_SKIPDATA, OPT_UNSIGNED.
	OPT_ON                  OptValue = 1 << 0 ///< Turn ON an option (OPT_DETAIL, OPT_SKIPDATA).
	OPT_SYNTAX_DEFAULT      OptValue = 1 << 1 ///< Default asm syntax (OPT_SYNTAX).
	OPT_SYNTAX_INTEL        OptValue = 1 << 2 ///< X86 Intel asm syntax - default on X86 (OPT_SYNTAX).
	OPT_SYNTAX_ATT          OptValue = 1 << 3 ///< X86 ATT asm syntax (OPT_SYNTAX).
	OPT_SYNTAX_NOREGNAME    OptValue = 1 << 4 ///< Prints register name with only number (OPT_SYNTAX)
	OPT_SYNTAX_MASM         OptValue = 1 << 5 ///< X86 Intel Masm syntax (OPT_SYNTAX).
	OPT_SYNTAX_MOTOROLA     OptValue = 1 << 6 ///< MOS65XX use $ as hex prefix
	OPT_SYNTAX_CS_REG_ALIAS OptValue = 1 << 7 ///< Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)
	OPT_SYNTAX_PERCENT      OptValue = 1 << 8 ///< Prints the % in front of PPC registers.
	OPT_DETAIL_REAL         OptValue = 1 << 1 ///< If enabled, always sets the real instruction detail. Even if the instruction is an alias.
)

func NewCapstone(arch Arch, mode Mode) *Capstone {
	ctx := context.Background()
	mod, err := wasmRT.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().
		WithName("").
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		WithStdin(os.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	malloc := newLazyFunction(mod, "malloc")

	// cshPtr is just an opaque size_t handle
	cshPtr := malloc.Call1(ctx, 4)

	csOpen := newLazyFunction(mod, "cs_open")
	csErr := csOpen.Call3(ctx, uint64(arch), uint64(mode), cshPtr)
	if csErr != 0 {
		// TODO(anuraaga): Parse error
		log.Fatalf("cs_open failed with %d", csErr)
	}
	csh, ok := mod.Memory().ReadUint32Le(uint32(cshPtr))
	if !ok {
		panic("failed to read csh")
	}

	csOption := newLazyFunction(mod, "cs_option")
	csOption.Call3(ctx, uint64(csh), uint64(OPT_SYNTAX), uint64(OPT_SYNTAX_ATT))

	return &Capstone{csh: uint64(csh), abi: &abi{
		mod:             mod,
		fnCsDisasmIter:  newLazyFunction(mod, "cs_disasm_iter"),
		fnCsMalloc:      newLazyFunction(mod, "cs_malloc"),
		fnCsFree:        newLazyFunction(mod, "cs_free"),
		fnCsGetMnemonic: newLazyFunction(mod, "cs_get_mnemonic"),
		fnCsGetOpStr:    newLazyFunction(mod, "cs_get_op_str"),
		fnMalloc:        malloc,
		fnFree:          newLazyFunction(mod, "free"),
	}}
}

type abi struct {
	mod api.Module

	fnCsDisasmIter  lazyFunction
	fnCsMalloc      lazyFunction
	fnCsFree        lazyFunction
	fnCsGetMnemonic lazyFunction
	fnCsGetOpStr    lazyFunction
	fnMalloc        lazyFunction
	fnFree          lazyFunction
}

type Capstone struct {
	abi *abi
	csh uint64
	io.Closer

	mu sync.Mutex
}

func (c *Capstone) Close() error {
	// No need to call cs_free, we're deleting all the memory by closing the module.
	return c.abi.mod.Close(context.Background())
}

// Decode returns the string ASM instructions of the given code.
// Each instruction is the mnemonic followed by the operands.
func (c *Capstone) Decode(code []byte) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctx := context.Background()

	insnPtr := c.abi.fnCsMalloc.Call1(ctx, c.csh)
	defer c.abi.fnCsFree.Call2(ctx, insnPtr, 1)

	codePtrs := c.abi.fnMalloc.Call1(ctx, 12)
	defer c.abi.fnFree.Call1(ctx, codePtrs)

	codePtrPtr := uint32(codePtrs)
	sizePtr := uint32(codePtrs + 4)
	addressPtr := uint32(codePtrs + 8)

	codePtr := c.abi.fnMalloc.Call1(ctx, uint64(len(code)))
	defer c.abi.fnFree.Call1(ctx, codePtr)

	codeBuf, ok := c.abi.mod.Memory().Read(uint32(codePtr), uint32(len(code)))
	if !ok {
		panic("failed to get code buffer")
	}
	copy(codeBuf, code)

	if ok := c.abi.mod.Memory().WriteUint32Le(codePtrPtr, uint32(codePtr)); !ok {
		panic("failed to write code ptr")
	}
	if ok := c.abi.mod.Memory().WriteUint32Le(sizePtr, uint32(len(code))); !ok {
		panic("failed to write code size")
	}
	if ok := c.abi.mod.Memory().WriteUint32Le(addressPtr, 0); !ok {
		panic("failed to write code address")
	}

	var res []string
	for c.abi.fnCsDisasmIter.Call5(ctx, c.csh, uint64(codePtrPtr), uint64(sizePtr), uint64(addressPtr), uint64(insnPtr)) != 0 {
		mnemonic := readCString(c.abi.mod.Memory(), uint32(c.abi.fnCsGetMnemonic.Call1(ctx, insnPtr)))
		opStr := readCString(c.abi.mod.Memory(), uint32(c.abi.fnCsGetOpStr.Call1(ctx, insnPtr)))
		res = append(res, mnemonic+" "+opStr)
	}
	return res
}

func readCString(mem api.Memory, ptr uint32) string {
	endPtr := ptr
	for {
		b, ok := mem.ReadByte(endPtr)
		if !ok {
			panic("failed to read cstring")
		}
		if b == 0 {
			break
		}
		endPtr++
	}
	buf, _ := mem.Read(ptr, endPtr-ptr)
	return string(buf)
}

type lazyFunction struct {
	mod  api.Module
	name string
	fun  api.Function
}

func newLazyFunction(mod api.Module, name string) lazyFunction {
	return lazyFunction{mod: mod, name: name}
}

func (f *lazyFunction) Call0(ctx context.Context) uint64 {
	var callStack [1]uint64
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call1(ctx context.Context, arg1 uint64) uint64 {
	var callStack [1]uint64
	callStack[0] = arg1
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call2(ctx context.Context, arg1 uint64, arg2 uint64) uint64 {
	var callStack [2]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call3(ctx context.Context, arg1 uint64, arg2 uint64, arg3 uint64) uint64 {
	var callStack [3]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	callStack[2] = arg3
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call5(ctx context.Context, arg1 uint64, arg2 uint64, arg3 uint64, arg4 uint64, arg5 uint64) uint64 {
	var callStack [5]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	callStack[2] = arg3
	callStack[3] = arg4
	callStack[4] = arg5
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) Call8(ctx context.Context, arg1 uint64, arg2 uint64, arg3 uint64, arg4 uint64, arg5 uint64, arg6 uint64, arg7 uint64, arg8 uint64) uint64 {
	var callStack [8]uint64
	callStack[0] = arg1
	callStack[1] = arg2
	callStack[2] = arg3
	callStack[3] = arg4
	callStack[4] = arg5
	callStack[5] = arg6
	callStack[6] = arg7
	callStack[7] = arg8
	return f.callWithStack(ctx, callStack[:])
}

func (f *lazyFunction) callWithStack(ctx context.Context, callStack []uint64) uint64 {
	if f.fun == nil {
		f.fun = f.mod.ExportedFunction(f.name)
	}
	if err := f.fun.CallWithStack(ctx, callStack); err != nil {
		panic(err)
	}
	return callStack[0]
}
