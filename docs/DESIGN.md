# TMS320C28x SLEIGH module — design & decisions

This document is the durable record of *why* the module is built the way it is.
Read it before changing the address-space model, register layout, or addressing
sub-tables — those decisions are load-bearing and easy to break.

## Goal (scope)

A Ghidra processor module for the TI **TMS320C28x** fixed-point DSP core (targeting
the **TMS320F28377D** — dual C28x + FPU + VCU). Scoped for practical reverse
engineering, not cycle-accurate emulation:

- **Decode-complete** core C28x + FPU + VCU instructions (everything disassembles).
- **Real p-code semantics** on the common subset: loads/stores in every addressing
  mode, MOV / ALU / compare / branch / call, MAC. This is what makes XREFs resolve
  and the decompiler produce readable output.
- **FPU / VCU instructions decode-only** where full semantics add little (FP math,
  CRC) — they disassemble with correct mnemonics + register operands so the linear
  sweep doesn't dead-end, without modeling IEEE-754 / polynomial details.

## The five architectural facts that drive everything

1. **Word-addressable memory — the "byte" is 16 bits.** Smallest addressable unit
   is a 16-bit word. Modeled with `wordsize=2` on the unified `ram` space so one
   address == one word. **If this is wrong, every XREF to a peripheral register
   lands at half/double the right place.** Highest-priority invariant. Confirmed in
   SPRU430F §5.4–5.5 (offsets are counted in *words*).

2. **Variable-length instructions**, 16–64 bits, in 16-bit parcels. Fetched
   little-endian (low byte first). Base token `instr16`; longer instructions append
   more 16-bit words after a `;` in the pattern.

3. **One shared `loc16`/`loc32` addressing field.** A single 8-bit field encodes
   *all* memory/register addressing modes (SPRU430F Table 5-1), reused across the
   whole ISA. It MUST be one shared SLEIGH sub-table, parameterized by the `AMODE`
   context bit. Implementing it once is the key leverage point. See
   `tms320c28x_addr.sinc` and `docs/c28x/ch5_addressing_modes.txt`.

4. **Overlapping registers.** `ACC=AH:AL` (AH/AL further split into MSB/LSB bytes),
   `XT=T:TL` (T is the HIGH half), `P=PH:PL`, `XARn=ARnH:ARn` (ARn is the LOW half).
   Modeled with SLEIGH register sub-pieces in the .slaspec, little-endian layout.

5. **Status flags / modes** live in ST0 (SXM OVM TC C Z N V PM OVC) and ST1
   (AMODE, PAGE0, VMAP, OBJMODE, …). Flags are implemented for the common
   ALU/branch subset; PM (product shift mode) and exotic corners are approximated.

### AMODE as decode context

`AMODE` (ST1 bit 8) selects the `loc16`/`loc32` decode (Table 5-1):
- **AMODE=0** — C28x modes. The C/C++ compiler default; what compiled firmware
  emits. **This is what's implemented.**
- **AMODE=1** — C2xLP-compatible modes. Secondary (gated by `ctx_AMODE` for later).

Tracked as the SLEIGH context variable `ctx_AMODE` (default 0 in the .pspec).

## Unified address space (important)

The C28x has a **unified** program+data address map — the same address is reached by
either bus. The module uses **ONE `ram` space** (not separate CODE/DATA):

```
define space ram type=ram_space size=4 wordsize=2 default;
```

This matches the hardware AND is required by the decompiler (which needs the default
space to be the cspec `<global>` space). Using split CODE/DATA spaces makes the
disassembler work but breaks the decompiler with "X may not be a global space". See
`docs/SLEIGH-IDIOMS.md` idiom 7c.

## Register-space layout (offsets within the SLEIGH register space)

| Offset | Size | Registers |
|---|---|---|
| 0x00 | 4 | ACC |
| 0x00 | 2 | AL, AH |
| 0x00 | 1 | AL_LSB, AL_MSB, AH_LSB, AH_MSB |
| 0x08 | 4 | P (PL, PH) |
| 0x10 | 4 | XT (TL, T) |
| 0x20 | 4 | XAR0..XAR7 (ARn, ARnH) |
| 0x40 | 2 | DP, SP |
| 0x44 | 4 | PC, RPC (22-bit values in 32-bit slots) |
| 0x50 | 2 | ST0, ST1 |
| 0x58 | 2 | IFR, IER, DBGIER |
| 0x60 | 4 | R0H..R7H (FPU) |
| 0x90 | 4 | STF, RB (FPU) |
| 0xA0 | 4 | VR0..VR8 (VCU) |
| 0xC8 | 4 | VT0, VT1, VSTATUS, VCRC (VCU) |
| 0x80 | 4 | contextreg |

> Note: SPRU430F Table 2-1 lists XAR0 as "16 bits" — a known doc typo. Fig 2-2 and
> all addressing-mode text treat all XAR0–7 as 32-bit. Modeled as 32-bit.

## Source files

| File | Role |
|---|---|
| `data/languages/tms320c28x.slaspec` | spaces + register file + context; includes the .sinc files |
| `tms320c28x.sinc` | tokens + the fixed-opcode/dispatch core; includes the family files |
| `tms320c28x_addr.sinc` | the shared `loc16`/`loc32` addressing sub-tables |
| `tms320c28x_mov.sinc` | MOV / MOVL / MOVB / MOVW |
| `tms320c28x_flow.sinc` | branch / call / return + COND condition codes |
| `tms320c28x_alu.sinc` | ADD/SUB/AND/OR/XOR/CMP/INC/DEC/NEG/NOT/TBIT + flags |
| `tms320c28x_mac.sinc` | MAC / MPY family |
| `tms320c28x_ext56.sinc` | the 0x56-prefix 2-word extended-ALU family (74 instrs) |
| `tms320c28x_more.sinc` | additional opcodes (LC/LB, MOVZ, MOVL XARn,#22bit ptr-loads, immediate-stores, PUSH/POP, PREAD/PWRITE, …) |
| `tms320c28x_fpu.sinc` | FPU (F2837x) — decode-only |
| `tms320c28x_vcu.sinc` | VCU-II / VCRC — decode-only (hardware CRC) |
| `tms320c28x.pspec` | PC, interrupt vectors, default AMODE context |
| `tms320c28x.cspec` | 16-bit char / 32-bit ptr data model, SP, calling convention |
| `docs/c28x/*.txt` | extracted SPRU430F / spruhs1c reference chapters |

## Reference manuals

- **SPRU430F** — TMS320C28x CPU and Instruction Set Reference Guide (the core ISA).
- **spruhs1c** — TMS320C28x Extended Instruction Sets TRM (FPU / VCU / VCRC / TMU).

Extracted chapters live in `docs/c28x/` (large per-instruction reference files are
gitignored — regenerate from the PDFs with `pdftotext -layout`).

## Building & testing

See `docs/BUILDING.md` (compile/install) and `docs/TESTING.md` (the headless
disassembly regression test — a constructor isn't done until a known-encoding byte
disassembles to the expected text). `docs/SLEIGH-IDIOMS.md` documents the SLEIGH
gotchas, each backed by a real compiler error.

## Status

Compiles clean against Ghidra 12.1.2's SLEIGH compiler. Full instruction set across
all families decodes; every hand-assembled regression vector passes; the decompiler
produces C output. See `docs/WRITING-INSTRUCTIONS.md` for adding more instructions.
