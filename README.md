# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core,
targeting the **TMS320F28377D** (dual-core C28x + FPU, F2837xD family).

There is no official Ghidra support for the TMS320C28x. This module fills that gap:
it disassembles and decompiles C28x firmware, which Ghidra otherwise cannot do at all.

> ⚠️ **WIP — expect bugs.** This is a work in progress, built rapidly ("vibe-coded")
> with [Claude Code](https://claude.com/claude-code). It validates to 100% mnemonic
> parity against TI's own `dis2000` on a sample of the `rts2800_fpu32` runtime (see
> Status), but that sample doesn't exercise the full ISA, and decode-only families
> (FPU/VCU) carry minimal/approximate p-code semantics. Several real
> operand/semantics bugs have already been found and fixed by cross-checking against
> the manual — assume more remain. **Verify against the SPRU430F/SPRUHS1C reference
> before trusting any decode for critical work, and please file issues.**

## Goal

A practical reverse-engineering processor module — decode-complete and decompilable,
not a cycle-accurate model:

- **Decode-complete** core C28x + FPU + VCU instructions (everything disassembles).
- **Real p-code semantics** on the common subset: loads/stores in every addressing
  mode, MOV/ALU/compare/branch/call, and MAC. This makes XREFs to peripheral
  registers resolve and the decompiler produce useful output.
- **FPU / VCU instructions decode-only** (disassemble, minimal semantics) — FP math
  and hardware CRC rarely need full modeling for control-flow RE.
- Includes a **peripheral-labeling script** (`ghidra_scripts/SetupF28377D.java`) that
  maps + labels the F2837xD peripheral frames (incl. the D_CAN CANA/CANB registers).

## The architectural quirks that drive the design

1. **Word-addressable memory.** The smallest addressable unit is **16 bits**, not 8.
   Address-space `wordsize` must reflect this or every XREF to a peripheral register
   lands at the wrong place. This is the single biggest correctness lever.
2. **Variable-length instructions** (16–64 bits, in 16-bit parcels).
3. **`loc16`/`loc32` addressing field.** One shared 8-bit operand field decodes to all
   addressing modes (Table 5-1, SPRU430F). Modeled as a single shared SLEIGH sub-table,
   parameterized by the `AMODE` context bit (from ST1). AMODE=0 is the compiler default
   and is implemented first.
4. **Overlapping registers.** `ACC=AH:AL`, `XT=T:TL`, `P=PH:PL`, `XARn=ARnH:ARn`.
   Modeled with SLEIGH register sub-pieces.
5. **Status flags / modes** (ST0/ST1: Z N C V OVM SXM TC PM AMODE …). Implemented for the
   common ALU/branch subset; PM shift mode and exotic corners approximated.

## Source

Built from **SPRU430F — TMS320C28x CPU and Instruction Set Reference Guide** (TI).
Extracted reference chapters live in [docs/c28x/](docs/c28x/):

| File | SPRU430F (printed pp.) | Feeds |
|---|---|---|
| `ch2_cpu_registers.txt` | 20–51 | register file + flags → `.pspec` |
| `ch5_addressing_modes.txt` | 79–106 | `loc16`/`loc32` table → addressing `.sinc` |
| `ch6_instruction_summary.txt` | 107–115 | master opcode list → constructor checklist |
| `appA_register_quickref.txt` | 490–497 | reset values |

Per-instruction encoding detail (SPRU430F pp. 116–472) is read on demand while writing
each constructor; it is not bulk-extracted.

> PDF page = printed page + 2 (front matter offset).

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — why it's built this way; the 5 architectural
  facts, register-space layout, roadmap, and open questions. Read this first.
- **[docs/BUILDING.md](docs/BUILDING.md)** — compile / install / smoke-test, and the
  WSL↔Windows gotchas.
- **[docs/WRITING-INSTRUCTIONS.md](docs/WRITING-INSTRUCTIONS.md)** — the per-instruction
  recipe and the shared `loc16`/`loc32` sub-table plan.
- **[docs/SLEIGH-IDIOMS.md](docs/SLEIGH-IDIOMS.md)** — SLEIGH idioms & gotchas (each
  backed by a real compiler error). Read before writing constructors.
- **[docs/TESTING.md](docs/TESTING.md)** — the disasm regression harness.

## Status

Compiles clean against Ghidra 12.1.2's SLEIGH compiler and decompiles C28x code.
The full instruction set across all families decodes, the shared `loc16`/`loc32`
addressing sub-tables are implemented (AMODE=0), and the decompiler produces C output.

**Validation (TI ground truth):** disassembled five objects from TI's own
`rts2800_fpu32.lib` runtime (real TI-compiled C28x code) and diffed mnemonics against
TI's `dis2000`: **100% agreement, 0 wrong decodes** across all objects (`k_expf`,
`catrigf`, `c99_complex`, `memcpy_s`, `strcpy_s`). The harness is
[tests/run_ti_parity.ps1](tests/run_ti_parity.ps1) +
[ghidra_scripts/DumpParity.java](ghidra_scripts/DumpParity.java) — reuse it for any
TI object.

**Validation (real firmware):** beyond the TI runtime, the opcode set was hardened
against a large (~250K-word) real-world F28377D production image: a linear sweep
decodes **~95% by word** (≈98% of actual code; the residual is inline data a linear
sweep can't skip) with **0 wrong decodes**. The undecoded-opcode histogram on real
code drove the remaining additions beyond what the TI runtime exercises (more
0x56-prefix forms incl. 64-bit `ACC:P` shifts, `MOV/ADD/SUB ACC,…<<#`,
`CLRC/SETC mode`, `RPT`, `MOVU`, `XOR loc16,AX`, the `0xE2` FPU mem-move family,
`ABS/NOT/SFR`, `ADDB/SUBB XARn`, …).

Note: mnemonic parity does **not** prove operand/semantics correctness
(it only checks the first token); several such bugs were caught by cross-checking the
manual, so keep auditing. See [docs/TESTING.md](docs/TESTING.md) for the parity harness
and the operand/semantics bug classes that parity can't catch.
