# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core,
targeting the **TMS320F28377D** (dual-core C28x + FPU, F2837xD family).

There is no official Ghidra support for the TMS320C28x. This module fills that gap:
it disassembles and decompiles C28x firmware, which Ghidra otherwise cannot do at all.

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

Skeleton complete and **compiling clean** against Ghidra 12.1.2's SLEIGH compiler:
word-addressable spaces, full register file with aliasing, and 6 verified fixed-opcode
instructions (ABORTI, EALLOW, EDIS, IDLE, ESTOP0, NOP). Next: load-test in Ghidra, then
the shared addressing sub-tables. See the roadmap in [docs/DESIGN.md](docs/DESIGN.md).
