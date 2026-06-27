# ghidra-tms320c28x

A Ghidra processor module (SLEIGH) for the Texas Instruments **TMS320C28x** DSP core,
targeting the **TMS320F28377D** (dual-core C28x + FPU, F2837xD family)..

> ⚠️ **WIP — expect bugs.** This is a work in progress and vibe-coded. **Verify against the SPRU430F/SPRUHS1C reference
> before trusting any decode for critical work, and please file issues.**

## Architectural Quirks

1. **Word-addressable memory.** The smallest addressable unit is **16 bits**, not 8.
2. **Variable-length instructions** (16–64 bits, in 16-bit parcels).
3. **`loc16`/`loc32` addressing field.** One shared 8-bit operand field decodes to all
   addressing modes (Table 5-1, SPRU430F). Modeled as a single shared SLEIGH sub-table,
   parameterized by the `AMODE` context bit (from ST1). AMODE=0 is the compiler default
   and is implemented first.
4. **Overlapping registers.** `ACC=AH:AL`, `XT=T:TL`, `P=PH:PL`, `XARn=ARnH:ARn`.
   Modeled with SLEIGH register sub-pieces.
5. **Status flags / modes** (ST0/ST1: Z N C V OVM SXM TC PM AMODE …). Implemented for the
   common ALU/branch subset; PM shift mode and exotic corners approximated.

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

