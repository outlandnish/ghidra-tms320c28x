# Third-party provenance

This file records where non-original material in this repository comes from, so
the licensing story is auditable. The umbrella notice lives in [NOTICE](NOTICE);
this document adds per-file/per-area detail.

## TL;DR

- This module is Apache-2.0 (see [LICENSE](LICENSE)).
- Peripheral register maps in `SetupF28377D.java` / `SetupF2812.java` were
  transcribed from TI technical reference manuals and device datasheets. Names
  and addresses are hardware facts; where naming conventions trace back to TI's
  own C headers, TI's BSD-3-Clause notice applies (reproduced in NOTICE).

## Per-file / per-area notes

### `ghidra_scripts/SetupF28377D.java`

Peripheral frame addresses, register names, and field layouts derived from:

- **SPRUHM8K** — F2837xD Technical Reference Manual (Texas Instruments)
- **SPRS880P** — F2837xD Device Datasheet, Table 7-1 (memory map)

Where a naming convention (e.g. `AdcaRegs.ADCCTL1`, `EPwm1Regs.TBCTL`) matches the
identifiers used in TI's C2000Ware device header files (`F2837xD_device.h`,
`F2837xD_Adc_defines.h`, etc.), that portion is materially TI-derived and
carries TI's BSD-3-Clause terms (see NOTICE). Individual register addresses and
field bit positions are facts about the hardware and are not themselves
copyrightable.

### `ghidra_scripts/SetupF2812.java`

Peripheral frame addresses, register names, and field layouts derived from:

- **SPRU430F** — TMS320C28x CPU and Instruction Set Reference Guide
- **SPRUFB0** — F281x System Control and Interrupts Reference Guide
- **SPRS174** — TMS320F2812 Device Datasheet (memory map)
- Peripheral-specific TRMs for eCAN, EV, ADC, SCI, SPI, McBSP, etc.

Same BSD-3-Clause caveat as above where names match TI's F281x header files.

### `data/languages/tms320c28x*.sinc`, `tms320c28x.slaspec`

SLEIGH constructors for the C28x instruction set. Encodings, mnemonics, and
operand tables are derived from:

- **SPRU430F** — TMS320C28x CPU and Instruction Set Reference Guide (fixed-point)
- **SPRUHS1C** — TMS320C28x Floating-Point Unit and Instruction Set Reference
  Guide (FPU32, TMU, VCU)

These reference manuals describe hardware behavior; the SLEIGH spec is this
project's own description of that behavior. Instruction encodings, mnemonics,
and syntax are facts. No prose is copied verbatim; where the manuals are
paraphrased in comments, the source section is cited.

Excerpted reference chapters under `docs/c28x/` (e.g. `ch6_instruction_summary.txt`,
`appA_register_quickref.txt`) are extracts from the TI manuals for local editing
convenience during development. They are used as fair-use references and cited
by section number; do not treat them as newly-authored content.

### `data/languages/tms320c28x.ldefs`, `.pspec`, `.cspec`

Ghidra language definition files. These follow the standard Ghidra processor-module
schema. No content was copied from any specific Ghidra processor module — the
schemas and idioms are the public Ghidra API surface for processor modules.

### `build.gradle`

The Ghidra Apache-2.0 "IP: GHIDRA" header block originated in Ghidra's extension
template (`Ghidra/Extensions/*/build.gradle`). It is retained per Apache-2.0
section 4(b) alongside this project's own SPDX + copyright line at the top of the
file.

### `tests/ti_*.bin`, `tests/*.sidebyside.txt` (gitignored, not tracked)

The firmware parity harness `tests/run_fw_parity.{ps1,sh}` invokes TI's
`asm2000` + `dis2000` at test time to produce ground-truth listings for a word
range of an image. Any resulting TI-authored artifacts (COFF2 objects, dis2000
listings, extracted `.text` bins) are TI-licensed and **not redistributable**
under Apache-2.0. They are gitignored and must never be committed. Bring your
own TI CGT install; point the harness at it via `$env:C2000WARE` / `-Ti <dir>`
(PowerShell) or `C2000WARE=... -Ti <dir>` (shell).

## Ghidra-bundled processor modules

No files in this repo were copied from another Ghidra-bundled processor module.
The processor module conventions (directory layout, `.ldefs`/`.pspec`/`.cspec`
schema, `sleigh` invocation) come from the public Ghidra extension API and do
not require attribution.

## Adapted from mwdmwd/ghidra-c28x (Apache-2.0)

An independent C28x Ghidra processor module,
[`mwdmwd/ghidra-c28x`](https://github.com/mwdmwd/ghidra-c28x), is also
Apache-2.0-licensed. Its maintainer invited reuse under that license in
[issue #12](https://github.com/outlandnish/ghidra-tms320c28x/issues/12).

Adoption is tracked by issues labeled
[`upstream-merge`](https://github.com/outlandnish/ghidra-tms320c28x/issues?q=is%3Aissue%20label%3Aupstream-merge).
Each merging PR appends the specific file(s) it adapted here, and preserves the
`mwdmwd` copyright line in the header of any materially-adapted file per
Apache-2.0 §4(b).

Files adapted so far:

- **`data/languages/tms320c28x.cspec`** — pentry ordering (hiddenret / ptr /
  float / general per SPRU514 §7), `stackshift="2"` + stack pentry `offset="2"`
  frame accounting for the RPC push, `context_data <tracked_set>` establishing
  the TI C-runtime state (PM=0 / OVM=0 / PAGE0=0, SPRU514 Table 7-4), extended
  `killedbycall` list (DP + status registers), and the standalone `interrupt`
  prototype. See #15.
- **`src/main/java/ghidra/app/plugin/core/analysis/TMS320C28xFfcReturnAnalyzer.java`**
  — port of their `TMS320C28FfcReturnAnalyzer`. Local changes: the processor-name
  string ("TMS320C28x" here vs "TMS320C28" upstream), the class rename, and the
  FFC/LB detection in `ffcTarget()` / `isXar7Branch()`. Upstream matches XAR7 as
  operand 0; this module's SLEIGH renders `FFC XAR7,#t` / `LB *XAR7` with XAR7 as a
  print literal (FFC operand 0 is the target; `LB *XAR7` has no operand), so
  detection is by mnemonic + resolved call flow / the `*XAR7` print form. Runtime-
  verified: with upstream's operand-0 checks the analyzer never fired on this
  module. See #16.
- **`data/languages/tms320c28x_more.sinc`** (partial) — the three-variant
  `LB *XAR7` constructor split dispatched by (`ffc_return`, `switch_canonical`)
  SLEIGH context bits, plus the `XAR7 & 0x003fffff` 22-bit PC mask on the
  branch/return targets (see #16); and the unpacked status-flag model plumbing:
  the `packst0` / `unpackst0` / `packst1` / `unpackst1` macros and their wiring on
  `PUSH` / `POP ST0` / `ST1`, the per-flag `SETC` / `CLRC #imm8` bodies, and the
  decoded-signed `PM` convention used by `SPM`.
- **`data/languages/tms320c28x.slaspec`** (partial) — the `ffc_return` and
  `switch_canonical` context bit definitions (see #16); the unpacked
  status-flag model: each ST0/ST1 status bit defined as its own register (the
  `define register` blocks at 0x100 / 0x110) with the `$(NAME)` flag macros
  expanding to those registers, which is what lets the compiler-spec
  `context_data <tracked_set>` name `PM` / `OVM` / `PAGE0` (SPRU514 Table 7-4);
  and the STF flag sub-registers at 0x124 (`STF_LV` / `STF_LU` / `STF_NF` /
  `STF_ZF` / `STF_NI` / `STF_ZI` / `STF_TF`) that the FPU condition-code table
  reads. See #17.
- **`data/languages/tms320c28x_fpu.sinc`** (partial) — the `cndf` sub-table
  (12 float conditions plus `UNC` / `UNCF`) exporting a 1-byte boolean; the
  operand-conditioning macros `fpu_cmp_operand` and `tmu_condition_operand`
  (denormal / NaN canonicalisation per SPRUHS1C §7.5.2); `fpu_minmax_output`
  for MAX/MIN result flushing; the flag-writing macros `update_stf` (arith
  1-op), `update_stf_cmp` (compare with conditioned operands),
  `update_stf_mov` (MOV loads: ZI/NI alongside ZF/NF); `packstf` /
  `unpackstf` for the packed-STF sync on STF ↔ memory moves; the UNCF-vs-
  conditional split on `MOV32` / `NEGF32` / `SWAPF ... cndf`; and the
  `MOVST0 → $(Z) / $(N)` forward from `STF_ZF` / `STF_NF` (replacing the
  previous packed `STF[0,1]` bit slices). Wired at every flag-setting site:
  CMPF32 (4 forms) → `update_stf_cmp`; MAXF32 / MINF32 (reg-reg, immediate,
  parallel-with-MOV32) → `update_stf_cmp` + `fpu_minmax_output` on the
  written result; ABSF32 and NEGF32 UNCF → `update_stf`; MOV32 UNCF loads
  (mem32, reg) → `update_stf_mov`; TMU inputs (MPY2PIF32, DIV2PIF32, DIVF32,
  SQRTF32) → `tmu_condition_operand`. See #17.
- **`data/languages/tms320c28x_ext56.sinc`** — *not adapted code*, noted for
  completeness: the `SETC` / `CLRC` mode-bit constructors (`OBJMODE`, `XF`, `OVC`,
  `M0M1MAP`) were wired to write the individual status registers introduced by the
  unpacked flag model above. The register-assignment wiring is this project's own.

## Nothing else

Beyond the entries above, no other third-party material has been identified.
If you discover something that should be listed here, please open an issue.
