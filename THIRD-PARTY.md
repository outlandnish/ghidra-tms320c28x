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
  The `TESTTF CNDF` constructor mirrors mwdmwd's one-line `testtf`
  (`STF_TF = cndf`), though the encoding was independently confirmed against
  asm2000/dis2000. The `MOVST0` flag-mask decode (its own `movst0_flags` field
  plus the 256-entry `attach names` list) and the `ctx_fimm16` display fix for
  the `MAXF32` / `MINF32` `#16FHi` immediates are *not* adapted — mwdmwd renders
  neither — and are original to this module.
- **`data/languages/tms320c28x_ext56.sinc`** — *not adapted code*, noted for
  completeness: the `SETC` / `CLRC` mode-bit constructors (`OBJMODE`, `XF`, `OVC`,
  `M0M1MAP`) were wired to write the individual status registers introduced by the
  unpacked flag model above. The register-assignment wiring is this project's own.
- **`src/main/java/ghidra/app/plugin/core/analysis/TMS320C28xSwitchAnalyzer.java`**
  — port of their `TMS320C28SwitchAnalyzer`. Recovers the seven TI-compiler switch
  dispatch shapes (PROGRAM_READ, PROGRAM_READ_SAVED_LONG, NATIVE_PL,
  NATIVE_SAVED_LONG, NATIVE_SAVED_P, NATIVE_AR6_ZERO, NATIVE_DIRECT), validates a
  unique unsigned-range guard, checks index-arithmetic consistency, proves the
  dispatch is a straight-line block, validates the code table and its targets,
  then sets `switch_canonical=1` on the proven index instruction, the optional
  range-subtraction, and the terminal `LB *XAR7` so Ghidra's generic Decompiler
  Switch Analysis can recover case labels. Local changes: processor-name string
  ("TMS320C28x" vs upstream "TMS320C28"), class rename, and XAR7 detection in
  `isComputedXar7Branch()` / `isRegisterOperand()`. Upstream matches XAR7 as
  operand 0 of `LB`; this module's SLEIGH renders `LB *XAR7` with XAR7 baked into
  the mnemonic literal (zero operands), so the terminal branch is matched by
  mnemonic + operand-count + `*XAR7` print form + `isJump && isComputed` flow.
  `isRegisterOperand` also grew an operand-representation fallback for indirect
  `*XAR7` operands (e.g. `MOVL XAR7,*+XAR7[0]`). See #18. Complements — does not
  replace — [`ghidra_scripts/MarkJumpTables.java`](ghidra_scripts/MarkJumpTables.java),
  which is the structured-data marker for the pointer table itself (an original
  entropy-gated pattern detector, no upstream counterpart).
- **`data/languages/tms320c28x_ext56.sinc`** (partial, `switch_canonical=1`
  variants of `MOV ACC,loc16<<#shft` at 0x5603 and `ADD ACC,loc16<<#shft` at
  0x5604) and **`data/languages/tms320c28x_more.sinc`** (partial,
  `switch_canonical=1` variant of `SUB ACC,#imm16<<#shft`) — the canonical
  constructor variants gated on the analyzer-set context bit above. The MOV/ADD
  canonical variants zero-extend `loc16` instead of sign-extending (which is what
  lets the decompiler prove the selector's [0, 0xffff] bound and reach the case
  labels through the subsequent CMP/BF and `LB *XAR7`), and update N/Z; the SUB
  canonical variant adds `C=1` and N/Z updates for arithmetic-flag parity. The
  non-canonical (default) constructors are unchanged. See #18.
- **`data/languages/tms320c28x_rpt.sinc`** (new) and **`data/languages/tms320c28x.slaspec`**
  (partial: `RPTC` / `RB_RSTART` / `RB_RC` / `RB_RE` / `RB_RSIZE` / `RB_RA`
  register slots + `rpt_active` / `rptb_flag` / `rpt_phase` context bits) —
  pure-SLEIGH loop models for RPT and RPTB via `:^instruction` prefix wrappers
  that match on the `rpt_active` / `rptb_flag` context bit and re-execute the
  wrapped instruction while the register-backed counter (`RPTC` / `RB_RC`) is
  non-zero. The body constructors in `tms320c28x_more.sinc` (RPT) and
  `tms320c28x_fpu.sinc` (RPTB, including the `rptb_end` sub-table that computes
  the block-end address and `globalset`s `rptb_flag` there) are the other half
  of the pattern. Makes both loops visible to the decompiler, which the previous
  Java `EmulateInstructionStateModifier` approach never did (it was
  emulation-only). Retires the RPTB half of that callback outright; the RPT half
  is retained for emulation only — see "Emulator cannot arm `inst_next`" below.
  See #19.

  **Divergence from mwdmwd upstream — phase-bit partition on every base constructor.**
  Upstream's wrappers pattern-match on `rpt_phase=0 & rpt_active=1 & instruction`
  and rely on the wrapper being "more constrained" than the base to win the
  SLEIGH pattern-resolution race. In practice `sleigh -l` reports the wrapper
  and every base constructor as *"Constructor patterns cannot be distinguished"*
  and (on Ghidra 12.x) the resolver picks the base — the wrapper is silently a
  no-op and the loop never fires. Every shipped Ghidra processor that uses
  `:^instruction` (ARM `ItCond`, avr8, 8051, Hexagon, M16C) fixes this by
  giving base constructors a positive-phase constraint that the wrapper's
  pattern negates. We do the same: every top-level `:MNEMONIC` constructor
  carries `& rpt_phase=1`; the pspec seeds `rpt_phase=1` as the ram-space
  default; RPT / RPTB globalset `rpt_phase=0` alongside `rpt_active` /
  `rptb_flag` at the wrapped address. The wrapper matches uniquely there and
  its local `[ rpt_phase=1; ]` action restores phase=1 for the inner
  `build instruction` re-parse. The wrappers also carry mutual-exclusion on
  the counterpart bit (`rpt_active=1 & rptb_flag=0` vs `rptb_flag=1 & rpt_active=0`)
  because sleigh's ambiguity checker treats their pattern spaces as overlapping
  otherwise, even though RPT and RPTB cannot arm the same address in practice.

  **RB_RSTART address units.** `RB_RSTART = inst_next >> 1` (word units), not
  `= inst_next` (which stores Ghidra's byte offset). The wrapper's
  `goto [RB_RSTART]` treats the register value as a raw PC (word units on this
  wordsize=2 space), so without the shift the branch lands at 2× the intended
  address. Upstream's `= inst_next` form works only on architectures whose
  PC and register-file agree on units; this is documented for the next port.

  **`rpt_phase` must be `noflow`.** All three dispatch bits are declared
  `noflow`. It is tempting to leave `rpt_phase` flowing on the theory that the
  wrapper's local `[ rpt_phase=1; ]` action bounds its scope — it does not. That
  action applies to the wrapper's own parse and never commits to the following
  address, so a flowing `globalset(inst_next, rpt_phase)` leaves `rpt_phase=0`
  live *past* the repeated instruction. At RPT+2 nothing can then match: the base
  forms require `rpt_phase=1`, the RPT wrapper requires `rpt_active=1` (already
  dropped, being `noflow`) and the RPTB wrapper requires `rptb_flag=1`. The
  address decodes as `<UNDEF>`. Measured on a byte-swapped F28377D production
  image over `0x82000+0x8000`: 57 extra UNDEFs and 3 extra length-skews versus
  `main`, 42 of them exactly two words after an RPT opcode.

  **Emulator cannot arm `inst_next`.** Ghidra's emulator applies a `globalset`
  context commit one instruction too late — the value written for the target
  address only becomes visible after that instruction has already been decoded
  and executed. RPTB is unaffected because its target is the block-end address,
  several instructions ahead. RPT targets `inst_next`, so under emulation the
  base constructor always wins and the wrapper's p-code never runs (`RPTC` is
  never decremented). The RPT arm / re-issue logic therefore stays in
  `postExecuteCallback`; the SLEIGH wrapper remains the decompiler model.
  Disassembly is unaffected — firmware decode parity against TI `dis2000` is
  identical to `main`. See `docs/EMULATION.md` for the measured context dump.
- **`data/languages/tms320c28x_ext56.sinc`** (partial, `CSB ACC` body) —
  pure-SLEIGH port of upstream's `csb` at `tms320c28.sinc:2314` using SLEIGH's
  built-in `lzcount`: for non-negative ACC, `lzcount(ACC)` gives the leading
  redundant sign bits; for negative ACC, `lzcount(~ACC)` gives the leading
  ones. Retires the `countSignBits` CALLOTHER from the Java state modifier.
  See #19.

Deferred (tracked as a follow-up):

- **VCRC8L / VCRC16P1L / VCRC32L** are not ported. Upstream mwdmwd/ghidra-c28x
  does not implement VCU-II at all, so there is no reference to lean on, and a
  pure-SLEIGH port would need an 8× manually unrolled MSB-first bit loop per
  instruction (~30 pcode ops). The `VCRC` pcodeop is kept in the Java modifier
  because its intrinsic name (`VCRC = VCRC8L(VCRC, src)`) is what makes CAN CRC
  compute/check code identifiable in the decompiler — the unrolled form would
  replace that with an unreadable shift-and-XOR salad.

## Nothing else

Beyond the entries above, no other third-party material has been identified.
If you discover something that should be listed here, please open an issue.
