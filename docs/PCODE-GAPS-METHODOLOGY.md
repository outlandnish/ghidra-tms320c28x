# Resolving C28x decompilation gaps

A repeatable playbook for taking a "this function won't decompile / shows red
`halt_baddata` / has unreachable blocks" report and turning it into a verified
SLEIGH fix.

For the *mechanics* — build/compile loop, headless decode-parity harnesses, the
byte-vs-word addressing model — see [BUILDING.md](BUILDING.md),
[TESTING.md](TESTING.md), and (for emulation) [EMULATION.md](EMULATION.md).

## 0. The mental model — three classes of problem

Every "bad decompilation" symptom is one of these. **Classify first; the fix is
different for each.**

| Class | Symptom | Cause | Fix lives in |
|---|---|---|---|
| **A. Missing opcode** | `halt_baddata` tail; a word won't disassemble | no constructor for that encoding | add a `.sinc` constructor |
| **B. Dataflow/semantics defect** | disassembles fine, every op has p-code, but **blocks pruned as "unreachable"** or wrong values | a constructor emits *wrong* p-code (self-reference, missing flag write, `if(1)goto` instead of `goto`) | fix the constructor body |
| **C. Data misread as code** | `halt_baddata` on a function with **0 xrefs**, bytes look like a table | not code at all — a seed landed in data | mark data / remove false seed (NOT a SLEIGH change) |

Fastest classifier:
- Does the failing word **disassemble** (force it, §2)? No → **A**. Yes but
  truncates/prunes → **B** or **C**.
- Does the function have **xrefs** and **decode as coherent code**? No xrefs +
  table-like bytes → **C**. Real callers + sane instructions → **B**.

## 1. Set up the target

1. Drive a **running** Ghidra (multi-minute JVM cold start makes headless
   iteration painful).
2. The deployed `.sla` is loaded at Ghidra **startup**. After any recompile you
   must restart Ghidra AND **re-import the image fresh** (re-analyzing a loaded
   program keeps the OLD language). Re-importing fresh also avoids stale 1-word
   function bodies.
3. `import_file` (language `TMS320C28x:LE:32:default`, `auto_analyze=false`),
   then in a script `setImageBase(addr, false)` — the `false` avoids the
   background-analysis Swing deadlock; the `import_file` base arg does NOT stick.
4. **Addressing gotcha (load-bearing):** the `ram` space is word-addressed, but
   Ghidra's `getAddress(long)` takes a BYTE offset = **word × 2**. To reach word
   `W`, call `getAddress(W*2)`. A bare `getAddress(W)` silently lands mid-word
   and every lookup misses. `run_script_inline` is JAVA, not Python.
5. Seed functions: `SeedFunctions.java` (call targets + prologue + fn-ptr tables,
   with a data/entropy filter). Then optionally `MarkJumpTables` /
   `MarkDataTables` to convert tables to data, and `RemoveFalseSeeds` to drop
   0-xref truncating stubs on data.

## 2. Pin the blocker (find the exact word)

For a reported address (or a sweep hit), find the FIRST undecodable/suspect word:

- **Read the raw words** around it (Java: `mem.getByte(addr)` low, `addr.add(1)`
  high → LE16 word). Do NOT hand-transcribe — byte order bites.
- Walk the function body in order; the first word that is neither a defined
  instruction start nor inside a multi-word instruction is the blocker.
  ⚠️ A **branch shadow** (a word reached only via a conditional branch, e.g.
  right after `SB ...,GEQ`) is missed by a "first word past
  `body.getMaxAddress()`" walk — scan the FULL body range, not just the tail.
- Compute `op_hi8 = word>>8`, `op_hi7 = word>>9`.

## 3. Identify the word — manual + the dis2000 ORACLE

1. Grep the encoding in `docs/c28x/ch6_instruction_detail.txt` (core) /
   `fpu_instructions.txt` / `tmu_instructions.txt` / `vcu2_*`. Convert the word
   to the `0101 0110 ....` bit pattern and grep the `Opcode` line. Confirm
   **1-word vs 2-word** (a trailing `CCCC CCCC ...` opcode line = 2-word) BEFORE
   writing the constructor — a wrong word count skews everything after.
2. ⭐ **If the manual grep is empty or ambiguous, run the word through
   `dis2000`.** It is the ground-truth oracle and is regularly right where the
   manual grep is wrong (rendering quirks, A-bit/condition placeholders,
   multi-line opcode wraps). `tests/run_fw_parity.sh` wraps the whole
   probe → assemble → dis2000 sequence over a word range of a real image. For a
   one-off probe of a bare encoding, separate probes with a NOP (`0x7700`) —
   a 2-word op swallows the next probe as its operand.
3. **`dis2000` force-decodes data too** — "dis2000 gave a mnemonic" does NOT
   prove it's code. Cross-check with the data test in §6.

## 4. Class A — add the missing opcode

- Find the right `.sinc` by family: core ALU/MOV/branch → `more.sinc` /
  `mov.sinc` / `alu.sinc` / `flow.sinc`; `0x56`-prefix extended → `ext56.sinc`;
  FPU `0xE0-0xE8` → `fpu.sinc`; MAC → `mac.sinc`; addressing modes → `addr.sinc`.
- **Mirror an existing sibling constructor exactly** (operand subtables, token
  fields, `;` for the 2nd word). The `loc16`/`loc32` subtables apply to word2
  when placed after `;`.
- Semantics: real where cheap and high-value; **flow-preserving** otherwise
  (write the dest / touch a reg so the op emits non-empty p-code and flow
  continues). An EMPTY `{ }` body truncates the decompiler — a "no-op" must
  still emit something.
- **Back-fill the whole family in one pass.** TI packs siblings into adjacent
  encodings (e.g. the `0xE7` parallel `||ADD/||SUB`, the `0x561x` mode cluster,
  the `*B AX,#imm8` family, the QMPYL/QMPYUL/QMPYXUL/IMPYXUL multiplies). Adding
  one variant and stopping means the next image re-hits the sibling.

## 5. Class B — fix the dataflow/semantics (subtle, invisible bugs)

These disassemble fine, so they hide. Symptom is usually **"Removing unreachable
block"** warnings + a missing body. Audit for these failure modes:

1. **Self-reference.** A 2-op-er stubbed `dst = dst` (ignoring the real source
   reg) makes the decompiler constant-fold and prune. Fix: read the actual
   source field. Example: `ADDF32 RaH,#imm,RbH` needs to read `f_rb`, not
   `f_ra`.
2. **Missing flag write.** An op whose TI "Flags and Modes" table lists N/Z/C/V
   but whose body omits `setNZ16` / carry — a following `SB/B ,cond` then reads
   a STALE flag, the decompiler proves the branch constant and prunes a real
   arm. Fix: set the flags. Detect by diffing the flag-write p-code against the
   next conditional branch. Example: `ANDB/ADDB/MOVB AX,#imm8`.
3. **`if(const_true) goto` is NOT an unconditional branch.** A `,UNC`/always
   condition routed through a CC subtable that exports `1:1` compiles to a
   **CBRANCH with a live dead fall-through edge** → the fall-through-only blocks
   get pruned. Fix: a dedicated, more-specific `goto`-only constructor for the
   always-true case. Example: `SB/B ,UNC`.
4. **Wrong word count / over-broad pattern** — the worst class, silent
   corruption with no `halt_baddata`. A constructor that claims N words when the
   op is M, or whose pattern matches a *different* op, desyncs all following
   decode. `tests/run_fw_parity.{ps1,sh}` reports these as "length skew".

For B, dump the **raw p-code** of the suspect instruction (`ins.getPcode()`) and
compare against what the op should do. The decompiled C's "unreachable block"
warnings name the pruned addresses — walk backward from there to the branch and
the op feeding its flags.

## 6. Class C — data misread as code (do NOT touch SLEIGH)

Confirm it's data, then mark/remove. Signals (any two = data):
- **0 xrefs** to the "function" entry (`getReferencesTo`). Real functions have
  callers.
  ⚠️ Exception: reset/init routines reached via the reset vector have 0 xrefs
  but decompile CLEANLY. ⚠️ And a call byte-scan can be fooled by FPU operand
  words that look like `LC`/`LCR`, giving a data blob a spurious xref — weigh
  xrefs with the others.
- **Regular-stepping high words** across the region (`0x3exx→0x3fxx` floats;
  `0x87xx` cluster; pointer pairs `lo, 0x0008`). Code doesn't march
  monotonically.
- **ASCII** when rendered as chars (C28x packs one char per 16-bit word).
- Decode as **IEEE-754 floats**: ≥90% "sane" (nonzero, exponent ~1e-19..1e19)
  over a long run.

Tools: `MarkJumpTables` (pointer/switch tables), `MarkDataTables` (float
tables), and `RemoveFalseSeeds` (0-xref + small + truncating stubs on irregular
tables). All have `-D...dryRun=true`. Conservative by design — they skip
anything overlapping a *referenced* function so real code is never clobbered.

## 7. Compile, deploy, verify

1. **Compile:**
   ```sh
   "$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/tms320c28x.slaspec
   ```
   Clean = only NOP / extension / "wrote to temporaries not read" WARNs. **Any
   ERROR = no `.sla` written** — read the FIRST error; see [SLEIGH-IDIOMS.md](SLEIGH-IDIOMS.md).
2. **Verify the build took:** the `.sla` **size delta** is the only reliable
   signal (grep-by-mnemonic gives false negatives — mnemonics are tokenized).
   No growth = it didn't pick up the edit (often a stale copy compiling old
   source).
3. **Deploy** the fresh `.sla` into the installed processor module
   (`$GHIDRA_INSTALL_DIR/Ghidra/Processors/TMS320C28x/data/languages/`).
   `tests/run_disasm_test.sh` does exactly this and runs the regression harness.
4. **Restart Ghidra**, reconnect, **re-import the image fresh**, set base, seed.
5. **Verify:** class A — the failing word decodes, the function ends in `return`
   with no `halt_baddata`. Class B — the "unreachable block" warnings are GONE
   and the pruned body appears in the C. Always re-check a regression reference
   (a known-good function + one or two `run_fw_parity.sh` ranges you were
   tracking).
6. **Sweep** for the next gap (full-body-range, branch-shadow-aware) and repeat.
   When the real-gap count is 0 and only 0-xref data false-seeds remain, the
   image is clean.

## 8. Recurring lessons

- **`dis2000` is the oracle.** Probe it when the manual is unclear.
- **Back-fill families**, don't chase one sibling at a time.
- **Branch shadows and stale flags hide bugs** that look fine in disassembly —
  a fix isn't done until the decompiled C is clean, not just the listing.
- **`if(1)goto` ≠ goto; `dst=dst` ≠ identity-is-harmless; empty `{}` ≠ no-op**
  — each silently corrupts the decompiler.
- **0-xref + table-bytes = data**, not a missing opcode — but reset/init
  routines are the 0-xref exception. Verify, don't assume.
- **Always re-import after a recompile**; never trust a stale loaded program or
  a same-size `.sla`.
