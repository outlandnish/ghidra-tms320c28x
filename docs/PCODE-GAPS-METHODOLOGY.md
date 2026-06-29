# Methodology: resolving C28x decompilation gaps from a fresh context

A repeatable playbook for taking a "this function won't decompile / shows red
`halt_baddata` / has unreachable blocks" report and turning it into a verified SLEIGH fix.
Distilled from the PMR/DIR/PCS/bootloader work logged in `docs/PCODE-GAPS.md`.

Read `docs/PCODE-GAPS-PICKUP.md` first for the environment (paths, compile loop, byte-vs-word
addressing). This doc is the *decision process*; that one is the *mechanics*.

---

## 0. The mental model — three classes of problem

Every "bad decompilation" symptom is one of these. **Classify first; the fix is different for
each.** Most wasted time this project came from assuming the wrong class.

| Class | Symptom | What's wrong | Fix lives in |
|---|---|---|---|
| **A. Missing opcode** | `halt_baddata` tail; a word won't disassemble | no constructor for that encoding | add a `.sinc` constructor |
| **B. Dataflow/semantics defect** | disassembles fine, every op has p-code, but **blocks pruned as "unreachable"** or wrong values | a constructor emits *wrong* p-code (self-reference, missing flag write, `if(1)goto` instead of `goto`) | fix the constructor body |
| **C. Data misread as code** | `halt_baddata` on a function with **0 xrefs**, bytes look like a table | not code at all — a seed landed in data | mark data / remove false seed (NOT a SLEIGH change) |

The fastest classifier:
- Does the failing word **disassemble** (force it, see §2)? No → **A**. Yes but truncates/prunes → **B** or **C**.
- Does the function have **xrefs** and **decode as coherent code**? No xrefs + table-like bytes → **C**. Real callers + sane instructions → **B**.

---

## 1. Set up the target (every session)

1. Reconnect to Ghidra over MCP (`list_instances` → `connect_instance`). Drive a RUNNING
   Ghidra; never headless (multi-minute JVM cold start).
2. The deployed `.sla` is loaded at Ghidra **startup**. After any recompile you MUST have the
   user restart Ghidra, then **re-import the image fresh** (re-analyzing a loaded program
   keeps the OLD language). Re-importing fresh also avoids stale 1-word function bodies.
3. `import_file` (language `TMS320C28x:LE:32:default`, `auto_analyze=false`), then in a script
   `setImageBase(addr,false)` — the `false` avoids the background-analysis Swing deadlock; the
   `import_file` base arg does NOT stick.
4. **Addressing gotcha (load-bearing):** the `ram` space is word-addressed, but the Ghidra
   `getAddress(long)` API takes a BYTE offset = **word × 2**. To reach word `W`, call
   `getAddress(W*2)`. A bare `getAddress(W)` silently lands mid-word and every lookup misses.
   `run_script_inline` is JAVA, not Python.
5. Seed functions: `SeedFunctions.java` (call targets + prologue + fn-ptr tables, with a
   data/entropy filter). Then optionally `MarkJumpTables` / `MarkDataTables` to convert tables
   to data, and `RemoveFalseSeeds` to drop 0-xref truncating stubs on data.

---

## 2. Pin the blocker (find the exact word)

For a reported address (or a sweep hit), find the FIRST undecodable/suspect word:

- **Read the raw words** around it (Java: `mem.getByte(addr)` low, `addr.add(1)` high → LE16
  word). Do NOT hand-transcribe — byte order bites.
- Walk the function body in order; the first word that is neither a defined instruction start
  nor inside a multi-word instruction is the blocker. ⚠️ A **branch shadow** (a word reached
  only via a conditional branch, e.g. right after `SB ...,GEQ`) is missed by a "first word
  past `body.getMaxAddress()`" walk — scan the FULL body range, not just the tail.
- Compute `op_hi8 = word>>8`, `op_hi7 = word>>9`.

---

## 3. Identify the word — manual + the dis2000 ORACLE

1. Grep the encoding in `docs/c28x/ch6_instruction_detail.txt` (core) /
   `fpu_instructions.txt` (FPU) / `tmu_instructions.txt` / `vcu2_*`. Convert the word to the
   `0101 0110 ....` bit pattern and grep the `Opcode` line. Confirm **1-word vs 2-word** (a
   trailing `CCCC CCCC ...` opcode line = 2-word) BEFORE writing the constructor — a wrong
   word count skews everything after.
2. ⭐ **If the manual grep comes up empty OR ambiguous, run the word through TI `dis2000`.**
   It is the ground-truth oracle and has repeatedly been right where the manual grep was wrong
   (rendering quirks, A-bit/condition placeholders, multi-line opcode wraps). Harness:
   ```
   BIN=C:\Users\nisha\Downloads\ti-cgt-c2000_25.11.0.LTS\bin
   # write a .asm of .word probes (the LIVE image words, already byte-correct), then:
   asm2000 -v28 probe.asm -o probe.obj ; dis2000 --all --data_as_text probe.obj
   ```
   Separate probes with a NOP (`0x7700`) — a 2-word op swallows the next probe as its operand.
   ⚠️ The Bash tool's `wsl bash -s` pipe eats stdout / mangles `/tmp`; write the script to
   `//wsl.localhost/.../tmp/x.sh`, run `wsl.exe -d Ubuntu-24.04 -- bash -lc 'bash /tmp/x.sh'`,
   read the result file over the UNC path.
3. **dis2000 force-decodes data too** — so "dis2000 gave a mnemonic" does NOT prove it's code.
   Cross-check with the data test in §6.

---

## 4. Class A — add the missing opcode

- Find the right `.sinc` by family: core ALU/MOV/branch → `more.sinc`/`mov.sinc`/`alu.sinc`/
  `flow.sinc`; `0x56`-prefix extended → `ext56.sinc`; FPU `0xE0-0xE8` → `fpu.sinc`; MAC →
  `mac.sinc`; addressing modes → `addr.sinc`.
- **Mirror an existing sibling constructor exactly** (operand subtables, token fields, `;`
  for the 2nd word). The `loc16`/`loc32` subtables apply to word2 when placed after `;`.
- Semantics: real where cheap and high-value; **flow-preserving** otherwise (write the dest /
  touch a reg so the op emits non-empty p-code and flow continues). An EMPTY `{ }` body
  truncates the decompiler — a "no-op" must still emit something.
- **Back-fill the whole family in one pass.** TI packs siblings into adjacent encodings
  (the `0xE7` parallel `||ADD/||SUB`, the `0x561x` mode cluster, the `*B AX,#imm8` family,
  the QMPYL/QMPYUL/QMPYXUL/IMPYXUL multiplies). Adding one variant and stopping just means the
  next image re-hits the sibling. Enumerate the encoding block and add all real members.

---

## 5. Class B — fix the dataflow/semantics (the subtle, invisible bugs)

These disassemble fine, so they hide. Symptom is usually **"Removing unreachable block"**
warnings + a missing body. Known failure modes from this project (audit for all of them):

1. **Self-reference.** A 2-op-er stubbed `dst = dst` (ignoring the real source reg) makes the
   decompiler constant-fold and prune. Fix: read the actual source field. (`ADDF32 RaH,#imm,RbH`
   was `f_ra=f_ra`; reading `f_rb` was the load-bearing fix.)
2. **Missing flag write.** An op whose TI "Flags and Modes" lists N/Z/C/V but whose body omits
   `setNZ16`/carry — a following `SB/B ,cond` then reads a STALE flag, the decompiler proves the
   branch constant and prunes a real arm. Fix: set the flags. (`ANDB/ADDB/MOVB AX,#imm8`.)
   Detect by diffing the flag-write p-code against the next conditional branch.
3. **`if(const_true) goto` is NOT an unconditional branch.** A `,UNC`/always condition routed
   through a CC subtable that exports `1:1` compiles to a **CBRANCH with a live dead
   fall-through edge** → the fall-through-only blocks get pruned. Fix: a dedicated, more-specific
   `goto`-only constructor for the always-true code. (`SB/B ,UNC`.)
4. **Wrong word count / over-broad pattern** (the worst — silent corruption, no `halt_baddata`).
   A constructor that claims N words when the op is M, or whose pattern matches a *different*
   op, desyncs all following decode. (`MAX AX,loc16` claimed `FLIP` + ate a word.) Detect with
   the dis2000 **length-differential** sweep (§7).

For B, dump the **raw p-code** of the suspect instruction (`ins.getPcode()`) and read what it
actually emits vs. what the op should do. The decompiled C's "unreachable block" warnings name
the pruned addresses — walk backward from there to the branch and the op feeding its flags.

---

## 6. Class C — data misread as code (do NOT touch SLEIGH)

Confirm it's data, then mark/remove. Signals (any two = data):
- **0 xrefs** to the "function" entry (`getReferencesTo`). Real functions have callers.
  ⚠️ Exception: reset/init routines reached via the reset vector have 0 xrefs but decompile
  CLEANLY — those are real. ⚠️ And a call byte-scan can be fooled by FPU operand words that
  look like `LC`/`LCR`, giving a data blob a spurious xref — so weigh xrefs with the others.
- **Regular-stepping high words** across the region (`0x3exx→0x3fxx` floats; `0x87xx` cluster;
  pointer pairs `lo,0x0008`). Code doesn't march monotonically.
- **ASCII** when rendered as chars (C28x packs one char per 16-bit word).
- Decode as **IEEE-754 floats**: ≥90% "sane" (nonzero, exponent ~1e-19..1e19) over a long run.

Tools: `MarkJumpTables` (pointer/switch tables), `MarkDataTables` (float tables), and
`RemoveFalseSeeds` (0-xref + small + truncating stubs on irregular tables). All have
`-D...dryRun=true`. Conservative by design — they skip anything overlapping a *referenced*
function so real code is never clobbered.

---

## 7. Compile, deploy, verify

1. **Compile** (PowerShell; UNC can't host the `.bat`, copy to Windows temp):
   ```
   copy data/languages/* to %TEMP%\c28x-build\languages ; sleigh.bat tms320c28x.slaspec
   ```
   Clean = only NOP / extension / "wrote to temporaries not read" WARNs. **Any ERROR = no
   `.sla` written** — read the FIRST error (later cascade); see `docs/SLEIGH-IDIOMS.md`.
2. **Verify the build took:** the `.sla` **size delta** is the only reliable signal (grep-by-
   mnemonic gives false negatives — mnemonics are tokenized). No growth = it didn't pick up the
   edit (often a stale copy compiling old source).
3. **Deploy** to BOTH `data/languages/` (the repo) and the Ghidra `Processors/TMS320C28x/data/
   languages/` dir.
4. **Restart Ghidra** (ask the user), reconnect, **re-import the image fresh**, set base, seed.
5. **Verify the fix:** for class A, the failing word now decodes + the function ends in
   `return` with no `halt_baddata`. For class B, the named "unreachable block" warnings are
   GONE and the pruned body appears in the C. Always re-check a **regression ref** stays clean
   (`CAN_init`, the FPU function, or the TI `k_expf`/`catrigf` parity sweep).
6. **Sweep** for the next gap (full-body-range, branch-shadow-aware) and repeat. When the
   real-gap count is 0 and only 0-xref data false-seeds remain, the image is clean.

---

## 8. Commit discipline

- Module changes go to the PUBLIC `ghidra-tms320c28x` repo. Keep messages **Tesla-name-free**
  ("a real F28377D production image", not the vehicle/ECU) per the repo-visibility rule.
- Commit per fix/batch after the verify. `SetupF28377D.java` shows as modified from another
  session — don't stage it unless you changed it. The `docs/PCODE-GAPS*.md` are gitignored —
  don't commit them; update them in place to record OPEN→RESOLVED.
- One commit per opcode family or per dataflow fix, with the dis2000-confirmed encoding and the
  surfacing image/address in the message.

---

## 9. The recurring lessons (don't re-learn these)

- **dis2000 is the oracle.** When the manual is unclear, probe it. It corrected the manual grep
  multiple times.
- **Back-fill families**, don't chase one sibling at a time.
- **Branch shadows and stale flags hide bugs** that look fine in disassembly — a fix isn't done
  until the decompiled C is clean, not just the listing.
- **`if(1)goto` ≠ goto; `dst=dst` ≠ identity-is-harmless; empty `{}` ≠ no-op** — each silently
  corrupts the decompiler.
- **0-xref + table-bytes = data, not a missing opcode** — but reset/init routines are the
  0-xref exception. Verify, don't assume (it was wrong both directions in this project).
- **Always re-import after a recompile**; never trust a stale loaded program or a same-size `.sla`.
