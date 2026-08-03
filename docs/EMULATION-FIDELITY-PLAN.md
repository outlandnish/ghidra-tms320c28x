# PLAN — make the C28x SLEIGH faithful enough to *emulate* (not just decode)

Status: **return-address emulation is fixed** (branch `fix/sleigh-emu-return-addr`).
Calls/returns now emulate correctly through arbitrary nesting. The remaining gap is
**data-path opcode fidelity**: emulating a known-good routine (AES-128) produces a wrong
result, so one or more compute instructions have wrong/empty p-code. This plan closes that
gap using **TI `dis2000` as decode ground-truth** + **differential emulation** against known
vectors. It is an independent workstream — it does not touch the return-address fix or the
`feature/widen-sp` branch.

---

## What's already done (don't redo)

Two return-address bugs, both fixed in `fix/sleigh-emu-return-addr`:

1. **Return addr stored as a byte offset.** `RPC/XAR7 = inst_next` stored `word*2`
   (`Address.getOffset()` is a byte offset in a `wordsize=2` space), but `return [RPC]`
   reads it as a word address → returns to 2× → out of range. **Fix:** `inst_next >> 1`.
2. **No RPC stack save/restore.** Hardware `LCR`/`LC`/`XCALL` push the old `RPC` and
   `LRETR`/`XRET` pop it (nested-call return chain, like ARM stacking `LR`). The spec modeled
   `RPC` as a single register, so a nested call clobbered the caller's return address →
   infinite self-return. **Fix:** model the push/pop (mirrors the existing `PUSH/POP RPC`
   idiom, `zext(SP)` + `*[ram]:4`).

Validated: on the AES call chain the emulator now returns correctly (sane `RPC` word
addresses, balanced `SP`). Cost: calling functions gain a minor `unaff_retaddr` spill in the
decompiler (RPC is declared `<returnaddress>` in the cspec, so it's mostly pruned).

---

## The remaining problem (what this plan fixes)

Emulating `AES128_encryptBlock_gen26 @0x9af9e` on the FIPS-197 vector
(key `000102…0f`, pt `0011…ff`) yields `c66363a5 81cdcd4c 60303050 00000000` instead of
`69c4e0d8 6a7b0430 d8cdb780 70b4c55a`. The state is wrong **before** any derail
(`SubBytes(pt⊕key0)` should be `63 ca b7 04 …`, not `c6 63 63 a5 …`), and the tail is zeros —
so a compute op is silently doing nothing or the wrong thing, and control flow then wanders
into unrelated runtime code via an uninitialised function pointer.

Root cause class: the module was built for **disassembly/decompilation**, where many ops are
"decode-only" (correct mnemonic, empty/minimal p-code) — fine for reading code, fatal for
emulation. The last compile flagged the smell directly:
`23 NOP constructors`, `19 unnecessary extensions→copies`, `5 operations wrote to
temporaries that were not read`.

---

## Part A results (dis2000 decode parity — DONE)

Ran dis2000 decode parity on all three target functions in `dir_26_65_2`. Tooling:
`tests/run_fw_parity.ps1` (new) — slices a word range out of the swapped image, emits it as
`.word` directives, `asm2000 -> dis2000 -i` for TI ground truth, headless-disassembles the
same raw `.bin` with our installed `.sla` (DumpParity), aligns on word address.

Function extents (terminal `LRETR`): AES `0x9af9e..0x9b08f` (242 w), key-schedule
`FUN_000aae42 0xaae42..0xaae95` (84 w), compute-expected `0xa3678..0xa370b` (148 w).

**Decode (mnemonic + instruction length) is CLEAN across all three:**

| fn | TI instrs | agree | WRONG | UNDEF | length-skew |
|----|-----------|-------|-------|-------|-------------|
| AES128_encryptBlock_gen26 | 211 | 211 | 0 | 0 | 0 |
| FUN_000aae42 (key sched)  |  72 |  72 | 0 | 0 | 0 |
| DIR_immoChallengeRefresh_computeExpected | 126 | 126 | 0 | 0 | 0 |

So the AES emulation failure is **NOT a wrong-decode** — it is a p-code **semantics** bug (Part
B). The operand-text diffs (e.g. 156/211 on AES) are almost entirely cosmetic (hex vs dec, the
`@` register-direct marker, `[0]` vs `[0x0]`, relative vs absolute branch targets). After
filtering, only two *genuine* operand-resolution gaps remain, both already-documented
`decode-only` constructors with empty p-code:

1. **`RPTB` block-repeat is not modeled** (`tms320c28x_fpu.sinc:162-169`). The constructor only
   does `RB = zext(RSIZE)`; it does not set the repeat-end / model the loop, and it ignores the
   `loc16` count word (renders a hardcoded `*loc16` instead of `AR6`). Under emulation the block
   runs **once**. This is hit by AES **MixColumns** (`RPTB #$+18,AR6 @0x9b00f`) and its byte loop
   (`@0x9b05c`), **and** by compute-expected (3× `RPTB @0xa36b7/cb/ec`). => **prime Part-B lead**:
   fixing RPTB unblocks both the AES acceptance vector and the compute-expected end goal. The
   observed wrong AES state `c66363a5…` is exactly `MixColumns([63,0,0,0])` — consistent with the
   MixColumns loop executing a single iteration.
2. **`MOV32` indirect `mem32` (`*SP++` / `*--SP`) is a no-op** (`tms320c28x_fpu.sinc:233,246`):
   deliberately doesn't compute the address ("pointer unrecoverable from the MSW low byte"), so
   the AES prologue pushes / epilogue pops of R4H-R7H don't touch memory and don't advance SP.
   Round body uses reg-to-reg MOV32 (modeled), so lower impact than RPTB, but breaks SP balance.

No `ext56` / `0x56`-prefix decode problems surfaced in any of the three functions.

Harness note: `tests/run_ti_parity.ps1` had two latent crash bugs (a `-Dprop` arg this Ghidra
rejects on the headless CLI; a `$ti`/`-Ti` case-insensitive+type-constrained variable collision
that coerced the hashtable to a string) — both fixed. It still has a *third* pre-existing bug (its
hand-rolled COFF2 `.text` extraction misaligns from word 0, making its k_expf comparison invalid);
`run_fw_parity.ps1` avoids the class entirely by round-tripping the same bytes through asm2000.

---

## Part B progress (differential emulation) — MOVB fixed; RPTB + isolation-derail open

Drove Ghidra's `EmulatorHelper` on the FIPS-197 vector (plaintext/key one-byte-per-word @
`0x13000`/`0x13020`, `XAR4/XAR5` = those, `SP=0x600`, `RPC`=sentinel, step to sentinel).
Reproduced the plan's exact bad state `c66363a5 81cdcd4c 60303050 00000000`, then bisected by
snapshotting the 16 state bytes at each transform boundary. Key gotcha: on this wordsize-2
space the **PC register holds a WORD address** (execution-Address `getOffset()` = word×2) —
set PC to the word, not word×2.

**Bug #1 — `MOVB Ax.LSB, *+XARn[ARm]` byte-addressing (FIXED).** First divergence was SubBytes:
the S-box table is byte-packed (2 entries/word) and `MOVB ... *+XARn[ARm]` must byte-address
(`byteaddr = (XARn<<1)+ARm`, lane = ARm&1), but the shared `loc16` path computed a WORD addr
(`XARn+ARm`) and took the low byte → returned `sbox[2*ARm]` (even entries only). Fixed in
`tms320c28x_more.sinc`: carved the AR0/AR1-indexed byte forms out of the generic `MOVB`
(`loc_mode5 != 0b10010/0b10011`) and added true byte-addressed constructors (LSB+MSB × AR0/AR1).
Decode-neutral (AES/KS/CE parity still 211/72/126, 0 wrong/undef/skew; addr_modes 14/14).
Validated: post-fix **AddRoundKey, SubBytes, ShiftRows, MixColumns are all bit-exact** vs
FIPS-197 (`postSBX=63cab704…e18c`, `postMIX=5f726415…f91a`).

**Bug #2 — `RPTB` does not loop (FIXED via a state modifier).** With SubBytes fixed, MixColumns
was still wrong until RPTB looping was supplied. Confirmed by PC trace: `9b00f(RPTB) → 9b011..9b020
→ 9b021 → … → 9b03a(BANZ) → 9b003` — the block runs **once** and falls through (the outer BANZ is
what loops; my earlier "RPTB loops fine" was a misread — `mixHits=4` was the outer column loop).
The constructor only does `RB = zext(RSIZE)`.

RPTB is a zero-overhead **block** repeat with an implicit loop-back (the CPU compares PC to the
block end after every instruction; there is no branch opcode there to hang loop-back p-code on),
so it cannot be modeled in pure SLEIGH — a constructor's p-code affects only its own instruction,
and the block end is arbitrary. Ghidra's answer to exactly this class of problem is an
`EmulateInstructionStateModifier` (the same mechanism Hexagon uses for its hardware loops):
`src/main/java/ghidra/program/emulation/TMS320C28xEmulateInstructionStateModifier.java` +
the `emulateInstructionStateModifierClass` pspec property. Its `postExecuteCallback` arms one
level of loop state when an RPTB executes (block `[inst_next, inst_next+RSIZE)`, count from the
loc16/imm operand) and redirects the PC back to the block start at the block end until the count
is exhausted — C28x RPTB cannot nest (single RB register), so one level is hardware-accurate.
Build/install with `tests/build_modifier.ps1` (restart Ghidra). **Validated:** plain stepping (no
harness) now hits the MixColumns block start 16× (4 cols × 4) and `postMIX` is bit-exact
`5f726415…`. (The `.sla` RPTB constructor is left as-is; the modifier supplies the loop for the
emulator. The earlier harness-level RPTB — re-step the block in the driver — remains a valid
fallback for emulation drivers that don't load the modifier.)

**Blocker #3 — the AES vector is NOT pure-isolation ("needs device data").** Even with round-1 math
bit-exact, execution derails identically: `AES → LCR 0xaae42 → … → FUN_000b2016: LCR *XAR7` where
`XAR7 = @global(word 0xb9c7a)` = 0 in isolation → calls 0 → decode-fault at PC 1. `FUN_000aae42` is
**not** an AES key schedule — it's runtime/heap machinery (pointer bookkeeping over a `0x013040`
struct, linked-list traversal, 6 calls to `b2b02/b32cb/b2034/b1a1b/b3621`) that dispatches through an
uninitialised global function pointer. So the plan's "AES needs no globals beyond the S-box" is wrong
for this firmware; the plan author's derail was this same dependency, not (only) the SubBytes bug.
To complete the full 10-round vector one must populate/stub that runtime state, or accept the round-1
bit-exact result as the `.sla` validation and check whether `compute-expected @0xa3678` is
self-contained before emulating it.

---

## Method

Two complementary passes. (A) catches wrong **decode**; (B) catches wrong **semantics**
even when decode is right. Run both; A first (cheaper, and a wrong mnemonic guarantees wrong
semantics).

### A. `dis2000` decode parity (ground-truth mnemonics/operands)

TI's `dis2000` (C2000 SDK) is authoritative for C28x decode. The repo already has
`tests/run_ti_parity.ps1` + `tests/run_disasm_test.ps1` — extend/lean on them.

1. Pick the emulation-relevant functions first: `AES128_encryptBlock_gen26 @0x9af9e`, its key
   schedule `FUN_000aae42`, and `DIR_immoChallengeRefresh_computeExpected @0xa3678` (in the
   `dir_26_65_2` image). Dump the raw bytes of each.
2. Run `dis2000` over those byte ranges → reference listing (word addresses).
3. Diff against Ghidra's disassembly (via MCP `disassemble_function`, or `dis2000`-vs-Ghidra
   in the parity harness). Flag every mnemonic/operand mismatch.
4. For each mismatch, fix the constructor's pattern/operands in the `.sinc`, referencing
   `docs/c28x/ch6_instruction_detail.txt` + SPRU430F.

### B. Differential emulation (ground-truth semantics)

1. Emulate `AES128_encryptBlock_gen26` on the FIPS-197 vector with the return-addr-fixed
   `.sla`. (Setup that works today: plaintext = 16 words one-byte-each @`0x13000`, key = 16
   words one-byte-each @`0x13020`, `XAR4=0x13000 XAR5=0x13020 SP=0x600 RPC=<sentinel>
   PC=0x9af9e`; step until `PC==sentinel`; read the 16 state bytes back.)
2. Single-step and compare the 16-byte state to a **reference AES** after each transform
   (AddRoundKey → SubBytes → ShiftRows → MixColumns …). Bisect to the **first diverging
   instruction**.
3. Read that instruction's constructor in the `.sinc`; compare its p-code to the SPRU430
   operation. Typical culprits here: the S-box `PREAD` / table-lookup addressing, `MOVB`
   byte-lane semantics, the GF-multiply / shift-xor used by MixColumns, or any `# decode-only`
   op in the round body.
4. Fix; re-emulate; repeat until AES → `69c4e0d8…`.
5. Then emulate `compute-expected @0xa3678` (preload the immo RAM block `0x13a42..0x13a55`)
   and confirm it reproduces a known (key, counter) → response.

### Suspect inventory (start here)

- Enumerate every constructor with an empty `{ }` body or a `# decode-only` comment; grep the
  `.sinc` set. Any that appears in the AES/`compute-expected` instruction stream is a prime
  suspect. Build the executed-instruction histogram from an emulation run (log each
  `getMnemonicString()`), intersect with the decode-only set.
- Audit the `MOVB *.LSB/.MSB` and byte-store forms in `tms320c28x_more.sinc` — byte-lane
  errors corrupt AES state without derailing.
- Re-check the `0x56`-prefix extended ALU forms in `tms320c28x_ext56.sinc` that are marked
  "decode-only / minimal p-code".

---

## Acceptance & regression

- **Acceptance:** AES FIPS-197 emulates to `69c4e0d8 6a7b0430 d8cdb780 70b4c55a`; then
  `compute-expected` emulates end-to-end.
- **Regression after every change:** `tests/run_disasm_test.ps1` and
  `tests/run_ti_parity.ps1` (addressing modes + TI RTS parity) — a semantic fix must not
  change decode.
- Spot-check decompilation of a few functions (e.g. `compute-expected`) so semantic edits
  don't regress the decompiler.

## Notes / gotchas

- `wordsize=2`: `Address.getOffset()` is a **byte** offset (word×2). Divide by 2 to compare to
  `dis2000` word addresses. This is exactly what bit the return address.
- Emulating in isolation, device **globals are zero** — a routine that reads a function
  pointer from an uninitialised global will call `0`. Distinguish "our op is wrong" (state
  diverges mid-computation) from "needs device data" (derails on an uninit pointer). AES needs
  no globals beyond the S-box (in flash), so any AES divergence is a spec bug, not missing data.
