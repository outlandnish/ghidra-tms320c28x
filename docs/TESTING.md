# Testing the disassembler

Decode correctness is verified with a headless Ghidra regression test, not by
eyeballing. **A constructor isn't done until a known-encoding byte disassembles to
the expected text.**

## Run it

```powershell
pwsh -File tests\run_disasm_test.ps1
```
It (1) recompiles the `.sla`, (2) reinstalls into Ghidra, (3) headless-disassembles
`tests/addr_modes.bin`, (4) diffs against `tests/addr_modes.expected.txt`, printing
`PASS: all N cases` or per-line `FAIL`.

## Files

- `tests/addr_modes.bin` — hand-assembled bytes, one instruction per test.
- `tests/addr_modes.expected.txt` — `wordaddr <tab> bytes <tab> expected text`.
- `ghidra_scripts/DumpDisasm.java` — headless post-script: disassembles linearly
  and prints `addr <tab> bytes <tab> mnemonic+operands`.

## Adding cases

1. Work out the instruction word(s). The loc field is the LOW byte; the opcode
   group is the HIGH byte. Bytes are little-endian, so a word `0xHHLL` is `LL HH`.
2. Append the bytes to `addr_modes.bin` (regenerate via the Python snippet in
   git history / DESIGN notes) and a row to `addr_modes.expected.txt`.
3. Re-run. Comparison is on the mnemonic text, tolerant of `0x` formatting.

## Verified baseline (2026-06-22): all 14 cases pass

Covers every AMODE=0 loc16/loc32 addressing mode (direct `@6`, stack `*-SP`/`*SP++`/
`*--SP`, indirect `*XARn++`/`*--XARn`/`*+XARn[AR0|AR1]`/`*+XARn[imm3]`, register-direct
`@XARn`), a multi-word instruction (`MOV @4,#0x1234`), and fixed opcodes
(`ABORTI`, `IDLE`).

## TI ground-truth parity (the strongest correctness check)

The most powerful validation is to disassemble **real TI-compiled C28x code** and diff
mnemonics against TI's own disassembler. Take an object out of a TI C2000 runtime lib,
run TI's `dis2000` on it for ground truth, extract its COFF2 `.text` to a raw bin
(`.text` size is in **words**), import that bin (`TMS320C28x:LE:32:default`, base 0),
disassemble linearly, and diff `<wordaddr> <mnemonic>` against the dis2000 lines.
Bar: **0 wrong decodes** (a wrong decode is a spec bug); minimize UNDEFs (missing
opcodes). The harness is `tests/run_ti_parity.ps1` + `ghidra_scripts/DumpParity.java`.

Current status: **100% mnemonic agreement, 0 wrong, 0 gaps** across five objects
(3,638 instructions) from `rts2800_fpu32.lib` — three FPU-heavy (`k_expf`, `catrigf`,
`c99_complex`) plus two integer (`memcpy_s`, `strcpy_s`); the `.text` bins are checked
in as `tests/ti_*_text.bin`. Use a mix of FPU and integer objects — they exercise
disjoint paths.

## What parity does NOT prove — and the bug classes that hide behind it

Mnemonic parity compares only the **first token**, so a constructor with the right
mnemonic but wrong operands/target/semantics passes silently. Real bugs found this way
(each needed eyeballing operands or the decompiler, then cross-checking SPRU430F):

- **Relative-vs-absolute targets** — a call/branch that should be absolute computed a
  PC-relative one (e.g. it pointed at itself). Check every branch/call target value.
- **Partial sub-register writes** — an instruction defined to zero/sign-extend into a
  wider register that writes only the narrow half leaves the sibling half stale; the
  decompiler then shows `CONCAT22(stale_hi, lo)` everywhere. Write the full register.
- **Wrong token-field bit range** — an operand field whose `(lo,hi)` overlaps the wrong
  bits. The mode name still renders, only the *value* is wrong (e.g. an index that
  always equals the register number). Prefer regression vectors where the two differ
  (index≠register) so `0==0` can't mask it.
- **Wrong multi-word length** — a 2-word instruction decoded as 1 word desyncs the
  entire downstream linear sweep; a greedy 1-word pattern can swallow a sibling opcode.

When adding constructors, spot-check the rendered operands (not just the mnemonic) and
run the decompiler on a small function — ugly `CONCAT`/`ZEXT` noise often points at one
of these.
