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
