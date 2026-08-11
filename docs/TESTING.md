# Testing the disassembler

Decode correctness is verified by a headless Ghidra regression test, not by
eyeballing. **A constructor isn't done until a known-encoding byte disassembles
to the expected text.**

## Run it

```sh
# Linux / macOS
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/run_disasm_test.sh
```
```powershell
# Windows
pwsh -File tests\run_disasm_test.ps1
```

It (1) recompiles the `.sla`, (2) reinstalls into Ghidra, (3) headless-disassembles
`tests/addr_modes.bin`, (4) diffs against `tests/addr_modes.expected.txt`,
printing `PASS: all N cases` or per-line `FAIL`.

## Files

- `tests/addr_modes.bin` — hand-assembled bytes, one instruction per test.
- `tests/addr_modes.expected.txt` — `wordaddr <tab> bytes <tab> expected text`.
- `ghidra_scripts/DumpDisasm.java` — headless post-script; dumps
  `addr <tab> bytes <tab> mnemonic+operands`.

## Adding cases

1. Work out the instruction word(s). The loc field is the LOW byte; the opcode
   group is the HIGH byte. Bytes are little-endian, so a word `0xHHLL` is `LL HH`.
2. Append the bytes to `addr_modes.bin` and a row to `addr_modes.expected.txt`.
3. Re-run. Comparison is on the mnemonic text, tolerant of `0x` formatting.

The 14-case baseline covers every AMODE=0 loc16/loc32 addressing mode (direct
`@6`, stack `*-SP` / `*SP++` / `*--SP`, indirect
`*XARn++` / `*--XARn` / `*+XARn[AR0|AR1]` / `*+XARn[imm3]`, register-direct
`@XARn`), a multi-word instruction (`MOV @4,#0x1234`), and fixed opcodes
(`ABORTI`, `IDLE`).

## TI ground-truth parity

Disassemble **real TI-compiled C28x code** and diff mnemonics against TI's own
disassembler `dis2000`. **Bar: 0 wrong decodes** (a wrong decode is a spec bug);
minimize UNDEFs (missing opcodes).

`tests/run_fw_parity.{ps1,sh}` slices a word range out of a firmware image,
round-trips through `asm2000` + `dis2000` for the ground truth,
headless-disassembles with our `.sla`, and reports agree / wrong / undef /
length-skew. Requires `$GHIDRA_INSTALL_DIR` and `$C2000WARE`.

Runtime-library parity (extract `.text` sections from `rts2800_fpu32.lib`,
compare against `dis2000`) has no in-tree driver — the toolchain-and-lib
dependencies aren't redistributable. Build it around
`ghidra_scripts/DumpParity.java` if you need to re-run.

## What parity does NOT prove

Mnemonic parity compares only the **first token**, so a constructor with the
right mnemonic but wrong operands or semantics passes silently. Bug classes to
spot-check for after any spec change:

- **Relative-vs-absolute branch targets.** Check every branch/call target value.
- **Partial sub-register writes.** An op defined to zero/sign-extend into a
  wider register that writes only the narrow half leaves the sibling half
  stale; the decompiler then shows `CONCAT22(stale_hi, lo)` everywhere. Write
  the full register.
- **Wrong token-field bit range.** The mode name still renders, only the
  *value* is wrong (e.g. an index that always equals the register number).
  Prefer regression vectors where the two differ so `0==0` can't mask it.
- **Wrong multi-word length.** A 2-word instruction decoded as 1 word desyncs
  the entire downstream sweep; `run_fw_parity.{ps1,sh}` reports these as
  "length skew".

When adding constructors, spot-check the rendered operands (not just the
mnemonic) and run the decompiler on a small function — ugly `CONCAT` / `ZEXT`
noise usually points at one of these.

## Semantics: `tests/run_emu_test.{sh,ps1}`

The disassembly test proves the *listing*; this proves the *p-code*. It emulates the FPU
status-flag instructions (`SETFLG`, `SAVE`, `RESTORE`) and reads the STF sub-registers
back, asserting both the flags a mask names and that the ones it does not name keep their
previous values, plus the SAVE/RESTORE round trip through the shadow register set.

This is the only test that can catch a wrong bit order *inside* a mask. `SETFLG`'s 11-bit
FLAG field is split across both instruction words with the halves in the opposite order
from the `#16FHi` immediates; swapping them silently moves `RND32` onto `NI` while the
disassembly still reads as something entirely plausible. It caught exactly that during
development.

Run `run_disasm_test` first -- it is what compiles and installs the language.

A second suite, `EmuFpuCondTest`, covers the `TMU_COND_OPERAND` / `FPU_MINMAX_FLUSH`
conditioning intrinsics. Those are pcodeops, so their behaviour lives in the compiled
`TMS320C28xEmulateInstructionStateModifier` and nothing else -- not the decompiler, not
the decode tests -- can see it. Run `tests/build_modifier.*` first; the pspec names the
modifier class, so without the jar the emulator refuses to start (verified: it dies with
`ClassNotFoundException` rather than passing vacuously). A *misspelled pcodeop name* is
the quieter failure -- `tryRegister` swallows it and the op stays opaque -- which is why
every assertion checks a conditioned value rather than merely that stepping succeeded.

It also covers `FPU_UNDERFLOW` / `FPU_OVERFLOW`, the LUF/LVF latching intrinsics. The two
negative cases there are the whole point of the design: `0.0 / 5.0` produces a zero that
is *not* an underflow and `Inf / 2.0` an infinity that is *not* an overflow, so neither
verdict is reachable from the rounded result -- they only pass if the intrinsic is reading
the operands.
