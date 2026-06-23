# SLEIGH idioms & gotchas (learned the hard way)

How to avoid the compile errors we hit building the loc16/loc32 sub-tables. Every
rule here is backed by a real error message from Ghidra 12.1.2's SLEIGH compiler.
**Read this before writing new constructors.**

## The fast feedback loop (do this, not eyeballing)

1. Edit `.sinc` / `.slaspec`.
2. Compile via `tests/run_disasm_test.ps1` (or just the compile block in
   `docs/BUILDING.md`). It copies to a Windows-local dir (UNC can't host the .bat),
   runs `sleigh.bat`, and reports errors.
3. A CLEAN build prints only `WARN  N NOP constructors found` and
   `WARN  N unnecessary extensions/truncations` — both benign. **Any `ERROR` line
   means no `.sla` was written.** Read the FIRST error; later ones often cascade.
4. For decode correctness, run the disasm regression test (below). Don't trust a
   constructor until you've seen Ghidra disassemble a known-encoding byte to the
   expected text.

The `sleigh.bat` pauses with "Press any key" on error. In the PowerShell tool, pipe
empty input so it never blocks:  `$null | & "$G\support\sleigh.bat" foo.slaspec`.

## Idiom 1 — a register cannot be a bare instruction operand

WRONG: `:MOVL ACC, loc32 is op_hi8=0x06 & loc32 { ACC = loc32; }`
→ `Error: operand ACC is undefined`. SLEIGH parses `ACC` (operand position) as an
operand symbol, and a bare register isn't a valid operand symbol.

RIGHT: define a zero-width display subtable (the 8051 `Areg` idiom) and match it
with `epsilon` (no pattern bits):
```
ACCreg: "ACC" is epsilon { export ACC; }
:MOVL ACCreg, loc32  is op_hi8=0x06 & ACCreg & loc32  { ACC = loc32; }
```
The subtable prints the name and exports the varnode. (Putting the register only in
the semantic body, not the display, also works but loses it from the listing.)

## Idiom 2 — select a register from a field with `attach variables`

To map an N-bit field to a register, DON'T write one subtable constructor per
register (that yields `operand XARn is undefined` / `exports size 0`). Use:
```
attach variables [ loc_areg ] [ XAR0 XAR1 XAR2 XAR3 XAR4 XAR5 XAR6 XAR7 ];
```
Then reference `loc_areg` directly as the register (read, write, export, print).
To attach the SAME bits to a second register list (e.g. 16-bit AR view), define a
SECOND token field over the same bit range and attach that:
```
loc_areg   = (0,2)   # -> XAR0..XAR7
loc_areg16 = (0,2)   # -> AR0..AR7   (one field can attach to only one list)
attach variables [ loc_areg16 ] [ AR0 AR1 AR2 AR3 AR4 AR5 AR6 AR7 ];
```

## Idiom 3 — a table must export ONE consistent size

WRONG: a `loc16` table where some constructors `export *[DATA]:2 a` (size 2) and
others `export XARn` (size 4) → `Table 'loc16' has inconsistent export size`.

RIGHT: every constructor in a given table exports the same byte size. So:
- `loc16` → all exports size 2 (memory `*[DATA]:2`, or 16-bit registers AH/AL/ARn…).
- `loc32` → all exports size 4 (memory `*[DATA]:4`, or 32-bit registers XARn/ACC/P/XT).
The register-direct `@ARn` row in loc16 must export the 16-bit `AR`, NOT `XAR`.

## Idiom 4 — token sub-fields share the instruction word; don't make a 2nd token

A `define token` consumes its own bytes. The loc field is the LOW byte of the same
16-bit instruction word, so its sub-fields (`loc_b76`, `loc_mode5`, `loc_areg`,
`loc_off6`, `loc_imm3`, `loc_full8`) are declared INSIDE the one `instr16` token —
not as a separate `define token`, which would consume an extra 2 bytes.

## Idiom 5 — use token fields directly; no `[ name = field; ]` aliasing needed

WRONG: `loc16: "@"^off6 is ... & loc_off6 [ off6 = loc_off6; ] { ... off6 ... }`
→ `Constraining currently undefined operand: off6` / `operand off6 has an issue`.
The `[ x = expr; ]` block is for *computed* disassembly values, not for renaming a
field. Just reference the field directly:
```
loc16: "@"loc_off6  is ctx_AMODE=0 & loc_b76=0b00 & loc_off6 {
    local a:4 = (zext(DP) << 6) | zext(loc_off6:4);
    export *[DATA]:2 a;
}
```
Display concatenation is juxtaposition or `^`; `"@"loc_off6` prints `@<val>`.

## Idiom 6 — size your arithmetic explicitly

`zext(field:N)` to widen a field to N bytes before arithmetic; keep address temps
at `:4` (32-bit data address). Mismatched sizes trigger the "unnecessary
extensions/truncations were converted to copies" warning (benign) or real errors.

## Idiom 7b — zext/sext of a token field or load needs an explicit size

`zext(imm16)` / `sext(T)` used directly in an expression often fails with
`Could not resolve at least 1 variable size`. Fixes:
- Give the token field an explicit size: `zext(imm16:2)`, `sext(loc16)` is fine when
  the field width is known, but when ambiguous assign to a sized temp first.
- Don't nest a widen around a load: `sext(*[DATA]:2 p)` fails — split it:
  `local v:2 = *[DATA]:2 p; local w:4 = sext(v);`
- Multiplies into a wider result: widen both operands to the result size in sized
  temps, then multiply: `local a:4=sext(T); local b:4=sext(loc16); P = a*b;`

## Idiom 7c — the decompiler needs ONE unified default `ram` space

Splitting memory into separate `CODE` and `DATA` ram_spaces makes the DISASSEMBLER
work but BREAKS the DECOMPILER: `decompile_function` fails with
`"CODE may not be a global space in the spec file"`. The decompiler requires the
`default` space to also be the cspec `<global>` space.

The C28x is genuinely a **unified** address map (program + data share one address
space; e.g. 0x048000 = CANA whether reached by the program or data bus), so the
correct model is ONE space:
```
define space ram type=ram_space size=4 wordsize=2 default;   # NOT CODE + DATA
```
and in the cspec `<global><range space="ram"/></global>` + `<stackpointer ... space="ram">`,
and in the pspec `<context_set space="ram">` and `address="ram:..."`. All `*[DATA]`/
`*[CODE]` dereferences in the .sinc become `*[ram]`. Changing the space layout
changes the language → existing analyzed programs must be RE-IMPORTED (close without
saving; restart Ghidra to reload the spec).

## Idiom 7 — context-gate variant decodes

AMODE selects the loc-field meaning. Gate every loc constructor with
`ctx_AMODE=0` so AMODE=1 rows can be added later without pattern conflicts. The
context var is defined in the .slaspec and defaulted in the .pspec.

## Regression test

`tests/run_disasm_test.ps1` assembles known-encoding bytes (`tests/addr_modes.bin`),
disassembles them headless, and diffs against `tests/addr_modes.expected.txt`
(14 cases covering every addressing mode + multi-word + fixed opcodes). Extend it
with new cases as you add instructions — a constructor isn't "done" until it's in
the expected table and passing.
