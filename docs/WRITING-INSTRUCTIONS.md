# How to add instruction constructors

The repetitive core work. Each instruction is transcribed from SPRU430F into a
SLEIGH constructor in `data/languages/tms320c28x.sinc`.

## Per-instruction recipe

1. **Find the encoding.** Grep the extracted reference:
   ```bash
   grep -A3 '^MOVL ' docs/c28x/ch6_instruction_detail.txt
   ```
   Each instruction page has a `Syntax Options` / `Opcode` block giving the bit
   pattern, e.g. `IDLE → 0111 0110 0010 0001`. Letters in the pattern are operand
   fields (e.g. `LLLL LLLL` = the loc16 field, `nnn` = an XARn selector).

2. **Pick the right token field.** Instructions are 16-bit parcels, little-endian.
   Use `instr16` fields already defined; add new sub-fields as needed. Multi-word
   instructions append `instr16` again (define `instr16b`, etc. for trailing words).

3. **Write the constructor.** Decode part is `:MNEMONIC operands is <pattern> { semantics }`.
   - Fixed opcodes: `:IDLE is op16=0x7621 { ... }`.
   - With the shared addressing field: `:MOV reg, loc16 is op_hi8=0x.. & loc16 { ... }`
     where `loc16` is the shared sub-table (see below).

4. **Semantics (p-code).** For the RE-critical subset, write real semantics so the
   decompiler works and XREFs resolve:
   - Loads/stores: `reg = *:2 addr;` / `*:2 addr = reg;` (size 2 = one 16-bit word).
   - ALU: set Z/N/C/V flags per the instruction's "Flags and Modes" table.
   - Branches/calls: use `goto`/`call`/`return` with the resolved target.
   For FPU and other out-of-scope instructions, an empty `{ }` body is fine
   (decode-only). Keep these clearly commented as decode-only.

5. **Compile** (see BUILDING.md) and fix errors before moving on. Compile often —
   one broken constructor fails the whole .sla.

## The shared loc16/loc32 sub-table (the key abstraction)

Table 5-1 (`docs/c28x/ch5_addressing_modes.txt`) defines one 8-bit field used by
nearly every memory instruction. Implement it ONCE as a SLEIGH sub-table that
computes an address (and any pre/post inc/dec side effects), then reuse it.

Sketch (AMODE=0):
```
loc16: ... is ... { ... export <address>; }   # many constructors, one per row of Table 5-1
```
- Direct `@6bit`: addr = (DP << 6) | 6bit  (word address in lower 4M).
- Stack `*-SP[6bit]`: addr = SP - 6bit.
- Indirect `*XARn++` / `*--XARn` / `*+XARn[AR0]` / `*+XARn[3bit]`: addr = XARn,
  with post-inc / pre-dec / indexed variants; apply the side effect in the body.
- Register modes `@ACC/@AH/@AL/@XARn/...`: export the register directly.

`loc32` is the same field but the access is 32-bit (size 4) and 32-bit register
modes apply. Often a parallel sub-table or a size-parameterized one.

Because AMODE=1 changes some rows, gate AMODE-1-only rows with the `ctx_AMODE`
context (or build a second sub-table). AMODE=0 first — it's the compiler default.

## Priority order (for CAN RE)

Implement in this order so the firmware becomes navigable fastest:
1. `loc16`/`loc32` sub-table (unblocks everything below).
2. `MOV`, `MOVL`, `MOVW`, `MOVB` (loads/stores — these reveal CAN register access).
3. Branches/calls/returns: `B`, `SB`, `BF`, `LC`/`LCR`, `LRET`/`LRETR`, `BANZ`.
4. ALU/compare: `ADD`, `ADDL`, `SUB`, `SUBL`, `AND`, `OR`, `XOR`, `CMP`, `TBIT`.
5. `MAC`/`MPY` family.
6. Flag/mode ops: `SETC`, `CLRC`, `SPM`.
7. FPU instructions — decode-only.

## Verifying against real firmware

We have an F28377D image. Once a batch of constructors is in, load the image in
Ghidra at the right base, disassemble a known region (e.g. the reset vector chain),
and confirm the mnemonics/operands match expectations. Mis-decodes usually mean a
wrong bit field or a missing AMODE gate.
```
