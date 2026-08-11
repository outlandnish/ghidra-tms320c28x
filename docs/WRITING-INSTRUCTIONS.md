# How to add instruction constructors

Each instruction is transcribed from SPRU430F (core) or spruhs1c (FPU/VCU) into a
SLEIGH constructor in the relevant `data/languages/*.sinc` file.

## Per-instruction recipe

1. **Find the encoding.** Grep the extracted reference:
   ```bash
   grep -A3 '^MOVL ' docs/c28x/ch6_instruction_detail.txt
   ```
   Each instruction page has a `Syntax Options` / `Opcode` block giving the bit
   pattern, e.g. `IDLE → 0111 0110 0010 0001`. Letters in the pattern are operand
   fields (`LLLL LLLL` = loc16, `nnn` = XARn selector).

2. **Pick the right token field.** Instructions are 16-bit parcels, little-endian.
   Use `instr16` fields already defined; add new sub-fields as needed. Multi-word
   instructions append `instr16` again (define `instr16b`, etc. for trailing words).

3. **Write the constructor.** `:MNEMONIC operands is <pattern> { semantics }`.
   - Fixed opcodes: `:IDLE is op16=0x7621 { ... }`.
   - With the shared addressing field:
     `:MOV reg, loc16 is op_hi8=0x.. & loc16 { ... }` — `loc16` is the shared
     sub-table (see below).

4. **Semantics (p-code).** For the RE-critical subset, write real semantics so the
   decompiler works and XREFs resolve: loads/stores (`reg = *:2 addr;` — size 2 =
   one 16-bit word), ALU with proper N/Z/C/V flags per the "Flags and Modes"
   table, branches/calls with resolved targets. For decode-only families (FPU
   math, VCU CRC), an empty `{ }` body is fine — but comment it clearly and note
   in the constructor that it's decode-only.

5. **Compile, test, verify.** Rebuild the `.sla` (see [BUILDING.md](BUILDING.md)),
   run [TESTING.md](TESTING.md)'s harness, add a regression case for the new
   encoding. For fidelity against real code, load a firmware image at the right
   base and disassemble a known region (e.g. the reset vector chain);
   mis-decodes usually mean a wrong bit field or a missing AMODE gate. See
   `tests/run_fw_parity.{ps1,sh}` for automated `dis2000` parity over a word range.

## The shared loc16/loc32 sub-table (the key abstraction)

Table 5-1 (`docs/c28x/ch5_addressing_modes.txt`) defines one 8-bit field used by
nearly every memory instruction. Implement it ONCE as a SLEIGH sub-table that
computes an address (and any pre/post inc/dec side effects), then reuse it:

```
loc16: ... is ... { ... export <address>; }   # one constructor per row of Table 5-1
```

- Direct `@6bit`: addr = (DP << 6) | 6bit  (word address in lower 4M).
- Stack `*-SP[6bit]`: addr = SP - 6bit.
- Indirect `*XARn++` / `*--XARn` / `*+XARn[AR0]` / `*+XARn[3bit]`: addr = XARn,
  with post-inc / pre-dec / indexed variants; apply the side effect in the body.
- Register modes `@ACC/@AH/@AL/@XARn/...`: export the register directly.

`loc32` is the same field but the access is 32-bit (size 4) and 32-bit register
modes apply. Often a parallel sub-table or a size-parameterized one.

AMODE=1 changes some rows — gate AMODE-1-only rows with the `ctx_AMODE` context
variable (or build a second sub-table). AMODE=0 is the compiler default and gets
implemented first.

## Priority order

If you're bootstrapping a new instruction family, implement in this order so the
firmware becomes navigable fastest:

1. `loc16`/`loc32` sub-table (unblocks everything below).
2. `MOV`, `MOVL`, `MOVW`, `MOVB` — loads/stores reveal peripheral register access.
3. Branches/calls/returns: `B`, `SB`, `BF`, `LC`/`LCR`, `LRET`/`LRETR`, `BANZ`.
4. ALU/compare: `ADD`, `ADDL`, `SUB`, `SUBL`, `AND`, `OR`, `XOR`, `CMP`, `TBIT`.
5. `MAC`/`MPY` family.
6. Flag/mode ops: `SETC`, `CLRC`, `SPM`.
7. FPU / VCU — decode-only.
