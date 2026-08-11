# TMS320C28x SLEIGH module — design & decisions

The durable record of *why* the module is built the way it is. Read this before
changing the address-space model, register layout, or addressing sub-tables —
those decisions are load-bearing and easy to break.

## Scope

A Ghidra processor module for the TI **TMS320C28x** fixed-point DSP core
(targeting the **TMS320F28377D** — dual C28x + FPU + VCU). Scoped for practical
reverse engineering, not cycle-accurate emulation:

- **Decode-complete** core C28x + FPU + VCU instructions (everything disassembles).
- **Real p-code semantics** on the common subset: loads/stores in every
  addressing mode, MOV / ALU / compare / branch / call, MAC. This is what makes
  XREFs resolve and the decompiler produce readable output.
- **FPU / VCU decode-only** where full semantics add little (FP math, CRC) — they
  disassemble with correct mnemonics + register operands so the linear sweep
  doesn't dead-end, without modeling IEEE-754 / polynomial details.

## The five architectural facts that drive everything

1. **Word-addressable memory — the "byte" is 16 bits.** Smallest addressable
   unit is a 16-bit word. Modeled with `wordsize=2` on the unified `ram` space so
   one address == one word. **If this is wrong, every XREF to a peripheral
   register lands at half/double the right place.** Highest-priority invariant.
   Confirmed in SPRU430F §5.4–5.5 (offsets are counted in *words*).

2. **Variable-length instructions**, 16–64 bits, in 16-bit parcels. Fetched
   little-endian (low byte first). Base token `instr16`; longer instructions
   append more 16-bit words after a `;` in the pattern.

3. **One shared `loc16`/`loc32` addressing field.** A single 8-bit field encodes
   *all* memory/register addressing modes (SPRU430F Table 5-1), reused across
   the whole ISA. It MUST be one shared SLEIGH sub-table, parameterized by the
   `AMODE` context bit. Implementing it once is the key leverage point. See
   `tms320c28x_addr.sinc` and `docs/c28x/ch5_addressing_modes.txt`.

4. **Overlapping registers.** `ACC=AH:AL` (AH/AL further split into MSB/LSB
   bytes), `XT=T:TL` (T is the HIGH half), `P=PH:PL`, `XARn=ARnH:ARn` (ARn is
   the LOW half). Modeled with SLEIGH register sub-pieces, little-endian.

5. **Status flags / modes** live in ST0 (SXM OVM TC C Z N V PM OVC) and ST1
   (AMODE, PAGE0, VMAP, OBJMODE, …). Flags are implemented for the common
   ALU/branch subset; PM (product shift mode) and exotic corners are
   approximated.

### AMODE as decode context

`AMODE` (ST1 bit 8) selects the `loc16`/`loc32` decode (Table 5-1):
- **AMODE=0** — C28x modes. The C/C++ compiler default; what compiled firmware
  emits. **This is what's implemented.**
- **AMODE=1** — C2xLP-compatible modes. Secondary (gated by `ctx_AMODE` for
  later).

Tracked as the SLEIGH context variable `ctx_AMODE` (default 0 in the .pspec).

## Unified address space

The C28x has a **unified** program+data address map — the same address is
reached by either bus. The module uses **ONE `ram` space** (not separate
CODE/DATA):

```
define space ram type=ram_space size=4 wordsize=2 default;
```

This matches the hardware AND is required by the decompiler, which needs the
default space to be the cspec `<global>` space. Split CODE/DATA spaces make the
disassembler work but break the decompiler with "X may not be a global space".
See [SLEIGH-IDIOMS.md](SLEIGH-IDIOMS.md) §8.

## Register-space layout (offsets within the SLEIGH register space)

| Offset | Size | Registers |
|---|---|---|
| 0x00 | 4 | ACC |
| 0x00 | 2 | AL, AH |
| 0x00 | 1 | AL_LSB, AL_MSB, AH_LSB, AH_MSB |
| 0x08 | 4 | P (PL, PH) |
| 0x10 | 4 | XT (TL, T) |
| 0x20 | 4 | XAR0..XAR7 (ARn, ARnH) |
| 0x40 | 2 | DP, SP |
| 0x44 | 4 | PC, RPC (22-bit values in 32-bit slots) |
| 0x50 | 2 | ST0, ST1 |
| 0x58 | 2 | IFR, IER, DBGIER |
| 0x60 | 4 | R0H..R7H (FPU) |
| 0x90 | 4 | STF, RB (FPU) |
| 0xA0 | 4 | VR0..VR8 (VCU) |
| 0xC8 | 4 | VT0, VT1, VSTATUS, VCRC (VCU) |
| 0x80 | 4 | contextreg |

> SPRU430F Table 2-1 lists XAR0 as "16 bits" — a documentation typo. Fig 2-2 and
> all addressing-mode text treat all XAR0–7 as 32-bit; modeled as 32-bit.

## Stack-local addressing: `*-SP[n]` in SP's native width

Without the fix below, stack accesses render as
`*(int *)(ZEXT24(&stack0x0008) - 3)` instead of clean `local_X` variables.
(`ZEXT24` is Ghidra's notation for a 2→4-byte zero-extension, not "24 bits".)

**Cause.** `SP` is a 16-bit register (`offset=0x40 size=2`) but the `ram` space
is 4-byte-addressed (`size=4`), so a stack address must widen SP: the p-code is
`INT_ZEXT(SP)`. `ActionStackPtrFlow` runs (output anchors on `&stack0xNNNN`
symbols) but the decompiler never folds `INT_ZEXT(&stack[n] ± c)` back into a
single spacebase reference, so every stack access stays as visible pointer-math.
The narrow-SP / word-addressed case of
[NSA/ghidra #2749](https://github.com/NationalSecurityAgency/ghidra/discussions/2749).

**Full fix is two halves; either alone is inert.** This module ships **half 1**:

1. **SLEIGH (`tms320c28x_addr.sinc`) — build the address in SP's native width
   inside the zext.** The two `*-SP[loc_off6]` constructors are:
   ```
   local off:2 = SP - loc_off6:2;   export *[ram]:2 off;   # (loc32: export *[ram]:4 off)
   ```
   so the p-code is a single `ZEXT(SP - n)` — one spacebase expression the
   downstream fold rule can peel. Numerically identical for every in-frame
   access (`SP ≥ n`, no 16-bit borrow). **No `.slaspec` change** — `SP` stays
   16-bit (widening it to 4 bytes breaks decompiler registration).

2. **Decompiler (Ghidra core, `ruleaction.cc`) — `vnSpacebase` walk.** Teaches
   `RuleLoadVarnode` / `RuleStoreVarnode`'s spacebase resolver to see through a
   bounded chain (`INT_ADD` / `INT_ZEXT` / `INT_SUB` / `CAST` / `PTRSUB`) and
   peel one `ZEXT` of a narrow spacebase register, range-checked to the SP width
   so it can never synthesize an invalid address. Lives on the
   `dieseld23/ghidra` `fold-zext-spacebase` branch as a candidate upstream PR
   against #2749. Fixes the class for every narrow-SP, word-addressed processor,
   not just C28x. Half 1 alone is inert on a *stock* `decompile.exe` (still
   shows `ZEXT24`) but harmless and numerically identical.

**For p-code injection / call-fixup authors:** build stack addresses in the
stackpointer's native width *inside* the zext (`zext(SP − n)`), never
`zext(SP) − n` — the latter defeats spacebase folding on every narrow-SP target.

**Known non-solutions** (don't re-attempt; each has a specific failure mode):
- **Widen `SP` to 4 bytes.** Decompiler *"Could not register program: Marshaling
  error"*. Ghidra can't marshal a stackpointer wider than 16 bits in a
  `wordsize=2` space.
- **Dedicated 2-byte stack space + SP spacebase.** #2749 documents that the
  decompiler treats stack offsets as *invalid references*.
- **`segmentop` in the cspec.** Resolves x86 far *data* pointers, not the
  stack-frame `zext`; `type="protected"` also drags in x86-16 analyzers.
- Not the cause: the `wordsize>1` `default_symbols` bug
  ([#5633](https://github.com/NationalSecurityAgency/ghidra/issues/5633)) only
  bites *small* spaces; our `ram` is `size=4` and the `0x3FFFC0` vectors load
  fine.

## Source files

| File | Role |
|---|---|
| `data/languages/tms320c28x.slaspec` | spaces + register file + context; includes the .sinc files |
| `tms320c28x.sinc` | tokens + fixed-opcode/dispatch core; includes the family files |
| `tms320c28x_addr.sinc` | shared `loc16`/`loc32` addressing sub-tables |
| `tms320c28x_mov.sinc` | MOV / MOVL / MOVB / MOVW |
| `tms320c28x_flow.sinc` | branch / call / return + COND condition codes |
| `tms320c28x_alu.sinc` | ADD/SUB/AND/OR/XOR/CMP/INC/DEC/NEG/NOT/TBIT + flags |
| `tms320c28x_mac.sinc` | MAC / MPY family |
| `tms320c28x_ext56.sinc` | 0x56-prefix 2-word extended-ALU family (74 instrs) |
| `tms320c28x_more.sinc` | LC/LB, MOVZ, MOVL XARn,#22bit ptr-loads, immediate-stores, PUSH/POP, PREAD/PWRITE, … |
| `tms320c28x_fpu.sinc` | FPU (F2837x) — decode-only |
| `tms320c28x_vcu.sinc` | VCU-II / VCRC — decode-only (hardware CRC) |
| `tms320c28x.pspec` | F28377D device map: PC, interrupt vectors, volatile MMIO, default AMODE context |
| `tms320c28x_f2812.pspec` | F2812 (F281x) device map: F281x MMIO ranges + vectors |
| `tms320c28x.cspec` | 16-bit char / 32-bit ptr data model, SP, calling convention |
| `docs/c28x/*.txt` | extracted SPRU430F / spruhs1c reference chapters (gitignored — see [BUILDING.md](BUILDING.md)) |

### Device targets (one core, multiple device maps)

The `.sla` decodes the **superset** ISA (C28x core + FPU + VCU + TMU).
Individual devices expose subsets of it, so a device target is just a
**`.pspec` + setup-script** pair layered over the shared `.sla`/`.cspec` — no
ISA fork, no `.sla` rebuild:

| Target | Language id | pspec | setup script |
|---|---|---|---|
| F28377D (C28x+FPU+VCU) | `TMS320C28x:LE:32:default` | `tms320c28x.pspec` | `SetupF28377D.java` |
| F2812 (F281x fixed-point) | `TMS320C28x:LE:32:f2812` | `tms320c28x_f2812.pspec` | `SetupF2812.java` |

The F2812 has **no FPU/TMU/VCU/CLA** and a completely different peripheral set
(Event Managers, eCAN, older ADC, McBSP — not ePWM/eCAP/eQEP/D_CAN); those
opcodes/frames simply never appear in F2812 code, so the superset spec handles
it. Adding another C28x device is the same recipe: verify its map (datasheet +
TI header `.cmd`), drop in a `.pspec` variant and a `Setup*.java`. F2812 map
ground truth: `docs/c28x/f2812_memmap.md`.
