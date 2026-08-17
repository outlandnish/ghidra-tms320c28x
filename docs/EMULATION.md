# Emulating TMS320C28x code in Ghidra

Most of the interesting semantics live in the SLEIGH spec and are visible to
both the decompiler and the emulator. A slim `EmulateInstructionStateModifier`
(`ghidra.program.emulation.TMS320C28xEmulateInstructionStateModifier`, wired via
the `emulateInstructionStateModifierClass` property in `tms320c28x.pspec`)
handles the few compute pcodeops that would be prohibitively verbose in SLEIGH:

| Feature | Where | Notes |
| --- | --- | --- |
| **RPT** | SLEIGH for the decompiler (`tms320c28x_rpt.sinc` + `tms320c28x_more.sinc`), Java for emulation | Zero-overhead single-instruction repeat. The `:^instruction` prefix wrapper matches when `rpt_active=1` (set by the RPT body via `globalset(inst_next, …)`) and re-executes the wrapped instruction while `RPTC > 0` — this is what makes the repeat visible in the **decompiler**. Under **emulation** the wrapper cannot fire (see [Why RPT still needs the modifier](#why-rpt-still-needs-the-modifier)), so `postExecuteCallback` re-issues the instruction instead. `RPT #15 ‖ SUBCU` (16-bit unsigned divide) and `RPT ‖ VCRCxx` (block CRC) emulate via the Java path. |
| **RPTB** | Pure SLEIGH (`tms320c28x_rpt.sinc` + `tms320c28x_fpu.sinc`) | Zero-overhead block repeat. The `rptb_end` sub-table computes the block-end address and `globalset`s `rptb_flag` there; the wrapper fires on the block-end instruction and jumps to `RB_RSTART` while `RB_RC > 0`. |
| **CSB ACC** | Pure SLEIGH (`tms320c28x_ext56.sinc`) | Leading sign bits − 1 → `T`. Built on SLEIGH's `lzcount`: `lzcount(ACC)` for non-negative, `lzcount(~ACC)` for negative. |
| **VCRC8L / VCRC16P1L / VCRC32L** | Java pcodeop | VCU-II CRC accumulate (polys `0x07` / `0x8005` / `0x04C11DB7`, MSB-first, low byte). Kept as an intrinsic so the decompiler renders `VCRC = VCRC8L(VCRC, src)` — the direct signal for CAN CRC compute/check code. |
| **FPU non-IEEE conditioning + LU/LV flags** | Java pcodeops (`TMU_COND_OPERAND`, `FPU_MINMAX_FLUSH`, `FPU_UNDERFLOW`, `FPU_OVERFLOW`) | Denormal/NaN canonicalisation per SPRUHS1C §7.3, §7.5.2, and the exact-in-double underflow/overflow verdicts. |

`FLIP`, `SUBCU`, and the CRC/CSB *flag* effects are all plain SLEIGH — the Java
modifier covers the VCRC compute, the FPU non-IEEE semantics, and the RPT
loop re-issue under emulation.

## How the RPT / RPTB wrappers work

The C28x's zero-overhead repeats have an implicit loop-back that a single
instruction's p-code cannot express. The `:^instruction` prefix wrapper
(`data/languages/tms320c28x_rpt.sinc`) handles this by re-executing the wrapped
instruction under decoded p-code control. Two subtleties in the design deserve
calling out — they're easy to miss and each one silently no-ops the wrapper:

1.  **Phase-bit partition.** `:^instruction is X & instruction { ... }` compiles
    to a variant of every base constructor whose pattern is `(X AND base_pattern)`.
    If a base constructor imposes NO context constraint that contradicts X, the
    variant and the base overlap — both match at addresses where X holds.
    `sleigh -l` reports this as "Constructor patterns cannot be distinguished",
    and at runtime (on Ghidra 12.x) the plain base wins, silently making the
    wrapper a no-op.

    Every shipped Ghidra processor that uses `:^instruction` (avr8, 8051, ARM,
    Hexagon) fixes this by giving base constructors a positive-phase constraint
    that the wrapper's pattern negates. We do the same: every top-level
    `:MNEMONIC` constructor requires `& rpt_phase=1`, the pspec seeds
    `rpt_phase=1` as the ram-space default, and the RPT / RPTB bodies
    `globalset` `rpt_phase=0` on the wrapped address alongside `rpt_active` /
    `rptb_flag`. The wrapper's pattern is `rpt_phase=0 & <rpt_active | rptb_flag>`,
    so it matches uniquely at wrapped addresses; its local `[ rpt_phase=1; ]`
    action flips the phase back for the inner `build instruction`, allowing the
    base to match on re-parse.

    If you add a new `:MNEMONIC` constructor without `& rpt_phase=1` it will
    silently NOT be wrappable by RPT/RPTB, and `RPT || <new instruction>` will
    execute only once during emulation. The `run_disasm_test` fixtures do not
    catch this on their own — add a new emulation case in `EmuRptTest.java` if
    your instruction is likely to appear inside an RPT.

2.  **`RB_RSTART` unit conversion.** The RPTB body stores
    `RB_RSTART = inst_next >> 1`, NOT `RB_RSTART = inst_next`. `inst_next`
    assigned to a register keeps Ghidra's byte-offset form (word × 2 on this
    wordsize=2 space), but the wrapper's `goto [RB_RSTART]` treats the register
    value as a raw PC (word units). Without the shift, the loop-back branches
    to twice the intended address.

The wrappers are mutually exclusive on the counterpart flag
(`rpt_active=1 & rptb_flag=0` vs `rptb_flag=1 & rpt_active=0`) — sleigh's
ambiguity checker requires that even though the C28x hardware can't arm both
at the same address.

The `EmuRptTest.java` regression test (`tests/run_emu_test.{sh,ps1}`) exercises
both wrappers: `RPT #15 || SUBCU` (100/7 divide → ACC=0x0002000e in 17 steps)
and `RPTB #0, #4 || ADD ACC,#1` (5 iterations → ACC=5 in 6 steps).

### Why RPT still needs the modifier

The wrappers are armed by `globalset`, and **Ghidra's emulator applies a
`globalset` context commit one instruction too late**: the value written for the
target address only becomes visible *after* that instruction has already been
decoded and executed.

* **RPTB is fine.** Its `globalset` targets the block-end address, several
  instructions ahead, so the commit has landed by the time the block-end
  instruction is decoded. RPTB emulates from SLEIGH alone.
* **RPT is not.** It targets `inst_next` — the very next instruction — so the
  commit is always late. The plain base constructor wins the pattern match and
  the wrapper's p-code never runs. Dumping `contextreg` per emulated step for
  `RPT #15 ‖ SUBCU` at `0xc010` shows it directly:

  ```
  PC=0xc011  RPTC=15  ctx=0x04000000   rpt_phase=1, rpt_active=0  -> base matches
  PC=0xc012  RPTC=15  ctx=0x10000000   rpt_active=1, rpt_phase=0  -> wrapper, one word late
  ```

  `RPTC` is never decremented. (Context fields are numbered from the MSB, so
  field `(n,n)` is bit `31-n`: `rpt_active` `(3,3)` → `0x10000000`, `rpt_phase`
  `(5,5)` → `0x04000000`.) This holds whether the bytes are written straight
  into emulator memory or properly disassembled into the program first.

So `postExecuteCallback` retains the RPT arm / re-issue logic, and only that.
The two mechanisms do not fight: under emulation the wrapper never fires at
`inst_next`, so the callback is the sole driver; under disassembly the callback
does not run at all, so the wrapper is the sole model. **Disassembly is
unaffected either way** — firmware decode parity against TI `dis2000` over a
byte-swapped F28377D production image (`0x82000+0x8000`) is identical to `main`
(23162 agree, 2 wrong, 1068 undef, 1 skew).

## Build & install

The emulator loads the compiled Java at startup, so after any change to the
modifier or the `.sla` you must reinstall and **restart Ghidra**. Ghidra must be
closed during install — it locks `TMS320C28x.jar` while running.

```sh
# Linux / macOS
GHIDRA_INSTALL_DIR=/path/to/ghidra tests/build_modifier.sh
```
```powershell
# Windows
pwsh -File tests\build_modifier.ps1 -Ghidra <ghidra-install-dir>
```

If you also changed the SLEIGH, recompile + reinstall the `.sla` too
(`tests/run_disasm_test.{sh,ps1}`). To confirm the modifier loaded, emulate a
`VCRC8L ACC` sequence and check that `VCRC` comes back computed rather than
unchanged; a `RPT #15 ‖ SUBCU` divide that returns `ACC=0x0002000e` works too.
`CSB ACC` and `RPTB` no longer need the modifier — they run from pure SLEIGH
p-code — so a working `CSB` result only proves the `.sla` is loaded, not the jar.

> **Rebuild the jar when you switch branches.** `run_disasm_test` installs only
> `data/languages/*` and `build_modifier` compiles only the modifier, so the
> extension jar under
> `<ghidra-user-dir>/Extensions/ghidra-tms320c28x/lib/` can silently be left over
> from a *different* worktree. A stale jar carrying an older `postExecuteCallback`
> will make RPT emulation appear to work regardless of what the SLEIGH does.
> Check with
> `javap -cp <jar> ghidra.program.emulation.TMS320C28xEmulateInstructionStateModifier`.

## Address convention (the one thing that trips everyone up)

The `ram` space is **wordsize = 2**. Two different units:

- **Display / PC / `AddressSpace.getAddress` argument order** you read in the
  listing are **word** addresses. **The `PC` register holds a word address.**
- **`Address.getOffset()` returns a BYTE offset = word × 2.** So `getAddress(W)`
  builds the address whose *byte* offset is `W`, i.e. **word `W/2`**. To target
  word `W`, call `getAddress(W * 2)`.

Consequences when scripting the emulator:

```
word W  ->  Address = sp.getAddress(W * 2)      // for reads/writes/placing code
word W  ->  PC       = W                         // writeRegister("PC", W)
```

Placing a two-instruction snippet at words `W` and `W+1` means byte offsets `W*2`
and `W*2+2` (`writeMemoryValue(addr, 2, ...)` writes 2 bytes). Getting this wrong
shows up as `Instruction decode failed (invalid memory)` — PC and your writes
landed in different places.

## Minimal recipe

`EmulatorHelper` writes to the emulator's own memory state, **not** the program
database, so placing scratch code and setting registers never dirties your
analysis.

```java
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

var p  = currentProgram;
var sp = p.getAddressFactory().getDefaultAddressSpace();
var mon = TaskMonitor.DUMMY;
java.util.function.LongFunction<Address> at = (w) -> sp.getAddress(w * 2);  // word -> Address

EmulatorHelper emu = new EmulatorHelper(p);
try {
    // place code at word 0xc000 (GS0_15_RAM). CSB ACC = 0x5635.
    emu.writeMemoryValue(at.apply(0xc000L), 2, 0x5635L);

    emu.writeRegister("ACC", 0x00000010L);   // input
    emu.writeRegister("PC",  0xc000L);        // PC is a WORD address
    emu.step(mon);                            // one instruction (invokes the state modifier)

    println("T = 0x" + emu.readRegister("T").toString(16));   // -> 0x1a (26)
    println("PC= 0x" + emu.readRegister("PC").toString(16));  // -> 0xc001 (advanced by 1 word)
} finally {
    emu.dispose();
}
```

Notes:
- `emu.step(mon)` returns `false` on error; `emu.getLastError()` has the reason.
- Use a RAM block (`M0M1_RAM 0x0`, `LS0_5_RAM 0x8000`, `D0D1_RAM 0xb000`,
  `GS0_15_RAM 0xc000`) for scratch code. Register-direct operands (`@ARn`,
  `@AL`) avoid needing to set up memory pointers.
- **Loops:** RPTB is pure SLEIGH — the `:^instruction` wrapper matches on the
  `rptb_flag` context bit and drives the loop-back from inside a single p-code
  sequence. RPT is modelled in SLEIGH for the decompiler but re-issued by
  `postExecuteCallback` under emulation ([why](#why-rpt-still-needs-the-modifier));
  either way `emu.step` handles it. To run a whole `RPT ‖ SUBCU` block, keep
  stepping until PC leaves the block:
  ```java
  emu.writeMemoryValue(at.apply(0xc010L), 2, 0xF60FL);  // RPT #15
  emu.writeMemoryValue(at.apply(0xc011L), 2, 0x1FA1L);  // SUBCU ACC,@AR1
  emu.writeRegister("ACC", 100L); emu.writeRegister("AR1", 7L); emu.writeRegister("PC", 0xc010L);
  while (emu.readRegister("PC").longValue() < 0xc012L) emu.step(mon);
  // ACC = 0x0002000e  ->  AL = 14 (quotient), AH = 2 (remainder)
  ```

## Validating changes

`tests/run_fw_parity.{ps1,sh}` checks **decode** (mnemonic + length) against TI's
`dis2000` — see [TESTING.md](TESTING.md).

**Emulation** correctness needs stepping known inputs and comparing results. The
VCU CRC ops match the standard catalog check values (CRC-8/SMBUS,
CRC-16/BUYPASS, CRC-32/MPEG-2). An AES-128 block emulated on the FIPS-197 vector
produces the bit-exact reference state (exercises RPTB + MOVB byte-lane
addressing).

## Caveat on the CRC ops

The VCRC behaviors model the native MSB-first, non-reflected path
(`VSTATUS[CRCMSGFLIP] = 0`). The polynomials are exact (SPRUHS1) and the bit
loop matches the standard CRC catalog, but the silicon message-bit-reflection
mode is not modeled — confirm the numeric result against a captured frame
before relying on it for a CRC equivalence check.
