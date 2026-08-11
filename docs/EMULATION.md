# Emulating TMS320C28x code in Ghidra

This module ships an `EmulateInstructionStateModifier`
(`ghidra.program.emulation.TMS320C28xEmulateInstructionStateModifier`, wired via
the `emulateInstructionStateModifierClass` property in `tms320c28x.pspec`) that
teaches Ghidra's p-code emulator the things plain SLEIGH can't express:

| Feature | What it does |
| --- | --- |
| **RPTB** | Zero-overhead **block** repeat — loops `[inst_next, inst_next+RSIZE)` for `RC+1` passes. |
| **RPT** | Zero-overhead **single-instruction** repeat — re-issues the next instruction `N+1` times. Makes `RPT #15 ‖ SUBCU` (16-bit unsigned divide) and `RPT ‖ VCRCxx` (block CRC) actually run. |
| **VCRC8L / VCRC16P1L / VCRC32L** | VCU-II CRC accumulate (polys `0x07` / `0x8005` / `0x04C11DB7`, MSB-first, low byte). |
| **countSignBits** | Backs `CSB ACC` (leading redundant sign bits − 1 → T). |

`FLIP`, `SUBCU`, and the CRC/CSB *flag* effects are plain SLEIGH p-code and don't
need the modifier; the modifier only supplies the two hardware loops and the
CRC/CSB *compute*.

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
`CSB ACC` (below) — if `T` comes back computed rather than unchanged, the new jar
is live.

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
- **Loops:** `emu.step` drives the RPTB/RPT loop-back automatically. To run a
  whole `RPT ‖ SUBCU` block, keep stepping until PC leaves the block:
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
