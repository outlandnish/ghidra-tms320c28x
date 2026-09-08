// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #114 LOOPZ / LOOPNZ N/Z semantics.
//
// LOOPNZ existed at the right opcode (0x2E) with a `{ }` decode-only body, so every
// peripheral-wait idiom silently ran with the previous compare's stale N/Z. LOOPZ (0x2C)
// was missing entirely -- its opcode was mis-claimed by a phantom MOV IERreg,loc16
// constructor with the wrong hi byte, which won every LOOPZ site in real firmware and
// rendered it as `MOV @loc,IER` while desyncing the following word.
//
// Both now decode with real semantics: AND [loc16] with the mask, set N/Z from the
// result, then `if (loop-condition) goto inst_start` to model the self-loop the manual
// describes. We can only exercise the EXIT path here because the loop path is genuinely
// infinite in emulation (the emulator has no peripheral to change the memory word).
// The exit path is what firmware analysis cares about anyway -- post-loop code reads
// N/Z from the LAST iteration.
//
// Every case pre-seeds the asserted flag to its opposite; a body that leaves the flag
// alone (the pre-fix state) will fail.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuLoopTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuLoopTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;   // *-SP[1] loc16 selector

    private static final long LOOPZ_W0  = 0x2C00L;
    private static final long LOOPNZ_W0 = 0x2E00L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // LOOPZ exit paths (AND != 0 -> exit immediately, no loop).
            // mem=0x8000, mask=0x8000 -> AND=0x8000 -> N=1 (bit 15), Z=0.
            loop(emu, sp, LOOPZ_W0, 0x8000L, 0x8000L, /*wantN*/1, /*wantZ*/0,
                "LOOPZ mem=0x8000 mask=0x8000 -> AND=0x8000, N=1 (regression: was mis-decoded as MOV IER)");
            // mem=0x0F0F, mask=0x0100 -> AND=0x0100 -> N=0, Z=0.
            loop(emu, sp, LOOPZ_W0, 0x0F0FL, 0x0100L, 0, 0,
                "LOOPZ mem=0x0F0F mask=0x0100 -> AND=0x0100, N=0 Z=0");

            // LOOPNZ exit paths (AND == 0 -> exit immediately, no loop).
            // mem=0xF0F0, mask=0x000F -> AND=0 -> N=0, Z=1.
            loop(emu, sp, LOOPNZ_W0, 0xF0F0L, 0x000FL, 0, 1,
                "LOOPNZ mem=0xF0F0 mask=0x000F -> AND=0, Z=1 (regression: body was `{ }`)");
            // mem=0x0000, mask=0xFFFF -> AND=0 -> N=0, Z=1.
            loop(emu, sp, LOOPNZ_W0, 0x0000L, 0xFFFFL, 0, 1,
                "LOOPNZ mem=0 mask=0xFFFF -> AND=0, Z=1");

            if (failures == 0) {
                println("EmuLoopTest.java> PASS: LOOPZ / LOOPNZ N/Z semantics (issue #114, 4 cases)");
            } else {
                println("EmuLoopTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void loop(EmulatorHelper emu, AddressSpace sp, long opWord, long mem, long mask,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2),       2, opWord | LOC_SP1);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, mask);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuLoopTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuLoopTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
