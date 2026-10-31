// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paul van der Wateren
//
// Emulation test for ASP / NASP (0x761B / 0x7617), rewritten branch-free. The old bodies
// used an intra-instruction `goto`, which made the decompiler report "Removing unreachable
// block" at every site; this pins the semantics so the rewrite cannot drift.
// SPRU430F: ASP -- if SP is odd, SP += 1 and SPA = 1, else SPA = 0.
//           NASP -- if SPA = 1, SP -= 1; SPA is cleared either way.
//
// Every case pre-seeds SPA to the opposite of the expected value.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuAspNaspTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuAspNaspTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long ASP  = 0x761BL;
    private static final long NASP = 0x7617L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            check(emu, sp, ASP,  0x0400L, 1L, 0x0400L, 0L, "ASP  : SP even -> SP unchanged, SPA=0");
            check(emu, sp, ASP,  0x0401L, 0L, 0x0402L, 1L, "ASP  : SP odd  -> SP+1, SPA=1");
            check(emu, sp, NASP, 0x0402L, 1L, 0x0401L, 0L, "NASP : SPA=1   -> SP-1, SPA=0");
            check(emu, sp, NASP, 0x0402L, 0L, 0x0402L, 0L, "NASP : SPA=0   -> SP unchanged, SPA=0");

            if (failures == 0) {
                println("EmuAspNaspTest.java> PASS: ASP/NASP align and unalign SP (4 cases)");
            } else {
                println("EmuAspNaspTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long op, long preSp, long preSpa,
            long wantSp, long wantSpa, String what) throws Exception {
        emu.writeRegister("SP", preSp);
        emu.writeRegister("SPA", preSpa);
        long here = codeCursor; codeCursor += 2;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [SP]",  emu.readRegister("SP").longValue() & 0xffffL, wantSp);
        expect(what + " [SPA]", emu.readRegister("SPA").longValue(), wantSpa);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuAspNaspTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuAspNaspTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
