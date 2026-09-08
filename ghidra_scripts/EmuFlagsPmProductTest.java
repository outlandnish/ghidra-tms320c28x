// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for ADDL/SUBL ACC,P<<PM (issue #90 group B). The pm_shift=0 variants ran
// with no flag writes at all -- both computed the sum/difference and returned. The audit's
// sibling ADDL ACC,loc32 sets N/Z/C/V; SPRU430F specifies the same for these forms. Only the
// pm_shift=0 constructor is exercised here because pm_shift=1 requires TMS320C28xPmShiftAnalyzer
// to have set the context, which -noanalysis defeats -- the flag logic is IDENTICAL on both
// variants, so pm_shift=0 is a representative cover.
//
// Every case pre-seeds the asserted flag to its opposite; a body that leaves the flag alone
// (the pre-fix state) will fail.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuFlagsPmProductTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFlagsPmProductTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long ADDL_ACC_P = 0x10ACL;   // ADDL ACC,P<<PM  (pm_shift=0 variant)
    private static final long SUBL_ACC_P = 0x11ACL;   // SUBL ACC,P<<PM  (pm_shift=0 variant)

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. ADDL: 5 + 3 -> 8. Z cleared, N cleared, C cleared, V cleared.
            check(emu, sp, ADDL_ACC_P, 0x00000005L, 0x00000003L, 0x00000008L, 0, 0, 0, 0,
                "ADDL: 5+3 -> 8");

            // 2. ADDL: 0xffffffff + 1 -> 0. Z set, C set (unsigned carry).
            check(emu, sp, ADDL_ACC_P, 0xffffffffL, 0x00000001L, 0x00000000L, 0, 1, 1, 0,
                "ADDL: 0xffffffff+1 -> 0, Z+C set");

            // 3. ADDL signed overflow: 0x7fffffff + 1 -> 0x80000000. V set, N set.
            check(emu, sp, ADDL_ACC_P, 0x7fffffffL, 0x00000001L, 0x80000000L, 1, 0, 0, 1,
                "ADDL: 0x7fffffff+1 -> 0x80000000, N+V set");

            // 4. SUBL: 5 - 2 -> 3. C set (no borrow).
            check(emu, sp, SUBL_ACC_P, 0x00000005L, 0x00000002L, 0x00000003L, 0, 0, 1, 0,
                "SUBL: 5-2 -> 3, C set (no borrow)");

            // 5. SUBL borrow: 0 - 1 -> 0xffffffff. C cleared (borrow), N set.
            check(emu, sp, SUBL_ACC_P, 0x00000000L, 0x00000001L, 0xffffffffL, 1, 0, 0, 0,
                "SUBL: 0-1 -> 0xffffffff, C cleared (borrow), N set");

            // 6. STALE-FLAG case. SUBL 0x1000 - 0x1000 -> 0. Z pre-seeded to 0, must set.
            check(emu, sp, SUBL_ACC_P, 0x00001000L, 0x00001000L, 0x00000000L, 0, 1, 1, 0,
                "SUBL: 0x1000-0x1000 -> 0, Z set (STALE Z=0)");

            if (failures == 0) {
                println("EmuFlagsPmProductTest.java> PASS: ADDL/SUBL ACC,P<<PM set N,Z,C,V (6 cases)");
            } else {
                println("EmuFlagsPmProductTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long word0, long initAcc, long initP,
            long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("P", initP);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", wantV == 1 ? 0L : 1L);
        long here = codeCursor;
        codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) {
            fail(what, "step: " + emu.getLastError());
            return;
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuFlagsPmProductTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuFlagsPmProductTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
