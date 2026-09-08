// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #106 NEG/ABS family flag audit.
//
// SPRU430F ch. 6 pages 334/336/337/369/428 define N/Z/C/V + OVM-driven signed
// saturation for NEG ACC, NEG64 ACC:P, NEGTC ACC, ABS ACC, ABSTC ACC. Prior
// bodies were missing:
//   - NEG ACC        : C, OVM saturation
//   - NEG64 ACC:P    : C, V, OVM saturation (Z was ACC-only -- regression trap)
//   - NEGTC ACC      : C, V, OVM saturation (only fired when TC=1)
//   - ABS ACC        : OVM saturation
//   - ABSTC ACC      : N, Z, C, V, OVM saturation (nearly flag-silent)
//
// Central regression: NEG/ABS(min_int) -- 0x80000000 for 32-bit, its 64-bit
// cousin for NEG64. Under OVM=0 the natural two's-complement wrap gives back
// min_int; under OVM=1 the result must saturate to signed max. V=1 either way.
//
// NEG AX is deliberately NOT in scope -- already correct per SPRU430F.
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuNegAbsTest extends GhidraScript {

    private static final long CODE = 0xc100L;

    private static final long NEG_ACC   = 0xFF54L;
    private static final long ABS_ACC   = 0xFF56L;
    private static final long NEG64     = 0x5658L;
    private static final long NEGTC_ACC = 0x5632L;
    private static final long ABSTC_ACC = 0x565FL;
    private static final long SETC_OVM  = 0x3B02L;
    private static final long CLRC_OVM  = 0x2902L;
    private static final long SETC_TC   = 0x3B04L;
    private static final long CLRC_TC   = 0x2904L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ---- 1. NEG ACC -----------------------------------------------
            // Basic negation: NEG(5) = 0xFFFFFFFB, C=0 (result != 0), N=1, V=0.
            negAcc(emu, sp, /*ovm*/0, /*preAcc*/0x00000005L,
                /*wantAcc*/0xFFFFFFFBL, /*wantN*/1, /*wantZ*/0, /*wantC*/0, /*wantV*/0,
                "NEG ACC : NEG(5) -> 0xFFFFFFFB, C=0");
            // Zero: NEG(0) = 0, C=1 (odd 'carry-set-on-zero' convention), Z=1.
            // Regression: prior body left C uninitialised (was neither pass-1 nor pass-2
            // audit-visible, so silently missed).
            negAcc(emu, sp, 0, 0x00000000L, 0x00000000L, 0, 1, 1, 0,
                "NEG ACC : NEG(0) -> 0, C=1 (regression: prior body did not write C)");
            // Overflow OVM=0: NEG(0x80000000) wraps to itself. V=1, C=0.
            negAcc(emu, sp, 0, 0x80000000L, 0x80000000L, 1, 0, 0, 1,
                "NEG ACC : NEG(min_int) OVM=0 wraps, V=1");
            // Overflow OVM=1: NEG(0x80000000) saturates to 0x7FFFFFFF. V=1, C=0, N=0.
            negAcc(emu, sp, 1, 0x80000000L, 0x7FFFFFFFL, 0, 0, 0, 1,
                "NEG ACC : NEG(min_int) OVM=1 saturates to 0x7FFFFFFF");

            // ---- 2. NEG64 ACC:P -------------------------------------------
            // Basic negation: NEG(0:1) = 0xFFFFFFFF:0xFFFFFFFF (64-bit -1). C=0, N=1, V=0.
            // REGRESSION for Z-from-ACC-only: a body that checks (ACC==0) would report
            // Z=1 here (since ACC would be 0 in a broken model), but full-pair Z gives 0.
            neg64(emu, sp, 0, 0x00000000L, 0x00000001L,
                0xFFFFFFFFL, 0xFFFFFFFFL, 1, 0, 0, 0,
                "NEG64 : NEG(0:1) -> full-64-bit -1, C=0 (regression: Z-from-ACC-only would fail)");
            // Zero: NEG(0:0) = 0:0, C=1, Z=1, N=0.
            neg64(emu, sp, 0, 0L, 0L, 0L, 0L, 0, 1, 1, 0,
                "NEG64 : NEG(0:0) -> 0, C=1, Z=1");
            // Overflow OVM=0: NEG(0x80000000:0) wraps to 0x80000000:0. V=1.
            neg64(emu, sp, 0, 0x80000000L, 0x00000000L,
                0x80000000L, 0x00000000L, 1, 0, 0, 1,
                "NEG64 : NEG(min_int64) OVM=0 wraps, V=1");
            // Overflow OVM=1: saturates to 0x7FFFFFFF:0xFFFFFFFF. V=1, N=0 (top bit clear).
            neg64(emu, sp, 1, 0x80000000L, 0x00000000L,
                0x7FFFFFFFL, 0xFFFFFFFFL, 0, 0, 0, 1,
                "NEG64 : NEG(min_int64) OVM=1 saturates to 0x7FFFFFFFFFFFFFFF");

            // ---- 3. NEGTC ACC ---------------------------------------------
            // TC=0: no negation, no C/V change, but N/Z still reflect current ACC.
            // Regression: seed opposite C and V, then verify they're preserved.
            negtc(emu, sp, /*tc*/0, /*ovm*/0, /*preAcc*/0x80000000L,
                /*preC*/1, /*preV*/0, /*wantAcc*/0x80000000L,
                /*wantN*/1, /*wantZ*/0, /*wantC*/1, /*wantV*/0,
                "NEGTC ACC : TC=0 preserves C/V, updates N/Z only");
            // TC=1: same math as NEG ACC. Basic case.
            negtc(emu, sp, 1, 0, 0x00000005L, 0, 0, 0xFFFFFFFBL, 1, 0, 0, 0,
                "NEGTC ACC : TC=1 negates 5 -> 0xFFFFFFFB");
            // TC=1 overflow OVM=1: saturates.
            negtc(emu, sp, 1, 1, 0x80000000L, 0, 0, 0x7FFFFFFFL, 0, 0, 0, 1,
                "NEGTC ACC : TC=1 OVM=1 saturates min_int -> 0x7FFFFFFF");

            // ---- 4. ABS ACC -----------------------------------------------
            // Positive: ABS(5) = 5, C=0.
            absAcc(emu, sp, 0, 0x00000005L, 0x00000005L, 0, 0, 0, 0,
                "ABS ACC : ABS(5) unchanged, C=0");
            // Negative: ABS(-5) = 5, C=0.
            absAcc(emu, sp, 0, 0xFFFFFFFBL, 0x00000005L, 0, 0, 0, 0,
                "ABS ACC : ABS(-5) -> 5, C=0");
            // Overflow OVM=0: ABS(min_int) wraps.
            absAcc(emu, sp, 0, 0x80000000L, 0x80000000L, 1, 0, 0, 1,
                "ABS ACC : ABS(min_int) OVM=0 wraps, V=1");
            // Overflow OVM=1: ABS(min_int) saturates to 0x7FFFFFFF.
            absAcc(emu, sp, 1, 0x80000000L, 0x7FFFFFFFL, 0, 0, 0, 1,
                "ABS ACC : ABS(min_int) OVM=1 saturates to 0x7FFFFFFF");

            // ---- 5. ABSTC ACC ---------------------------------------------
            // Negative input: ABS(-5) = 5, TC XORed to 1 (from 0), N=0, Z=0, C=0, V=0.
            // Multiple regressions here: prior body had NO N, Z, C, or V.
            abstc(emu, sp, /*ovm*/0, /*preTc*/0, /*preAcc*/0xFFFFFFFBL,
                /*wantAcc*/0x00000005L, /*wantTc*/1,
                /*wantN*/0, /*wantZ*/0, /*wantC*/0, /*wantV*/0,
                "ABSTC ACC : ABS(-5)+TC^1 -- N/Z/C/V all newly set (regression)");
            // Positive input: unchanged, TC preserved, N=0, Z=0, C=0, V=0.
            abstc(emu, sp, 0, 1, 0x00000005L, 0x00000005L, 1, 0, 0, 0, 0,
                "ABSTC ACC : ABS(5) unchanged, TC preserved");
            // Overflow OVM=1: ABS(min_int) saturates + TC XOR + V=1.
            abstc(emu, sp, 1, 0, 0x80000000L, 0x7FFFFFFFL, 1, 0, 0, 0, 1,
                "ABSTC ACC : ABS(min_int) OVM=1 saturates + TC XOR + V=1");

            if (failures == 0) {
                println("EmuNegAbsTest.java> PASS: NEG/ABS family flag semantics (17 cases)");
            } else {
                println("EmuNegAbsTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void negAcc(EmulatorHelper emu, AddressSpace sp, long ovm, long preAcc,
            long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        preSetFlagsNZCV(emu, wantN, wantZ, wantC, wantV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, NEG_ACC);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlagsNZCV(what, emu, wantN, wantZ, wantC, wantV);
    }

    private void neg64(EmulatorHelper emu, AddressSpace sp, long ovm, long preAcc, long preP,
            long wantAcc, long wantP, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("P",   preP);
        preSetFlagsNZCV(emu, wantN, wantZ, wantC, wantV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, NEG64);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [P]",   emu.readRegister("P").longValue()   & 0xffffffffL, wantP);
        checkFlagsNZCV(what, emu, wantN, wantZ, wantC, wantV);
    }

    private void negtc(EmulatorHelper emu, AddressSpace sp, long tc, long ovm, long preAcc,
            long preC, long preV, long wantAcc,
            long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        // seed C/V explicitly so the TC=0 preservation is provable
        emu.writeRegister("C", preC);
        emu.writeRegister("V", preV);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, tc == 1 ? SETC_TC : CLRC_TC);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, NEGTC_ACC);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 3; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlagsNZCV(what, emu, wantN, wantZ, wantC, wantV);
    }

    private void absAcc(EmulatorHelper emu, AddressSpace sp, long ovm, long preAcc,
            long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        preSetFlagsNZCV(emu, wantN, wantZ, wantC, wantV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ABS_ACC);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlagsNZCV(what, emu, wantN, wantZ, wantC, wantV);
    }

    private void abstc(EmulatorHelper emu, AddressSpace sp, long ovm, long preTc, long preAcc,
            long wantAcc, long wantTc, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("TC", preTc);
        preSetFlagsNZCV(emu, wantN, wantZ, wantC, wantV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ABSTC_ACC);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [TC]",  emu.readRegister("TC").longValue(),  wantTc);
        checkFlagsNZCV(what, emu, wantN, wantZ, wantC, wantV);
    }

    private void preSetFlagsNZCV(EmulatorHelper emu, long wantN, long wantZ, long wantC, long wantV) throws Exception {
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", wantV == 1 ? 0L : 1L);
    }
    private void checkFlagsNZCV(String what, EmulatorHelper emu, long wantN, long wantZ, long wantC, long wantV) throws Exception {
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuNegAbsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuNegAbsTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
