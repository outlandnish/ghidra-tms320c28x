// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the "lone family" flag fixes from issue #90 group D. Each of these
// instructions had NO sibling variant to compare against in the audit script, so each fix
// needed a direct SPRU430F reading. Coverage here is one representative case per distinct
// FLAG PATTERN, not per constructor -- MAC/MPYS/ADDUL/SUBCUL all take the ADDL/SUBL flag
// shape already validated in EmuFlagsPmProductTest; the interesting cases below are the ones
// with UNIQUE flag semantics:
//   - ABS ACC:   V is set only for input 0x80000000 (the one value with no positive counterpart)
//   - LSLL/LSRL/ASRL by T:  C is the LAST BIT SHIFTED OUT of ACC (0 when T[4:0]=0)
//   - SFR ACC,#shcount:     SXM-governed (arith vs logical) AND C=last bit out -- both fixed
//   - ZALR ACC,loc16:       N/Z from the loaded ACC (0x8000 | (loc<<16))
//   - NORM ACC,XARn++:      TC=0 if the shift happened, TC=1 if bits 31,30 differ (or ACC=0)
//
// Every case pre-seeds the asserted flag to its opposite.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuFlagsLoneFamilyTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFlagsLoneFamilyTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long ABS_ACC   = 0xFF56L;                 // ABS ACC
    private static final long LSLL_ACC_T = 0x563BL;                // LSLL ACC,T
    private static final long ASRL_ACC_T = 0x5610L;                // ASRL ACC,T
    private static final long LSRL_ACC_T = 0x5622L;                // LSRL ACC,T
    private static final long SFR_ACC_SH = 0xFF40L;                // SFR ACC,#shcount (| shft4)
    private static final long ZALR_ACC   = 0x5613L;                // ZALR ACC,loc16 (2-word)
    private static final long LOC_SP1    = 0x41L;                  // *-SP[1] loc byte
    private static final long NORM_ACC_XAR0_PP = 0xFF78L;          // NORM ACC,XAR0++  (norm_pm=1)
    private static final long SETC_SXM   = 0x3B01L;                // set SXM
    private static final long CLRC_SXM   = 0x2901L;                // clear SXM
    private static final long SP_BASE    = 0x8000L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ---- ABS ACC ----------------------------------------------------
            // 1. ABS 0x80000000 -> stays 0x80000000 (no positive counterpart), V set, C cleared.
            single(emu, sp, ABS_ACC, 0x80000000L, 0x80000000L, /*N*/1, /*Z*/0, /*C*/0, /*V*/1,
                "ABS 0x80000000 : V set (STALE V=0), C cleared");
            // 2. ABS -5 -> 5. V clears, C clears, N clears.
            single(emu, sp, ABS_ACC, 0xfffffffbL, 0x00000005L, 0, 0, 0, 0,
                "ABS -5 : |val|=5, all flags clear");

            // ---- LSLL/LSRL/ASRL by T ---------------------------------------
            // 3. LSLL ACC=0x80000000 by T=1 -> ACC=0, C=1 (MSB shifted out).
            shiftByT(emu, sp, LSLL_ACC_T, 0x80000000L, 1, 0x00000000L, 0, 1, 1,
                "LSLL by 1 : 0x80000000 -> 0, C=1 (MSB out)");
            // 4. LSRL ACC=0x00000003 by T=2 -> ACC=0, C=1 (last bit out = bit 1 = 1).
            shiftByT(emu, sp, LSRL_ACC_T, 0x00000003L, 2, 0x00000000L, 0, 1, 1,
                "LSRL by 2 : 0x3 -> 0, C=1 (LSB out)");
            // 5. ASRL ACC=0x80000000 by T=1 -> ACC=0xC0000000 (sign-extended), C=0.
            shiftByT(emu, sp, ASRL_ACC_T, 0x80000000L, 1, 0xC0000000L, 1, 0, 0,
                "ASRL by 1 : 0x80000000 -> 0xC0000000, C=0");
            // 6. LSLL by T=0 -> C forced to 0 (no shift).
            shiftByT(emu, sp, LSLL_ACC_T, 0xffffffffL, 0, 0xffffffffL, 1, 0, 0,
                "LSLL by 0 : C forced to 0 (STALE C=1)");

            // ---- SFR ACC,#shcount (SXM-governed) ---------------------------
            // 7. SFR ACC #1 with SXM=1 : arithmetic shift right, 0x80000000 -> 0xC0000000.
            sfrWithSxm(emu, sp, 1, 0x80000000L, 1, 0xC0000000L, 1, 0, 0,
                "SFR #1 with SXM=1 : arith shift");
            // 8. SFR ACC #1 with SXM=0 : logical shift right, 0x80000000 -> 0x40000000.
            sfrWithSxm(emu, sp, 0, 0x80000000L, 1, 0x40000000L, 0, 0, 0,
                "SFR #1 with SXM=0 : logic shift");
            // 9. SFR ACC #2 : C = last bit out (bit 1 pre-shift).
            sfrWithSxm(emu, sp, 0, 0x00000002L, 2, 0x00000000L, 0, 1, 1,
                "SFR #2 : C = last bit out");

            // ---- ZALR ACC,loc16 --------------------------------------------
            // 10. ZALR with loc=0x1234 -> ACC = 0x12348000. N=0, Z=0.
            zalrCase(emu, sp, 0x1234, 0x12348000L, 0, 0,
                "ZALR loc=0x1234 : ACC=0x12348000");

            // ---- NORM ACC,XAR0++ -------------------------------------------
            // 11. NORM ACC=0x30000000 (bits 31,30 both 0) -> shift, TC=0, XAR0++.
            //     ACC becomes 0x60000000.
            normCase(emu, sp, 0x30000000L, /*xar0*/ 0x100L, 0x60000000L, /*xar0*/ 0x101L,
                /*wantTC*/ 0, "NORM ACC=0x30000000 : shift, TC=0 (STALE TC=1)");
            // 12. NORM ACC=0x40000000 (bits 31=0, 30=1 differ) -> no shift, TC=1, XAR0 unchanged.
            normCase(emu, sp, 0x40000000L, 0x200L, 0x40000000L, 0x200L, 1,
                "NORM ACC=0x40000000 : no shift, TC=1 (STALE TC=0)");
            // 13. NORM ACC=0 -> no shift, TC=1.
            normCase(emu, sp, 0x00000000L, 0x300L, 0x00000000L, 0x300L, 1,
                "NORM ACC=0 : no shift, TC=1");

            if (failures == 0) {
                println("EmuFlagsLoneFamilyTest.java> PASS: lone-family flag fixes (13 cases)");
            } else {
                println("EmuFlagsLoneFamilyTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** One-word instruction, ACC-only. */
    private void single(EmulatorHelper emu, AddressSpace sp, long word0, long initAcc,
            long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", wantV == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    /** Shift-by-T: set T register, then step the shift instruction. */
    private void shiftByT(EmulatorHelper emu, AddressSpace sp, long word0, long initAcc, long tval,
            long wantAcc, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("T", tval);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
    }

    /** SFR with SETC/CLRC SXM prefix. `shcount` is the shift AMOUNT (1..16), encoded as
     *  shft4 = shcount - 1 in the opcode (or 0 for shcount==16). */
    private void sfrWithSxm(EmulatorHelper emu, AddressSpace sp, long sxm, long initAcc, long shcount,
            long wantAcc, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        long shft4 = (shcount - 1) & 0xf;   // shcount=16 wraps to 0 per SPRU430F
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, sxm == 1 ? SETC_SXM : CLRC_SXM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, SFR_ACC_SH | shft4);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
    }

    /** ZALR: load AL=0x8000, AH=[loc16]. Uses *-SP[1] scratch for loc16. */
    private void zalrCase(EmulatorHelper emu, AddressSpace sp, long locVal, long wantAcc,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", 0x11111111L);
        emu.writeRegister("SP", SP_BASE);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, locVal & 0xffffL);
        long here = codeCursor; codeCursor += 6;
        // ZALR is a TWO-WORD instruction: word1 = 0x5613, word2 low byte = loc16 encoding.
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ZALR_ACC);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    /** NORM ACC,XAR0++ : verify TC and XAR0 post-modification. */
    private void normCase(EmulatorHelper emu, AddressSpace sp, long initAcc, long initXar0,
            long wantAcc, long wantXar0, long wantTC, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("XAR0", initXar0);
        emu.writeRegister("TC", wantTC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, NORM_ACC_XAR0_PP);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [XAR0]", emu.readRegister("XAR0").longValue() & 0xffffffffL, wantXar0);
        expect(what + " [TC]", emu.readRegister("TC").longValue(), wantTC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuFlagsLoneFamilyTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuFlagsLoneFamilyTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
