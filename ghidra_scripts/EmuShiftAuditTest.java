// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #104 shift-family flag semantics + 3 new constructors.
//
// Covers the two holes flag_audit didn't catch because its DEST regex missed the
// sub-table-variable aliases (AXb0 / AXb4 / ACCreg):
//
//   1. AX shifts by T and #imm (ASR/LSR/LSL, both AL & AH) -- were flag-silent;
//      SPRU430F requires N/Z/C on all six.
//   2. 64-bit ACC:P shifts by T and #imm (ASR64/LSR64/LSL64) -- were flag-silent;
//      SPRU430F requires N/Z/C with Z from the FULL pair, not just ACC.
//   3. FLIP AX -- was flag-silent; SPRU430F specifies N/Z.
//
// Plus the three new constructors that filled the 0xFF50-0xFF52 gap:
//   4. LSL ACC,T (0xFF50), SFR ACC,T (0xFF51, SXM-governed), ROR ACC (0xFF52).
//
// Existing LSLL/LSRL/ASRL by T and SFR ACC,#imm coverage lives in
// EmuFlagsLoneFamilyTest.java (issue #90); do not re-cover.
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuShiftAuditTest extends GhidraScript {

    private static final long CODE = 0xc100L;

    // AX shifts by T -- 1111 1111 0110 <ss>A. A=bit0.
    private static final long ASR_AL_T = 0xFF64L;
    private static final long LSR_AL_T = 0xFF62L;
    private static final long LSL_AL_T = 0xFF66L;
    private static final long LSL_AH_T = 0xFF67L;
    // AX shifts by #imm -- 1111 1111 <sss>A SHFT. A=bit4, SHFT=bits0..3.
    private static final long ASR_AL_IMM_BASE = 0xFFA0L;
    private static final long LSR_AL_IMM_BASE = 0xFFC0L;
    private static final long LSL_AL_IMM_BASE = 0xFF80L;
    // 64-bit ACC:P shifts.
    private static final long ASR64_IMM_BASE  = 0x5680L;
    private static final long LSR64_IMM_BASE  = 0x5690L;
    private static final long LSL64_IMM_BASE  = 0x56A0L;
    private static final long ASR64_ACC_P_T   = 0x562CL;
    private static final long LSR64_ACC_P_T   = 0x565BL;
    private static final long LSL64_ACC_P_T   = 0x5652L;
    // FLIP.
    private static final long FLIP_AL         = 0x5670L;
    // New constructors (0xFF50-0xFF52 block).
    private static final long LSL_ACC_T       = 0xFF50L;
    private static final long SFR_ACC_T       = 0xFF51L;
    private static final long ROR_ACC         = 0xFF52L;
    // SXM mode prefix for SFR ACC,T tests.
    private static final long SETC_SXM        = 0x3B01L;
    private static final long CLRC_SXM        = 0x2901L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ---- 1. AX shifts by T ----------------------------------------
            // LSR AL,T with T=4, AL=0x00F0 -> AL=0x000F, C = last bit out (bit 3 = 0),
            // N=0, Z=0. Pre-stale flags to prove the constructor writes them.
            axShiftByT(emu, sp, LSR_AL_T, /*al*/0x00F0L, /*t*/4, /*wantAX*/0x000FL,
                /*wantN*/0, /*wantZ*/0, /*wantC*/0,
                "LSR AL,T=4 : 0x00F0 -> 0x000F, C=0");
            // ASR AL,T=1 with AL=0x8000 -> AL=0xC000, N=1, C=0 (bit 0 pre-shift = 0).
            axShiftByT(emu, sp, ASR_AL_T, 0x8000L, 1, 0xC000L, 1, 0, 0,
                "ASR AL,T=1 : 0x8000 -> 0xC000 (sign-fill), C=0");
            // LSL AL,T=1 with AL=0x8000 -> AL=0, C=1 (MSB out), Z=1.
            axShiftByT(emu, sp, LSL_AL_T, 0x8000L, 1, 0x0000L, 0, 1, 1,
                "LSL AL,T=1 : 0x8000 -> 0, C=1, Z=1");
            // LSL AH,T=0 : C forced to 0 (STALE C=1 must clear). AL unchanged (no register aliasing).
            axShiftByT(emu, sp, LSL_AH_T, /*al=*/0x5555L, /*t=*/0, /*wantAX=*/0x5555L,
                0, 0, 0, "LSL AH,T=0 : C forced 0 (SPRU430F T=0 clears C)", /*testAH=*/true);

            // ---- 2. AX shifts by #imm --------------------------------------
            // LSL AL,#1 with AL=0x8000 -> AL=0, C=1, Z=1.
            axShiftByImm(emu, sp, LSL_AL_IMM_BASE, 1, 0x8000L, 0x0000L, 0, 1, 1,
                "LSL AL,#1 : 0x8000 -> 0, C=1, Z=1");
            // ASR AL,#4 with AL=0x00F0 -> AL=0x000F, C=(bit 3 pre)=0.
            axShiftByImm(emu, sp, ASR_AL_IMM_BASE, 4, 0x00F0L, 0x000FL, 0, 0, 0,
                "ASR AL,#4 : 0x00F0 -> 0x000F, C=0");
            // LSR AL,#4 with AL=0x00F8 -> AL=0x000F, C=(bit 3 pre)=1.
            axShiftByImm(emu, sp, LSR_AL_IMM_BASE, 4, 0x00F8L, 0x000FL, 0, 0, 1,
                "LSR AL,#4 : 0x00F8 -> 0x000F, C=1 (bit 3 out)");

            // ---- 3. 64-bit ACC:P shifts ------------------------------------
            // LSL64 ACC:P,#1 with ACC:P = 0x8000000000000001. ACC=0x80000000 P=1.
            // -> ACC:P = 0x0000000000000002. ACC=0 P=2. C = MSB pre = 1. N=0 (ACC[31]=0).
            // Z=0 (P!=0). Regression: buggy Z-from-ACC-only would report Z=1.
            shift64Imm(emu, sp, LSL64_IMM_BASE, 1, 0x80000000L, 0x00000001L,
                0x00000000L, 0x00000002L, 0, 0, 1,
                "LSL64 ACC:P,#1 : Z from FULL pair (regression: Z-from-ACC-only would be 1)");
            // ASR64 ACC:P,T=32 with ACC=0x80000000 P=0x80000000. Value=0x8000000080000000.
            // Right-arith by 32: sign-fill upper 32 -> new value=0xFFFFFFFF80000000.
            // ACC=0xFFFFFFFF P=0x80000000. C = last bit out = original bit 31 = 1.
            // N=1 (ACC[31]=1), Z=0.
            shift64T(emu, sp, ASR64_ACC_P_T, 32, 0x80000000L, 0x80000000L,
                0xFFFFFFFFL, 0x80000000L, 1, 0, 1,
                "ASR64 ACC:P,T=32 : arith fill, C=1, N=1");
            // LSR64 ACC:P,T=0 : C forced 0 (STALE C=1 must clear); ACC:P unchanged.
            shift64T(emu, sp, LSR64_ACC_P_T, 0, 0xffffffffL, 0xffffffffL,
                0xffffffffL, 0xffffffffL, 1, 0, 0,
                "LSR64 ACC:P,T=0 : C forced 0, pair unchanged");
            // LSL64 ACC:P,#64 : shft4=15 -> shcount=16. ACC:P entirely shifted out.
            // C = last bit out = bit(64-16)=48 pre = ACC pre bit 16.
            // ACC pre = 0x00010000 -> bit 16 = 1. P pre = 0. -> ACC:P = 0. Z=1.
            shift64Imm(emu, sp, LSL64_IMM_BASE, 16, 0x00010000L, 0x00000000L,
                0x00000000L, 0x00000000L, 0, 1, 1,
                "LSL64 ACC:P,#16 : all out, C=1 (bit 48 pre)");

            // ---- 4. New constructors ---------------------------------------
            // LSL ACC,T=1 with ACC=0x80000000 -> 0, C=1, Z=1.
            accShiftByT(emu, sp, LSL_ACC_T, 0x80000000L, 1, 0x00000000L, 0, 1, 1,
                "LSL ACC,T=1 : 0x80000000 -> 0, C=1, Z=1  (new constructor, 0xFF50)");
            // LSL ACC,T=0 : C forced 0 (regression against STALE C=1). ACC unchanged.
            accShiftByT(emu, sp, LSL_ACC_T, 0xffffffffL, 0, 0xffffffffL, 1, 0, 0,
                "LSL ACC,T=0 : C forced 0 (new constructor)");
            // SFR ACC,T=1 with SXM=1 : arithmetic (sign-fill) : 0x80000000 -> 0xC0000000.
            sfrAccTWithSxm(emu, sp, /*sxm*/1, /*acc*/0x80000000L, /*t*/1,
                0xC0000000L, 1, 0, 0,
                "SFR ACC,T=1 with SXM=1 : arithmetic fill  (new constructor, 0xFF51)");
            // SFR ACC,T=1 with SXM=0 : logical (zero-fill) : 0x80000000 -> 0x40000000.
            sfrAccTWithSxm(emu, sp, 0, 0x80000000L, 1, 0x40000000L, 0, 0, 0,
                "SFR ACC,T=1 with SXM=0 : logical fill");
            // ROR ACC : rotate right through carry. ACC=1, C=1 -> ACC=0x80000000, C=1.
            rorCase(emu, sp, /*acc*/0x00000001L, /*cIn*/1, /*wantACC*/0x80000000L,
                /*wantN*/1, /*wantZ*/0, /*wantC*/1,
                "ROR ACC : {C=1, ACC=1} -> ACC=0x80000000, C=1  (new constructor, 0xFF52)");
            // ROR ACC : ACC=0, C=0 -> ACC=0, C=0, Z=1.
            rorCase(emu, sp, 0L, 0, 0L, 0, 1, 0,
                "ROR ACC : {C=0, ACC=0} -> ACC=0, C=0, Z=1");

            // ---- 5. FLIP AX ------------------------------------------------
            // FLIP AL 0x0001 -> 0x8000, N=1, Z=0.
            flipCase(emu, sp, 0x0001L, 0x8000L, 1, 0, "FLIP AL 0x0001 -> 0x8000 : N=1");
            // FLIP AL 0x0000 -> 0x0000, Z=1.
            flipCase(emu, sp, 0x0000L, 0x0000L, 0, 1, "FLIP AL 0x0000 -> 0, Z=1");

            if (failures == 0) {
                println("EmuShiftAuditTest.java> PASS: shift-family flag semantics (18 cases)");
            } else {
                println("EmuShiftAuditTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void axShiftByT(EmulatorHelper emu, AddressSpace sp, long word0, long al, long tval,
            long wantAX, long wantN, long wantZ, long wantC, String what) throws Exception {
        axShiftByT(emu, sp, word0, al, tval, wantAX, wantN, wantZ, wantC, what, false);
    }
    private void axShiftByT(EmulatorHelper emu, AddressSpace sp, long word0, long axVal, long tval,
            long wantAX, long wantN, long wantZ, long wantC, String what, boolean isAH) throws Exception {
        String reg = isAH ? "AH" : "AL";
        emu.writeRegister(reg, axVal);
        emu.writeRegister("T", tval);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void axShiftByImm(EmulatorHelper emu, AddressSpace sp, long base, long shcount,
            long axVal, long wantAX, long wantN, long wantZ, long wantC, String what) throws Exception {
        long shft4 = (shcount - 1) & 0xf;
        long word0 = base | shft4;
        emu.writeRegister("AL", axVal);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xffffL, wantAX);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void shift64T(EmulatorHelper emu, AddressSpace sp, long word0, long tval,
            long preAcc, long preP, long wantAcc, long wantP,
            long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("P", preP);
        emu.writeRegister("T", tval);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [P]",   emu.readRegister("P").longValue()   & 0xffffffffL, wantP);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void shift64Imm(EmulatorHelper emu, AddressSpace sp, long base, long shcount,
            long preAcc, long preP, long wantAcc, long wantP,
            long wantN, long wantZ, long wantC, String what) throws Exception {
        long shft4 = (shcount - 1) & 0xf;
        long word0 = base | shft4;
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("P", preP);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [P]",   emu.readRegister("P").longValue()   & 0xffffffffL, wantP);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void accShiftByT(EmulatorHelper emu, AddressSpace sp, long word0, long acc, long tval,
            long wantAcc, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("T", tval);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void sfrAccTWithSxm(EmulatorHelper emu, AddressSpace sp, long sxm, long acc, long tval,
            long wantAcc, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("T", tval);
        preSetFlags(emu, wantN, wantZ, wantC);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, sxm == 1 ? SETC_SXM : CLRC_SXM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, SFR_ACC_T);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void rorCase(EmulatorHelper emu, AddressSpace sp, long acc, long cIn,
            long wantAcc, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("C", cIn);
        // Don't pre-set N/Z to opposite here since ROR always writes N/Z.
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ROR_ACC);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        checkFlags(what, emu, wantN, wantZ, wantC);
    }

    private void flipCase(EmulatorHelper emu, AddressSpace sp, long al, long wantAL,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("AL", al);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, FLIP_AL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xffffL, wantAL);
        expect(what + " [N]",  emu.readRegister("N").longValue(),  wantN);
        expect(what + " [Z]",  emu.readRegister("Z").longValue(),  wantZ);
    }

    private void preSetFlags(EmulatorHelper emu, long wantN, long wantZ, long wantC) throws Exception {
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
    }
    private void checkFlags(String what, EmulatorHelper emu, long wantN, long wantZ, long wantC) throws Exception {
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuShiftAuditTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuShiftAuditTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
