// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #95: MAC-family and add-with-carry / sub-with-borrow
// constructors from SPRU430F Table 2-5 that update OVC on the ACC += P (or
// ACC -= P) step. Coverage matches the ten constructors touched in the fix:
//
//   ADDCL ACC,loc32   ADDCU ACC,loc16   SBBU ACC,loc16
//   MOVA T,loc16      MOVAD T,loc16     MOVS T,loc16
//   SQRA loc16        SQRS loc16
//   XMAC P,loc16,*(pma)   XMACD P,loc16,*(pma)
//
// Each case pre-seeds OVC to a value that contradicts the expected outcome,
// so a body that leaves OVC alone can't accidentally pass. Add-family cases
// force +ve signed overflow (0x7fffffff -> 0x80000000, OVC++), sub-family
// cases force -ve signed overflow (0x80000000 -> 0x7fffffff, OVC--). Two
// OVM=1 suppression checks (one add, one sub) verify the general gate.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuMacOvcTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuMacOvcTest extends GhidraScript {

    private static final long CODE     = 0xc100L;   // GS RAM on the F28377D map
    private static final long SP_BASE  = 0x8000L;
    private static final long LOC_SP1  = 0x41L;     // *-SP[1] loc byte
    private static final long SETC_OVM = 0x3B02L;
    private static final long CLRC_OVM = 0x2902L;

    // Instruction words (see the corresponding constructors in the .sinc files).
    private static final long ADDCL_W1 = 0x5640L;
    private static final long ADDCU    = 0x0C00L;   // op_hi8=0x0C | loc16 byte
    private static final long SBBU     = 0x1D00L;   // op_hi8=0x1D | loc16 byte
    private static final long MOVA_T   = 0x1000L;   // op_hi8=0x10 | loc16 byte (loc16!=0xAC)
    private static final long MOVS_T   = 0x1100L;   // op_hi8=0x11 | loc16 byte (loc16!=0xAC)
    private static final long MOVAD_T  = 0xA700L;   // op_hi8=0xA7 | loc16 byte
    private static final long SQRA_W1  = 0x5615L;
    private static final long SQRS_W1  = 0x5611L;
    private static final long XMAC_W1  = 0x8400L;   // op_hi8=0x84 | loc16 byte
    private static final long XMACD_W1 = 0xA400L;   // op_hi8=0xA4 | loc16 byte

    // XMAC/XMACD force the upper 6 bits of the program-memory addr to 0x3F,
    // so pma word 0 maps to program address 0x3F0000. We only need the read
    // to succeed; the multiplicand value at that address doesn't affect the
    // ACC += P step whose OVC we're checking. Use a nearby word-aligned addr.
    private static final long XPMA_LO  = 0x0100L;   // -> 0x3F0100 in word-address
    private static final long XPMA_HI_BASE = 0x3F0000L;

    // Group A (issue #97, 32x32 MAC forms). All 2-word, word1=0x564x, word2=loc32.
    private static final long QMPYAL_W1 = 0x5646L;
    private static final long QMPYSL_W1 = 0x5645L;
    private static final long IMPYAL_W1 = 0x564CL;
    // Pre-load XT with 0 so the "P = ..." step produces a predictable P after
    // the ACC += P we care about. XT is written directly via emu.writeRegister.
    private static final long IMPYL_ACC_W1 = 0x5644L;   // IMPYL ACC,XT,loc32

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. ADDCL: ACC=0x7fffffff + loc32=0 + C=1 -> 0x80000000, OVC 0 -> +1
            testAddc32(emu, sp, /*preOvc*/0, /*preAcc*/0x7fffffffL, /*loc32*/0L,
                /*preC*/1L, /*ovm*/0, /*wantAcc*/0x80000000L, /*wantOvc*/1L,
                "ADDCL +ve overflow via +C : OVC 0 -> 1");

            // 2. ADDCL under OVM=1: same setup, OVC must NOT change.
            testAddc32(emu, sp, 5, 0x7fffffffL, 0L, 1L, /*ovm*/1,
                0x80000000L, /*wantOvc*/5L,
                "ADDCL +ve overflow with OVM=1 : OVC unchanged");

            // 3. ADDCU: ACC=0x7fffffff + zext(loc16)=0 + C=1 -> 0x80000000, OVC 0 -> +1
            testAddc16(emu, sp, ADDCU, /*preOvc*/0, 0x7fffffffL, 0L, /*preC*/1L,
                0x80000000L, /*wantOvc*/1L,
                "ADDCU +ve overflow via +C : OVC 0 -> 1");

            // 4. SBBU: ACC=0x80000000 - zext(loc16)=0 - ~C=1 (C=0) -> 0x7fffffff, OVC 0 -> -1
            testAddc16(emu, sp, SBBU, /*preOvc*/0, 0x80000000L, 0L, /*preC*/0L,
                0x7fffffffL, /*wantOvc*/-1L & 0xff,
                "SBBU -ve overflow via -~C : OVC 0 -> -1");

            // 5. MOVA T,loc16: P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testMovaFamily(emu, sp, MOVA_T, /*preOvc*/0, /*preAcc*/0x7fffffffL,
                /*preP*/1L, /*wantAcc*/0x80000000L, /*wantOvc*/1L, /*ovm*/0,
                "MOVA T,loc16 +ve overflow : OVC 0 -> 1");

            // 6. MOVA under OVM=1 : OVC unchanged.
            testMovaFamily(emu, sp, MOVA_T, 5, 0x7fffffffL, 1L, 0x80000000L,
                /*wantOvc*/5L, 1,
                "MOVA T,loc16 +ve overflow with OVM=1 : OVC unchanged");

            // 7. MOVAD T,loc16: P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testMovaFamily(emu, sp, MOVAD_T, 0, 0x7fffffffL, 1L, 0x80000000L,
                1L, 0, "MOVAD T,loc16 +ve overflow : OVC 0 -> 1");

            // 8. MOVS T,loc16: P=1, ACC=0x80000000 -> 0x7fffffff, OVC 0 -> -1
            testMovaFamily(emu, sp, MOVS_T, 0, 0x80000000L, 1L, 0x7fffffffL,
                -1L & 0xff, 0, "MOVS T,loc16 -ve overflow : OVC 0 -> -1");

            // 9. SQRA loc16: P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testSqrFamily(emu, sp, SQRA_W1, 0, 0x7fffffffL, 1L, 0x80000000L,
                1L, "SQRA loc16 +ve overflow : OVC 0 -> 1");

            // 10. SQRS loc16: P=1, ACC=0x80000000 -> 0x7fffffff, OVC 0 -> -1
            testSqrFamily(emu, sp, SQRS_W1, 0, 0x80000000L, 1L, 0x7fffffffL,
                -1L & 0xff, "SQRS loc16 -ve overflow : OVC 0 -> -1");

            // 11. XMAC P,loc16,*(pma): P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testXmacFamily(emu, sp, XMAC_W1, 0, 0x7fffffffL, 1L, 0x80000000L,
                1L, "XMAC P,loc16,*(pma) +ve overflow : OVC 0 -> 1");

            // 12. XMACD P,loc16,*(pma): P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testXmacFamily(emu, sp, XMACD_W1, 0, 0x7fffffffL, 1L, 0x80000000L,
                1L, "XMACD P,loc16,*(pma) +ve overflow : OVC 0 -> 1");

            // --- Group A (issue #97, 32x32 MAC forms) --------------------------
            // 13. QMPYAL P,XT,loc32: P=1, ACC=0x7fffffff -> 0x80000000, OVC 0 -> +1
            testXtL32(emu, sp, QMPYAL_W1, 0, 0x7fffffffL, 1L, 0x80000000L,
                1L, /*ovm*/0, "QMPYAL P,XT,loc32 +ve overflow : OVC 0 -> 1");

            // 14. QMPYSL P,XT,loc32: P=1, ACC=0x80000000 -> 0x7fffffff, OVC 0 -> -1
            testXtL32(emu, sp, QMPYSL_W1, 0, 0x80000000L, 1L, 0x7fffffffL,
                -1L & 0xff, 0, "QMPYSL P,XT,loc32 -ve overflow : OVC 0 -> -1");

            // 15. IMPYAL P,XT,loc32 unsigned carry: P=1, ACC=0xffffffff -> 0, OVC 0 -> +1 via OVCU
            testXtL32(emu, sp, IMPYAL_W1, 0, 0xffffffffL, 1L, 0L,
                1L, 0, "IMPYAL P,XT,loc32 unsigned carry : OVC 0 -> 1");

            // 16. IMPYAL under OVM=1 : OVCU still increments (SPRU430F: OVM does
            //     NOT affect OVCU). This is the negative test for the macro fix
            //     that removed the OVM gate from applyOvcUnsigned.
            testXtL32(emu, sp, IMPYAL_W1, 0, 0xffffffffL, 1L, 0L, 1L, /*ovm*/1,
                "IMPYAL unsigned carry with OVM=1 : OVC still 0 -> 1");

            // 17. IMPYL ACC,XT,loc32 N/Z: MOVL XT,#-1; loc32=+1; ACC = -1*1 = -1.
            //     N should be 1, Z should be 0. This tests the setNZ32 that was
            //     added while auditing the family for #97.
            testImpylAcc(emu, sp, IMPYL_ACC_W1, /*xt*/0xffffffffL, /*loc32*/1L,
                /*wantAcc*/0xffffffffL, /*wantN*/1L, /*wantZ*/0L,
                "IMPYL ACC : (-1)*1 -> -1, N=1 Z=0");

            if (failures == 0) {
                println("EmuMacOvcTest.java> PASS: MAC-family OVC accounting (17 cases)");
            } else {
                println("EmuMacOvcTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** SETC/CLRC OVM then ADDCL ACC,loc32 with loc32 via *-SP[1]. */
    private void testAddc32(EmulatorHelper emu, AddressSpace sp, long preOvc,
            long preAcc, long loc32val, long preC, long ovm,
            long wantAcc, long wantOvc, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("C", preC);
        emu.writeRegister("SP", SP_BASE);
        // *-SP[1] as loc32 -> two words at (SP-1) and SP.
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (loc32val >> 16) & 0xffffL);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ADDCL_W1);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        // First step is SETC/CLRC (single word); second is ADDCL (2 words).
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** ADDCU or SBBU (1-word op_hi8 opcode | loc16 byte). */
    private void testAddc16(EmulatorHelper emu, AddressSpace sp, long opHi,
            long preOvc, long preAcc, long loc16val, long preC,
            long wantAcc, long wantOvc, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("C", preC);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc16val & 0xffffL);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, opHi | LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** MOVA T / MOVAD T / MOVS T -- 1-word encoding, ACC ± P; loc16 side is a T load. */
    private void testMovaFamily(EmulatorHelper emu, AddressSpace sp, long opHi,
            long preOvc, long preAcc, long preP, long wantAcc, long wantOvc, long ovm,
            String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("P",   preP);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, 0L);  // T target = 0
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, opHi | LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** SQRA / SQRS -- 2-word encoding, ACC ± P then P = loc16 squared. */
    private void testSqrFamily(EmulatorHelper emu, AddressSpace sp, long w1,
            long preOvc, long preAcc, long preP, long wantAcc, long wantOvc,
            String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("P",   preP);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, 0L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** XMAC / XMACD -- 2-word encoding, ACC += P then P = loc16 * prog[0x3F:pma]. */
    private void testXmacFamily(EmulatorHelper emu, AddressSpace sp, long w1,
            long preOvc, long preAcc, long preP, long wantAcc, long wantOvc,
            String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("P",   preP);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, 0L);  // T source = 0
        // Pre-seed the pma target at 0x3F0100 (upper 6 bits forced to 0x3F).
        emu.writeMemoryValue(sp.getAddress((XPMA_HI_BASE + XPMA_LO) * 2), 2, 0L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, w1 | LOC_SP1);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, XPMA_LO);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** QMPYAL / QMPYSL / IMPYAL: 2-word, XT preloaded, loc32 via *-SP[1]. */
    private void testXtL32(EmulatorHelper emu, AddressSpace sp, long w1,
            long preOvc, long preAcc, long preP, long wantAcc, long wantOvc,
            long ovm, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("P",   preP);
        emu.writeRegister("XT",  0L);
        emu.writeRegister("SP",  SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, 0L);
        emu.writeMemoryValue(sp.getAddress(SP_BASE       * 2), 2, 0L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** IMPYL ACC,XT,loc32: pure multiply, check N/Z afterward. */
    private void testImpylAcc(EmulatorHelper emu, AddressSpace sp, long w1,
            long xt, long loc32val, long wantAcc, long wantN, long wantZ,
            String what) throws Exception {
        emu.writeRegister("ACC", 0L);
        emu.writeRegister("XT",  xt);
        emu.writeRegister("N",   wantN == 1 ? 0L : 1L);   // pre-seed opposite
        emu.writeRegister("Z",   wantZ == 1 ? 0L : 1L);
        emu.writeRegister("SP",  SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE       * 2), 2, (loc32val >> 16) & 0xffffL);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]",   emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]",   emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuMacOvcTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuMacOvcTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
