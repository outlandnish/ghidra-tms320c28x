// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the OVC (Overflow Counter) modelling landed for issue #93.
// Covers the four semantic surfaces:
//   1. Signed ADDL: OVC increments on +ve overflow, decrements on -ve overflow.
//   2. Unsigned ADDUL: OVC increments on unsigned carry.
//   3. OVM=1 suppresses OVC updates on both paths.
//   4. SAT ACC saturates ACC per OVC direction and clears OVC (issue #93's main reader).
//   5. ZAPA clears OVC alongside ACC/P.
//   6. MOVU loc16,OVC stores the actual counter value (was: literal 0 -- bug fixed).
//
// Each case pre-seeds OVC to a value that contradicts the expected outcome, so a body
// that leaves OVC alone can't accidentally pass.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuOvcTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuOvcTest extends GhidraScript {

    private static final long CODE = 0xc100L;         // GS RAM on the F28377D map
    private static final long ADDL_ACC_LOC32 = 0x0700L;  // ADDL ACC,loc32  | loc byte
    private static final long ADDUL_ACC_LOC32 = 0x5653L; // ADDUL ACC,loc32 (2-word)
    private static final long SUBUL_ACC_LOC32 = 0x5655L; // SUBUL ACC,loc32 (2-word)
    private static final long ADDUL_P_LOC32   = 0x5657L; // ADDUL P,loc32   (2-word)
    private static final long SUBUL_P_LOC32   = 0x565DL; // SUBUL P,loc32   (2-word)
    private static final long SETC_OVM = 0x3B02L;
    private static final long CLRC_OVM = 0x2902L;
    private static final long SAT_ACC  = 0xFF57L;
    private static final long ZAPA     = 0x5633L;
    private static final long MOVU_LOC_OVC = 0x5628L;    // MOVU loc16,OVC (2-word)
    private static final long LOC_SP1  = 0x41L;          // *-SP[1] loc byte
    private static final long SP_BASE  = 0x8000L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. Signed +ve overflow: ADDL ACC=0x7fffffff, [loc32]=1 -> 0x80000000. OVC += 1.
            //    Pre-seed OVC=0 so the +1 is measurable; OVM off so counter updates.
            testAddl(emu, sp, /*ovm*/0, /*preOvc*/0, /*acc*/0x7fffffffL, /*loc32*/1L,
                /*wantOvc*/1L, /*wantAcc*/0x80000000L,
                "ADDL +ve overflow : OVC 0 -> 1");

            // 2. Signed -ve overflow: ADDL ACC=0x80000000, [loc32]=0xffffffff -> 0x7fffffff. OVC -= 1.
            testAddl(emu, sp, 0, 0, 0x80000000L, 0xffffffffL,
                (long) -1 & 0xff, 0x7fffffffL,
                "ADDL -ve overflow : OVC 0 -> -1");

            // 3. OVM=1 suppresses: same setup as case 1, but with OVM set, OVC must stay 0.
            testAddl(emu, sp, 1, 0, 0x7fffffffL, 1L,
                0L, 0x80000000L,
                "ADDL +ve overflow with OVM=1 : OVC unchanged");

            // 4. Unsigned carry: ADDUL 0xffffffff + 1 -> 0. OVC += 1 via applyOvcUnsigned.
            testAddul(emu, sp, /*preOvc*/0, /*acc*/0xffffffffL, /*loc32*/1L,
                /*wantOvc*/1L, "ADDUL unsigned carry : OVC 0 -> 1");

            // 5. Unsigned no-carry: 5 + 3 = 8. No OVC change.
            testAddul(emu, sp, 5, 5L, 3L, 5L, "ADDUL no carry : OVC 5 unchanged");

            // 5b. ADDUL with OVM=1 : OVCU still increments -- SPRU430F is explicit
            //     that "The OVM mode does not affect the OVCU counter" (see the OVCU
            //     row on the ADDUL page). Negative test for the OVM-gate that was
            //     erroneously present on applyOvcUnsigned until #97's Group A audit.
            testAddulOvm(emu, sp, /*preOvc*/0, /*acc*/0xffffffffL, /*loc32*/1L,
                /*wantOvc*/1L, "ADDUL unsigned carry with OVM=1 : OVC still 0 -> 1");

            // --- issue #98: SUBUL / ADDUL P get OVCU too --------------------
            // 5c. SUBUL ACC borrow decrement. ACC=0 - 1 -> 0xffffffff, borrow => OVC 0 -> -1.
            //     Regression test for a real bug: the shipped body used applyOvcSigned;
            //     SPRU430F ch. 6 is explicit ("The overflow counter is DECREMENTED
            //     whenever a subtraction operation generates an unsigned borrow. The OVM
            //     mode does not affect the OVCU counter"). Table 2-5 misgroups SUBUL under
            //     "Signed Subtraction" -- individual page is authoritative.
            testUnsignedSub(emu, sp, SUBUL_ACC_LOC32, /*isP*/false, /*preOvc*/0,
                /*pre*/0L, /*loc32*/1L, /*want*/0xffffffffL, /*wantOvc*/-1L & 0xff, /*ovm*/0,
                "SUBUL ACC borrow : OVC 0 -> -1");

            // 5d. SUBUL ACC borrow with OVM=1 : OVCU still decrements (OVCU-ignores-OVM).
            testUnsignedSub(emu, sp, SUBUL_ACC_LOC32, false, 0, 0L, 1L,
                0xffffffffL, -1L & 0xff, /*ovm*/1,
                "SUBUL ACC borrow with OVM=1 : OVC still 0 -> -1");

            // 5e. ADDUL P carry increment. P=0xffffffff + 1 -> 0, carry => OVC 0 -> +1.
            testUnsignedAdd(emu, sp, ADDUL_P_LOC32, /*isP*/true, 0, 0xffffffffL, 1L,
                0L, 1L, /*ovm*/0,
                "ADDUL P unsigned carry : OVC 0 -> 1");

            // 5f. SUBUL P borrow decrement. P=0 - 1 -> 0xffffffff, borrow => OVC 0 -> -1.
            testUnsignedSub(emu, sp, SUBUL_P_LOC32, /*isP*/true, 0, 0L, 1L,
                0xffffffffL, -1L & 0xff, 0,
                "SUBUL P borrow : OVC 0 -> -1");

            // 6. SAT ACC with OVC > 0 : saturate to 0x7FFFFFFF, clear OVC, V=1.
            testSat(emu, sp, /*preOvc*/3, /*preAcc*/0x11111111L,
                /*wantOvc*/0, /*wantAcc*/0x7FFFFFFFL, /*wantV*/1,
                "SAT ACC : OVC>0 -> saturate high, OVC clear");

            // 7. SAT ACC with OVC < 0 : saturate to 0x80000000, clear OVC, V=1.
            testSat(emu, sp, (long) -3 & 0xff, 0x11111111L, 0, 0x80000000L, 1,
                "SAT ACC : OVC<0 -> saturate low, OVC clear");

            // 8. SAT ACC with OVC == 0 : ACC unchanged, V=0.
            testSat(emu, sp, 0, 0x12345678L, 0, 0x12345678L, 0,
                "SAT ACC : OVC=0 -> ACC unchanged, V clear");

            // 9. ZAPA clears OVC alongside ACC and P.
            emu.writeRegister("ACC", 0xdeadbeefL);
            emu.writeRegister("P", 0xcafef00dL);
            emu.writeRegister("OVC", 7L);
            long here = codeCursor; codeCursor += 4;
            emu.writeMemoryValue(sp.getAddress(here * 2), 2, ZAPA);
            emu.writeRegister("PC", here);
            if (!emu.step(monitor)) fail("ZAPA", emu.getLastError());
            expect("ZAPA [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, 0L);
            expect("ZAPA [P]",   emu.readRegister("P").longValue() & 0xffffffffL,   0L);
            expect("ZAPA [OVC]", emu.readRegister("OVC").longValue() & 0xffL,       0L);

            // 10. MOVU loc16,OVC stores actual OVC (was: literal 0).
            emu.writeRegister("OVC", 0x2AL);   // 42 (fits in 6 bits)
            emu.writeRegister("SP", SP_BASE);
            emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, 0xFFFFL);  // scratch pre-seeded
            here = codeCursor; codeCursor += 6;
            emu.writeMemoryValue(sp.getAddress(here * 2), 2, MOVU_LOC_OVC);
            emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, LOC_SP1);
            emu.writeRegister("PC", here);
            if (!emu.step(monitor)) fail("MOVU loc,OVC", emu.getLastError());
            byte[] mem = emu.readMemory(sp.getAddress((SP_BASE - 1) * 2), 2);
            long stored = ((mem[0] & 0xffL) | ((mem[1] & 0xffL) << 8));  // little-endian
            expect("MOVU loc,OVC : stored OVC low 6b, upper 10 zero", stored, 0x002AL);

            if (failures == 0) {
                println("EmuOvcTest.java> PASS: OVC model (15 cases)");
            } else {
                println("EmuOvcTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** Set OVM via SETC/CLRC then ADDL ACC,loc32 with loc32 via *-SP[1]. */
    private void testAddl(EmulatorHelper emu, AddressSpace sp, long ovm, long preOvc,
            long preAcc, long loc32val, long wantOvc, long wantAcc, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("SP", SP_BASE);
        // *-SP[1] as loc32 reads 32 bits starting at (SP-1) -> two words at (SP-1) and SP.
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (loc32val >> 16) & 0xffffL);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ADDL_ACC_LOC32 | LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** ADDUL ACC,loc32 with OVM off. */
    private void testAddul(EmulatorHelper emu, AddressSpace sp, long preOvc, long preAcc,
            long loc32val, long wantOvc, String what) throws Exception {
        testAddulOvmGate(emu, sp, preOvc, preAcc, loc32val, wantOvc, 0, what);
    }

    /** ADDUL ACC,loc32 with OVM on -- for the OVCU-ignores-OVM regression. */
    private void testAddulOvm(EmulatorHelper emu, AddressSpace sp, long preOvc, long preAcc,
            long loc32val, long wantOvc, String what) throws Exception {
        testAddulOvmGate(emu, sp, preOvc, preAcc, loc32val, wantOvc, 1, what);
    }

    private void testAddulOvmGate(EmulatorHelper emu, AddressSpace sp, long preOvc,
            long preAcc, long loc32val, long wantOvc, long ovm, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (loc32val >> 16) & 0xffffL);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ADDUL_ACC_LOC32);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** Generic ADDUL/SUBUL for #98 -- either ACC or P destination, either OVM. */
    private void testUnsignedAdd(EmulatorHelper emu, AddressSpace sp, long opW1,
            boolean isP, long preOvc, long pre, long loc32val, long want,
            long wantOvc, long ovm, String what) throws Exception {
        runOvcuOp(emu, sp, opW1, isP, preOvc, pre, loc32val, want, wantOvc, ovm, what);
    }
    private void testUnsignedSub(EmulatorHelper emu, AddressSpace sp, long opW1,
            boolean isP, long preOvc, long pre, long loc32val, long want,
            long wantOvc, long ovm, String what) throws Exception {
        runOvcuOp(emu, sp, opW1, isP, preOvc, pre, loc32val, want, wantOvc, ovm, what);
    }
    private void runOvcuOp(EmulatorHelper emu, AddressSpace sp, long opW1,
            boolean isP, long preOvc, long pre, long loc32val, long want,
            long wantOvc, long ovm, String what) throws Exception {
        String reg = isP ? "P" : "ACC";
        emu.writeRegister(reg, pre);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("SP",  SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2),       2, (loc32val >> 16) & 0xffffL);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, ovm == 1 ? SETC_OVM : CLRC_OVM);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, opW1);
        emu.writeMemoryValue(sp.getAddress((here + 2) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        for (int i = 0; i < 2; i++) {
            if (!emu.step(monitor)) { fail(what, "step " + i + ": " + emu.getLastError()); return; }
        }
        expect(what + " [" + reg + "]",
            emu.readRegister(reg).longValue() & 0xffffffffL, want);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
    }

    /** Pre-seed OVC, run SAT ACC, check ACC/OVC/V. */
    private void testSat(EmulatorHelper emu, AddressSpace sp, long preOvc, long preAcc,
            long wantOvc, long wantAcc, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("OVC", preOvc);
        emu.writeRegister("V", wantV == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, SAT_ACC);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0xffL, wantOvc & 0xffL);
        expect(what + " [V]",   emu.readRegister("V").longValue(), wantV);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuOvcTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuOvcTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
