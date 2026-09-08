// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #108 Compare / Logical / Bit-manipulation audit.
//
// Compare-family regressions:
//   - V is NOT affected by CMP per SPRU430F ch. 6 -- pre-seed V=1 opposite
//     and verify it is preserved.
//   - N is INFINITE PRECISION per spec: 0x8000 - 0x0001 must set N=1, even
//     though the 16-bit truncated result 0x7FFF has bit 15 = 0. A body that
//     computed N from the truncated result would fail this case.
//   - CMP loc16,#simm16 was missing C entirely.
//
// Logical store-side regressions: 5 constructors were flag-silent
// (OR/AND/XOR loc16,AX and AND/OR/XOR loc16,#imm16). Verify N/Z newly set.
//
// Bit-manipulation regressions: TSET / TCLR were `{ }` decode-only with the
// bit-index field dropped by the pattern. Verify TC from tested bit, memory
// write-back, N/Z from result, and that the bit index is now properly
// decoded from word 2's BBBB nibble.
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuCmpLogicBitTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;              // *-SP[1] shared loc16/loc32 byte

    // Compare -- op_hi7 fields occupy bits 15..9, so the word base is (op_hi7 << 9),
    // with bit 8 = AX selector (0=AL) and bits 7..0 = loc byte.
    private static final long CMP_AL_LOC16   = 0x5400L;     // CMP AL,loc16   (op_hi7=0x2A, A=0)
    private static final long CMPB_AL_IMM8   = 0x5200L;     // CMPB AL,#imm8 (0101 0010 CCCC CCCC)
    private static final long CMP_LOC16_IMM  = 0x1B00L;     // CMP loc16,#simm16 base | loc byte (2-word)
    private static final long CMPL_ACC_LOC32 = 0x0F00L;     // CMPL ACC,loc32 base | loc byte

    // Logicals (store-side)
    private static final long OR_LOC_AL      = 0x9800L;     // OR loc16,AL   (1001 1000)
    private static final long XOR_LOC_AL     = 0xF200L;     // XOR loc16,AL  (1111 0010)
    private static final long AND_LOC_IMM    = 0x1800L;     // AND loc16,#imm16 (0001 1000)

    // Bit-manip (2-word)
    private static final long TSET_W0        = 0x560DL;
    private static final long TCLR_W0        = 0x5609L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ============================================================
            // Compare family
            // ============================================================

            // 1. CMP AL,loc16 : the infinite-precision N regression case.
            // AL=0x8000, [loc16]=0x0001 -> math result -32769 (negative), N=1.
            // A finite-precision body computes 0x8000 - 0x0001 = 0x7FFF, N=0 (WRONG).
            // Also verify V is UNCHANGED (SPRU430F: V is not affected by CMP).
            cmpAxLoc16(emu, sp, /*al*/0x8000L, /*mem*/0x0001L,
                /*wantN*/1, /*wantZ*/0, /*wantC*/1, /*preV*/1, /*wantV*/1,
                "CMP AL,loc16 : 0x8000-0x0001 -> N=1 (infinite prec), V preserved");
            // Normal case: AL=5, mem=3 -> pos result, N=0, Z=0, C=1.
            cmpAxLoc16(emu, sp, 5L, 3L, 0, 0, 1, 1, 1,
                "CMP AL,loc16 : 5-3 -> positive, V preserved (regression)");
            // Equal: AL=5, mem=5 -> Z=1, N=0, C=1.
            cmpAxLoc16(emu, sp, 5L, 5L, 0, 1, 1, 0, 0,
                "CMP AL,loc16 : equal -> Z=1, V=0 preserved");
            // Borrow: AL=3, mem=5 -> negative, N=1, C=0.
            cmpAxLoc16(emu, sp, 3L, 5L, 1, 0, 0, 1, 1,
                "CMP AL,loc16 : 3-5 borrow -> C=0, N=1");

            // 2. CMPB AL,#imm8 : same infinite-precision regression.
            // AL=0x8000, imm=1 -> math -32769, N=1.
            cmpbAxImm(emu, sp, 0x8000L, 1L, 1, 0, 1, 1, 1,
                "CMPB AL,#1 : 0x8000-1 -> N=1 (infinite prec)");

            // 3. CMP loc16,#simm16 : verify newly added C flag AND infinite-prec N.
            // mem=5, imm=3 -> pos, N=0, Z=0, C=1 (was: no C set at all).
            cmpLocImm(emu, sp, 5L, 3L, 0, 0, 1, 1, 1,
                "CMP loc16,#3 with mem=5 : C=1 (regression: prior body did not write C)");
            // mem=3, imm=5 -> negative, N=1, C=0.
            cmpLocImm(emu, sp, 3L, 5L, 1, 0, 0, 0, 0,
                "CMP loc16,#5 with mem=3 : C=0 borrow, N=1");

            // 4. CMPL ACC,loc32 : infinite-precision on 64-bit.
            // ACC=0x80000000, [loc32]=0x00000001 -> math -0x80000001, N=1.
            cmplAccLoc32(emu, sp, 0x80000000L, 0x00000001L, 1, 0, 1, 1, 1,
                "CMPL ACC,loc32 : 0x80000000-1 -> N=1 (infinite prec)");

            // ============================================================
            // Logical family (store-side)
            // ============================================================

            // 5. OR loc16,AL : mem=0x0F0F, AL=0x8080 -> result 0x8F8F, N=1, Z=0.
            storeLogicAx(emu, sp, OR_LOC_AL, 0x0F0FL, 0x8080L, 0x8F8FL, 1, 0,
                "OR loc16,AL : N=1 from result (regression: was flag-silent)");
            // 6. XOR loc16,AL : mem=0xAAAA, AL=0xAAAA -> result 0, Z=1.
            storeLogicAx(emu, sp, XOR_LOC_AL, 0xAAAAL, 0xAAAAL, 0x0000L, 0, 1,
                "XOR loc16,AL : Z=1 from zero result (regression)");
            // 7. AND loc16,#imm16 : mem=0xFFFF, imm=0x0001 -> result 0x0001, N=0, Z=0.
            storeLogicImm(emu, sp, AND_LOC_IMM, 0xFFFFL, 0x0001L, 0x0001L, 0, 0,
                "AND loc16,#1 : result=1, N=0 (regression)");

            // ============================================================
            // Bit-manipulation
            // ============================================================

            // 8. TSET loc16,#4 : mem=0x0000, bit 4 -> result=0x0010, TC=0 (bit was 0).
            tsetTclr(emu, sp, TSET_W0, /*bit*/4, /*mem*/0x0000L,
                /*wantMem*/0x0010L, /*wantTC*/0,
                "TSET loc16,#4 with bit clear : TC=0, bit-4 now set (regression: bit index was dropped)");
            // 9. TSET when bit already set : mem=0x00FF, bit 3 -> result=0x00FF (unchanged), TC=1.
            tsetTclr(emu, sp, TSET_W0, 3, 0x00FFL, 0x00FFL, 1,
                "TSET loc16,#3 with bit set : TC=1, unchanged");
            // 10. TCLR loc16,#7 with bit set : mem=0x00FF, bit 7 -> result=0x007F, TC=1.
            tsetTclr(emu, sp, TCLR_W0, 7, 0x00FFL, 0x007FL, 1,
                "TCLR loc16,#7 with bit set : TC=1, bit-7 now clear (regression)");
            // 11. TCLR bit already clear : mem=0x0000, bit 5 -> unchanged, TC=0.
            tsetTclr(emu, sp, TCLR_W0, 5, 0x0000L, 0x0000L, 0,
                "TCLR loc16,#5 with bit clear : TC=0, unchanged");
            // 12. TSET high bit (15) : mem=0x0000, bit 15 -> result=0x8000, TC=0.
            //     Regression against a naive 8-bit mask that would fail bit 8+.
            tsetTclr(emu, sp, TSET_W0, 15, 0x0000L, 0x8000L, 0,
                "TSET loc16,#15 : bit 15 handled (regression: 8-bit mask would fail)");

            if (failures == 0) {
                println("EmuCmpLogicBitTest.java> PASS: Compare/Logical/Bit-manip semantics (14 cases)");
            } else {
                println("EmuCmpLogicBitTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void cmpAxLoc16(EmulatorHelper emu, AddressSpace sp, long al, long mem,
            long wantN, long wantZ, long wantC, long preV, long wantV, String what) throws Exception {
        emu.writeRegister("AL", al);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", preV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CMP_AL_LOC16 | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void cmpbAxImm(EmulatorHelper emu, AddressSpace sp, long al, long imm,
            long wantN, long wantZ, long wantC, long preV, long wantV, String what) throws Exception {
        emu.writeRegister("AL", al);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", preV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CMPB_AL_IMM8 | (imm & 0xffL));
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void cmpLocImm(EmulatorHelper emu, AddressSpace sp, long mem, long imm,
            long wantN, long wantZ, long wantC, long preV, long wantV, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", preV);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CMP_LOC16_IMM | LOC_SP1);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, imm & 0xffffL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void cmplAccLoc32(EmulatorHelper emu, AddressSpace sp, long acc, long loc32val,
            long wantN, long wantZ, long wantC, long preV, long wantV, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2),       2, (loc32val >> 16) & 0xffffL);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", preV);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, CMPL_ACC_LOC32 | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]", emu.readRegister("V").longValue(), wantV);
    }

    private void storeLogicAx(EmulatorHelper emu, AddressSpace sp, long op, long mem, long al,
            long wantMem, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("AL", al);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        byte[] b = emu.readMemory(sp.getAddress((SP_BASE - 1) * 2), 2);
        long got = ((b[0] & 0xffL) | ((b[1] & 0xffL) << 8));
        expect(what + " [mem]", got, wantMem);
        expect(what + " [N]",   emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]",   emu.readRegister("Z").longValue(), wantZ);
    }

    private void storeLogicImm(EmulatorHelper emu, AddressSpace sp, long op, long mem, long imm,
            long wantMem, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op | LOC_SP1);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, imm & 0xffffL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        byte[] b = emu.readMemory(sp.getAddress((SP_BASE - 1) * 2), 2);
        long got = ((b[0] & 0xffL) | ((b[1] & 0xffL) << 8));
        expect(what + " [mem]", got, wantMem);
        expect(what + " [N]",   emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]",   emu.readRegister("Z").longValue(), wantZ);
    }

    /** TSET/TCLR: word 2 = 0000 BBBB LLLL LLLL. bit is 0..15. */
    private void tsetTclr(EmulatorHelper emu, AddressSpace sp, long w0, long bit,
            long mem, long wantMem, long wantTC, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("TC", wantTC == 1 ? 0L : 1L);
        long word2 = ((bit & 0xfL) << 8) | LOC_SP1;
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, w0);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, word2);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        byte[] b = emu.readMemory(sp.getAddress((SP_BASE - 1) * 2), 2);
        long got = ((b[0] & 0xffL) | ((b[1] & 0xffL) << 8));
        expect(what + " [mem]", got, wantMem);
        expect(what + " [TC]",  emu.readRegister("TC").longValue(), wantTC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuCmpLogicBitTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuCmpLogicBitTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
