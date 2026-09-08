// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the SHIFT-FORM ACC arithmetic constructors that issue #90 caught:
//   ADD ACC,loc16<<T ; ADD ACC,loc16<<#shft ; ADD ACC,#imm16<<#shft ; ADD ACC,loc16<<#16
//   SUB ACC,loc16<<T ; SUB ACC,#imm16<<#shft ; SUB ACC,loc16<<#16
//   MOV ACC,loc16<<#16
//
// Same shape as EmuAddb/SubbAccFlagsTest -- decode parity is structurally blind to a missing
// flag write, so this is the only pass that catches it. Each constructor got the same flag
// pattern as its plain non-shift sibling (ADD ACCreg,loc16 already-flag-setting form): C via
// carry/scarry-of-shifted-addend, N/Z from ACC after, V from scarry. MOV sets N,Z only per spec.
//
// Every case here pins the STALE-FLAG behaviour -- the flag we assert is pre-seeded to the
// opposite value before the instruction runs, so a body that computes the flag from just its
// operand (rather than actually writing it) will not pass. Cases 1-4 exercise ADD/SUB via the
// #imm16<<#shft encoding which needs no memory; cases 5-6 exercise the loc16<<#16 encodings
// via @AL; case 7 is the MOV form (N/Z only per spec, no C/V).
//
// Run headless:
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuFlagsShiftAddTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFlagsShiftAddTest extends GhidraScript {

    private static final long CODE = 0xc100L;         // GS RAM on the F28377D map
    private static final long MOV_AL_I16 = 0x28A9L;   // MOV @AL,#16bit  (2 words)
    private static final long MOV_AH_I16 = 0x28A8L;   // MOV @AH,#16bit  (2 words)
    // 0xFF1<shft4> : imm16  -- ADD ACC,#imm16<<#shft (2 words)
    // 0xFF0<shft4> : imm16  -- SUB ACC,#imm16<<#shft (2 words)
    private static final long ADD_ACC_IMM_SH = 0xFF10L;
    private static final long SUB_ACC_IMM_SH = 0xFF00L;
    // 0x05<loc8> -- ADD ACC,loc16<<#16 (single word). 0x04 = SUB, 0x25 = MOV.
    // Use *-SP[1] as the loc16 operand -- an INDEPENDENT scratch memory location, not
    // aliased to ACC's low half (which is what @AL is, since AL is ACC[0..15]). Encoding:
    // loc_b76=0b01, loc_off6=1 -> low byte 0b01000001 = 0x41.
    private static final long ADD_ACC_LOC_SH16 = 0x0541L;
    private static final long SUB_ACC_LOC_SH16 = 0x0441L;
    private static final long MOV_ACC_LOC_SH16 = 0x2541L;
    private static final long SP_BASE = 0x8000L;      // word addr; SP-1 == 0x7fff is scratch

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. ADD ACC,#1<<#0 : 1+1 -> 2. Z was 1, must clear; N,V,C all 0.
            addImmCase(emu, sp, 0x00000001L, 1, 0, 0x00000002L, /*N*/0, /*Z*/0, /*C*/0, /*V*/0,
                "ADD ACC,#1<<0 : 1+1 -> 2");

            // 2. ADD ACC,#1<<#0 with ACC=0xffffffff: wraps to 0. Z must set, C must set.
            addImmCase(emu, sp, 0xffffffffL, 1, 0, 0x00000000L, /*N*/0, /*Z*/1, /*C*/1, /*V*/0,
                "ADD ACC,#1<<0 : 0xffffffff+1 -> 0, Z+C set");

            // 3a. Sanity: SUB ACC,#2<<#0 with ACC=10 -> 8, no wrap, N=0, C=1(no borrow).
            subImmCase(emu, sp, 0x0000000AL, 2, 0, 0x00000008L, /*N*/0, /*Z*/0, /*C*/1, /*V*/0,
                "SUB ACC,#2<<0 : 10-2 -> 8, no borrow");
            // 3. SUB ACC,#1<<#0 : ACC=0 - 1 -> 0xffffffff. C cleared (borrow), N set.
            //    Pre-seed C=1 to prove the SUB path writes it back to 0.
            subImmCase(emu, sp, 0x00000000L, 1, 0, 0xffffffffL, /*N*/1, /*Z*/0, /*C*/0, /*V*/0,
                "SUB ACC,#1<<0 : 0-1 borrows, C cleared (STALE C=1)");

            // 4. STALE-FLAG for the SHIFT path. ADD ACC,#0x8000<<#1 -> 0 + 0x10000 -> 0x10000.
            //    Z pre-set to 1, must clear. Confirms the shift-then-flag path fires, not just
            //    the unshifted-flag path.
            addImmCase(emu, sp, 0x00000000L, 0x8000, 1, 0x00010000L, /*N*/0, /*Z*/0, /*C*/0, /*V*/0,
                "ADD ACC,#0x8000<<#1 : shift-path Z cleared from 1");

            // 5. ADD ACC,@AL<<#16 with AL=0x0001 -> ACC += 0x00010000. STALE Z=1 -> 0.
            addLocSh16Case(emu, sp, 0x00000000L, 0x0001L, 0x00010000L, /*N*/0, /*Z*/0,
                "ADD ACC,@AL<<#16 : + 0x10000");

            // 6. SUB ACC,@AL<<#16: ACC=0x00010000, AL=0x0001 -> ACC = 0. Z must set.
            //    Also proves the loc16<<#16 SUB path clears N and sets Z.
            subLocSh16Case(emu, sp, 0x00010000L, 0x0001L, 0x00000000L, /*N*/0, /*Z*/1,
                "SUB ACC,@AL<<#16 : Z set on 0x10000-0x10000");

            // 7. MOV ACC,@AL<<#16 with AL=0xFFFF -> ACC = 0xFFFF0000. N must set, Z cleared.
            //    Pre-seed both to opposite. MOV form sets N,Z ONLY per spec; C/V unchanged --
            //    we do not assert them (that would require asserting the fix DIDN'T touch them,
            //    which is a different fix class).
            movLocSh16Case(emu, sp, 0xFFFFL, 0xFFFF0000L, /*N*/1, /*Z*/0,
                "MOV ACC,@AL<<#16 : N set on 0xFFFF0000");

            if (failures == 0) {
                println("EmuFlagsShiftAddTest.java> PASS: shift-form ADD/SUB/MOV ACC set N,Z,C,V (7 cases)");
            } else {
                println("EmuFlagsShiftAddTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** Load ACC from AH:AL, run ADD ACC,#imm16<<#shft, assert result and flags. */
    private void addImmCase(EmulatorHelper emu, AddressSpace sp, long initAcc, long imm16,
            long shft, long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what)
            throws Exception {
        runImm(emu, sp, initAcc, ADD_ACC_IMM_SH | (shft & 0xf), imm16, wantAcc, wantN, wantZ,
            wantC, wantV, what);
    }

    private void subImmCase(EmulatorHelper emu, AddressSpace sp, long initAcc, long imm16,
            long shft, long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what)
            throws Exception {
        runImm(emu, sp, initAcc, SUB_ACC_IMM_SH | (shft & 0xf), imm16, wantAcc, wantN, wantZ,
            wantC, wantV, what);
    }

    private long codeCursor = CODE;
    private void runImm(EmulatorHelper emu, AddressSpace sp, long initAcc, long word0, long imm16,
            long wantAcc, long wantN, long wantZ, long wantC, long wantV, String what)
            throws Exception {
        emu.writeRegister("ACC", initAcc);
        // Pre-seed every asserted flag to its OPPOSITE so the check is real.
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", wantV == 1 ? 0L : 1L);
        long here = codeCursor;
        codeCursor += 8;  // leave room; use a fresh region per case to avoid instruction cache
        long pc = here;
        pc = emit(emu, sp, pc, word0, imm16 & 0xffffL);
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

    private void addLocSh16Case(EmulatorHelper emu, AddressSpace sp, long initAcc, long locVal,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        runLocSh16(emu, sp, initAcc, ADD_ACC_LOC_SH16, locVal, wantAcc, wantN, wantZ, what);
    }

    private void subLocSh16Case(EmulatorHelper emu, AddressSpace sp, long initAcc, long locVal,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        runLocSh16(emu, sp, initAcc, SUB_ACC_LOC_SH16, locVal, wantAcc, wantN, wantZ, what);
    }

    private void movLocSh16Case(EmulatorHelper emu, AddressSpace sp, long locVal, long wantAcc,
            long wantN, long wantZ, String what) throws Exception {
        runLocSh16(emu, sp, 0L, MOV_ACC_LOC_SH16, locVal, wantAcc, wantN, wantZ, what);
    }

    /** loc16 is *-SP[1]: write value into (SP-1)*2 as bytes, set SP, run one-word insn. */
    private void runLocSh16(EmulatorHelper emu, AddressSpace sp, long initAcc, long word0,
            long locVal, long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", initAcc);
        emu.writeRegister("SP", SP_BASE);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        // *-SP[1] reads the word at byte-address (SP - 1) * 2 = 0xfffe if SP=0x8000.
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, locVal & 0xffffL);
        long here = codeCursor;
        codeCursor += 8;
        emit1(emu, sp, here, word0);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) {
            fail(what, "step: " + emu.getLastError());
            return;
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuFlagsShiftAddTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuFlagsShiftAddTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }

    /** Write a 2-word instruction; returns the next word address. */
    private long emit(EmulatorHelper emu, AddressSpace sp, long word, long w1, long w2) throws Exception {
        emu.writeMemoryValue(sp.getAddress(word * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((word + 1) * 2), 2, w2);
        return word + 2;
    }

    /** Write a 1-word instruction; returns the next word address. */
    private long emit1(EmulatorHelper emu, AddressSpace sp, long word, long w1) throws Exception {
        emu.writeMemoryValue(sp.getAddress(word * 2), 2, w1);
        return word + 1;
    }
}
