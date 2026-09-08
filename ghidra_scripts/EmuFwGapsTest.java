// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #118 fw-parity gap fills. Covers the constructors added
// in this PR that carry runtime-observable flag semantics:
//
//   AND ACC, #16bit << #0..15   -- N/Z from ACC after masked-shift AND
//   AND ACC, #16bit << #16      -- same
//   TBIT loc16, #bit            -- TC from bit `bit` of [loc16]
//   TBIT loc16, T               -- TC from bit `15 - T[3:0]` of [loc16] (reversed index!)
//
// MOVB AR6/AR7 and MOV DP,#10bit have no flag effects per SPRU430F; their correctness
// is exercised by the disasm fixture, not here.
//
// Every case pre-seeds the asserted flag to its opposite so a body that leaves it alone
// (the pre-fix state = <UNDEF>) fails.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuFwGapsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFwGapsTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // AND ACC, #16bit << #0..15
            // ACC = 0xFFFFFFFF, mask #0x8000 << #0 -> ACC = 0x00008000, N=0 Z=0.
            andAccImm(emu, sp, /*acc*/0xFFFFFFFFL, /*imm*/0x8000L, /*shft*/0L,
                /*wantAcc*/0x00008000L, /*wantN*/0, /*wantZ*/0,
                "AND ACC,#0x8000<<#0 : N=0 Z=0");
            // ACC = 0x80000000, mask #0x8000 << #16 -> ACC = 0x80000000, N=1 Z=0.
            andAccImmShift16(emu, sp, 0x80000000L, 0x8000L,
                0x80000000L, 1, 0,
                "AND ACC,#0x8000<<#16 : N=1 (bit 31 survived)");
            // ACC = 0x0FFF0000, mask #0x0FFF << #4 -> ACC & 0x0FFF0 = 0. Z=1.
            andAccImm(emu, sp, 0x0FFF0000L, 0x0FFFL, 4L,
                0x00000000L, 0, 1,
                "AND ACC,#0xFFF<<#4 : Z=1 (regression: was <UNDEF>)");

            // TBIT loc16, #bit
            // mem = 0x8080, bit 7 -> TC = 1.
            tbitImm(emu, sp, /*mem*/0x8080L, /*bit*/7, /*wantTC*/1,
                "TBIT *-SP[1],#7 : bit 7 set -> TC=1");
            // mem = 0x8080, bit 6 -> TC = 0.
            tbitImm(emu, sp, 0x8080L, 6, 0,
                "TBIT *-SP[1],#6 : bit 6 clear -> TC=0");
            // mem = 0x8000, bit 15 -> TC = 1 (regression: naive 8-bit mask would fail).
            tbitImm(emu, sp, 0x8000L, 15, 1,
                "TBIT *-SP[1],#15 : bit 15 set -> TC=1");

            // TBIT loc16, T  (T[3:0]=0 corresponds to bit 15, T[3:0]=15 corresponds to bit 0)
            // mem = 0x8000, T = 0 -> tested bit = 15 -> TC = 1.
            tbitT(emu, sp, /*mem*/0x8000L, /*t*/0L, /*wantTC*/1,
                "TBIT *-SP[1],T (T=0) : reversed idx -> bit 15 -> TC=1");
            // mem = 0x0001, T = 15 -> tested bit = 0 -> TC = 1.
            tbitT(emu, sp, 0x0001L, 15L, 1,
                "TBIT *-SP[1],T (T=15) : reversed idx -> bit 0 -> TC=1");
            // mem = 0x0080, T = 8 -> tested bit = 7 -> TC = 1.
            tbitT(emu, sp, 0x0080L, 8L, 1,
                "TBIT *-SP[1],T (T=8) : reversed idx -> bit 7 -> TC=1");
            // Upper T bits ignored: mem = 0x0080, T = 0xFF08 -> bit 7 -> TC=1.
            tbitT(emu, sp, 0x0080L, 0xFF08L, 1,
                "TBIT *-SP[1],T (T=0xFF08) : upper bits ignored, bit 7 -> TC=1");

            if (failures == 0) {
                println("EmuFwGapsTest.java> PASS: AND ACC,#imm<<# + TBIT semantics (issue #118, 10 cases)");
            } else {
                println("EmuFwGapsTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void andAccImm(EmulatorHelper emu, AddressSpace sp, long acc, long imm, long shft,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        // AND ACC,#imm<<#SHFT : op_hi8=0x3E, loc_hi4=0, shft4 in bits 0..3, imm in word2.
        emu.writeMemoryValue(sp.getAddress(here * 2),       2, 0x3E00L | (shft & 0xfL));
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, imm & 0xffffL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void andAccImmShift16(EmulatorHelper emu, AddressSpace sp, long acc, long imm,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2),       2, 0x5608L);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, imm & 0xffffL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void tbitImm(EmulatorHelper emu, AddressSpace sp, long mem, long bit, long wantTC,
            String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("TC", wantTC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        // TBIT loc16,#bit : 0100 BBBB LLLL LLLL -> word = 0x4000 | (bit<<8) | loc.
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x4000L | ((bit & 0xfL) << 8) | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [TC]", emu.readRegister("TC").longValue(), wantTC);
    }

    private void tbitT(EmulatorHelper emu, AddressSpace sp, long mem, long tval, long wantTC,
            String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeRegister("T", tval);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("TC", wantTC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        // TBIT loc16,T : word1 = 0x5625, word2 = 0000 0000 LLLL LLLL.
        emu.writeMemoryValue(sp.getAddress(here * 2),       2, 0x5625L);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [TC]", emu.readRegister("TC").longValue(), wantTC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuFwGapsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuFwGapsTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
