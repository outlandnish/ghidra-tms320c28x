// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for four FPU semantics that decode parity cannot see (SPRUHS1C):
//
//   FRACF32        the fractional part, sign kept: 19.625 -> 0.625, -2.75 -> -0.75. The old
//                  body float-subtracted trunc()'s INTEGER bits, so any value with an integer
//                  part came out as garbage.
//   F32TOI16R      round to nearest, ties to even (1.7 -> 2, -1.7 -> -2, 2.5 -> 2, 3.5 -> 4);
//                  it used to truncate.
//   F32TOUI16(R)   saturate to [0, 65535] before converting (300000 -> 65535, negative -> 0);
//                  it used to wrap.
//   MACF32 || MOV32  the multiply reads its sources before the accumulate writes R3H/R7H,
//                  so `MACF32 R3H,R2H,R2H,R3H,R0H` multiplies the OLD R3H.
//   RPT || MACF32 R7H,R3H,mem32,*XAR7++  alternates the R3H/R2H and R7H/R6H pairs on every
//                  iteration (p.68). It used to put every product through R3H/R2H. A
//                  standalone MACF32 is the negative control: R3H/R2H only, R6H/R7H untouched.
//
// Host-driven: writes the instruction words into emulator memory and steps, so any
// TMS320C28x program will do as the import target.
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuFpuConvMacTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFpuConvMacTest extends GhidraScript {

    private static final long CODE = 0xc200L;
    private static final long SP_BASE = 0x8000L;

    private int failures = 0;
    private int cases = 0;
    private AddressSpace space;

    @Override
    public void run() throws Exception {
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // --- FRACF32 R1H,R0H  (E6F1 / 0001) ----------------------------------------
            conv(emu, 0xE6F1, 0x0001, 19.625f,  bits(0.625f),  "FRACF32 19.625");
            conv(emu, 0xE6F1, 0x0001, -2.75f,   bits(-0.75f),  "FRACF32 -2.75 keeps the sign");
            conv(emu, 0xE6F1, 0x0001, 0.25f,    bits(0.25f),   "FRACF32 0.25 (no integer part)");
            conv(emu, 0xE6F1, 0x0001, 1.0e10f,  bits(0.0f),    "FRACF32 1e10 (beyond int32)");

            // --- F32TOI16R R1H,R0H  (E68C / 8001) --------------------------------------
            conv(emu, 0xE68C, 0x8001, 1.7f,  2L,          "F32TOI16R 1.7 -> 2");
            conv(emu, 0xE68C, 0x8001, -1.7f, 0xFFFFFFFEL, "F32TOI16R -1.7 -> -2, sign-extended");
            conv(emu, 0xE68C, 0x8001, 2.5f,  2L,          "F32TOI16R 2.5 -> 2 (tie to even)");
            conv(emu, 0xE68C, 0x8001, 3.5f,  4L,          "F32TOI16R 3.5 -> 4 (tie to even)");
            conv(emu, 0xE68C, 0x8001, -2.5f, 0xFFFFFFFEL, "F32TOI16R -2.5 -> -2 (tie to even)");
            // Truncating sibling is unchanged.
            conv(emu, 0xE68C, 0x0001, 1.7f,  1L,          "F32TOI16 1.7 -> 1 (truncate)");

            // --- F32TOUI16 R1H,R0H  (E68E / 0001) --------------------------------------
            conv(emu, 0xE68E, 0x0001, 300000f, 0xFFFFL, "F32TOUI16 300000 saturates to 65535");
            conv(emu, 0xE68E, 0x0001, -5.0f,   0L,      "F32TOUI16 -5 saturates to 0");
            conv(emu, 0xE68E, 0x0001, 123.9f,  123L,    "F32TOUI16 123.9 -> 123");
            conv(emu, 0xE68E, 0x0001, 65535f,  0xFFFFL, "F32TOUI16 65535 exactly");

            // --- F32TOUI16R R1H,R0H  (E68E / 8001) -------------------------------------
            conv(emu, 0xE68E, 0x8001, 300000f,  0xFFFFL, "F32TOUI16R 300000 saturates");
            conv(emu, 0xE68E, 0x8001, -0.4f,    0L,      "F32TOUI16R -0.4 -> 0");
            conv(emu, 0xE68E, 0x8001, 2.5f,     2L,      "F32TOUI16R 2.5 -> 2 (tie to even)");
            conv(emu, 0xE68E, 0x8001, 1.5f,     2L,      "F32TOUI16R 1.5 -> 2 (tie to even)");
            conv(emu, 0xE68E, 0x8001, 65534.6f, 0xFFFFL, "F32TOUI16R 65534.6 -> 65535");

            // --- parallel MACF32 with the accumulator as a multiply source --------------
            // MACF32 R3H,R2H,R2H,R3H,R0H || MOV32 R1H,*-SP[2]
            //   LSW 0xE330 (rf=R0, re_hi=0)  MSW re_lo=3, rd=R2, ra=R1, loc32=0x42
            parallelMac(emu, 0xE330, 0xD142, "R3H", "R2H",
                "MACF32 R3H,R2H,R2H,R3H,R0H multiplies the old R3H");
            // MACF32 R7H,R6H,R6H,R7H,R0H || MOV32 R1H,*-SP[2]
            parallelMac(emu, 0xE3C1, 0xF142, "R7H", "R6H",
                "MACF32 R7H,R6H,R6H,R7H,R0H multiplies the old R7H");

            // --- RPT #3 || MACF32 R7H,R3H,*XAR6++,*XAR7++ -------------------------------
            repeatedMac(emu);
            standaloneMac(emu);

            if (failures == 0) {
                println("EmuFpuConvMacTest.java> PASS: FRACF32, F32TO(U)I16(R), MACF32 ordering"
                    + " and RPT alternation (" + cases + " cases)");
            } else {
                println("EmuFpuConvMacTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private long cursor = CODE;

    /** Place a two-word instruction at a fresh address and step it once. */
    private boolean stepAt(EmulatorHelper emu, int lsw, int msw, String what) throws Exception {
        long here = cursor;
        cursor += 2;
        emu.writeMemoryValue(space.getAddress(here * 2), 2, lsw);
        emu.writeMemoryValue(space.getAddress((here + 1) * 2), 2, msw);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) {
            fail(what, emu.getLastError());
            return false;
        }
        return true;
    }

    private void conv(EmulatorHelper emu, int lsw, int msw, float in, long want, String what)
            throws Exception {
        cases++;
        emu.writeRegister("R0H", bits(in));
        emu.writeRegister("R1H", 0xDEADBEEFL);
        if (!stepAt(emu, lsw, msw, what)) {
            return;
        }
        expect(what, emu.readRegister("R1H").longValue() & 0xFFFFFFFFL, want);
    }

    private void parallelMac(EmulatorHelper emu, int lsw, int msw, String acc, String tmp,
            String what) throws Exception {
        cases++;
        emu.writeRegister(acc, bits(2.0f));
        emu.writeRegister(tmp, bits(1.0f));
        emu.writeRegister("R0H", bits(3.0f));
        emu.writeRegister("SP", SP_BASE);
        writeLong(emu, SP_BASE - 2, bits(7.0f));
        if (!stepAt(emu, lsw, msw, what)) {
            return;
        }
        // acc = 2 + 1 = 3; tmp = OLD acc (2) * 3 = 6 (the buggy order gave 3 * 3 = 9).
        expect(what + " [" + acc + "]", reg(emu, acc), bits(3.0f));
        expect(what + " [" + tmp + "]", reg(emu, tmp), bits(6.0f));
        expect(what + " [R1H]", reg(emu, "R1H"), bits(7.0f));
    }

    private static final long A = 0x9000L, B = 0x9100L;

    private void loadVectors(EmulatorHelper emu) throws Exception {
        float[] a = {1f, 2f, 3f, 4f};
        float[] b = {10f, 20f, 30f, 40f};
        for (int i = 0; i < 4; i++) {
            writeLong(emu, A + 2L * i, bits(a[i]));
            writeLong(emu, B + 2L * i, bits(b[i]));
        }
        for (String r : new String[] {"R2H", "R3H", "R6H", "R7H"}) {
            emu.writeRegister(r, 0L);
        }
        emu.writeRegister("XAR6", A);
        emu.writeRegister("XAR7", B);
    }

    private void repeatedMac(EmulatorHelper emu) throws Exception {
        cases++;
        String what = "RPT #3 || MACF32 R7H,R3H,*XAR6++,*XAR7++";
        loadVectors(emu);
        long base = cursor;
        cursor += 4;
        emu.writeMemoryValue(space.getAddress(base * 2), 2, 0xF603L);              // RPT #3
        emu.writeMemoryValue(space.getAddress((base + 1) * 2), 2, 0xE250L);        // MACF32
        emu.writeMemoryValue(space.getAddress((base + 2) * 2), 2, 0x1F86L);        // *XAR6++
        emu.writeMemoryValue(space.getAddress((base + 3) * 2), 2, 0x7700L);        // NOP
        emu.writeRegister("PC", base);
        int steps = 0;
        while (emu.readRegister("PC").longValue() < base + 3) {
            if (!emu.step(monitor)) {
                fail(what, emu.getLastError());
                return;
            }
            if (++steps > 50) {
                fail(what, "did not leave the repeat within 50 steps");
                return;
            }
        }
        // products 10, 40, 90, 160 through pairs R3/R2, R7/R6, R3/R2, R7/R6:
        //   1: R3 = 0 + 0,   R2 = 10     2: R7 = 0 + 0,  R6 = 40
        //   3: R3 = 0 + 10,  R2 = 90     4: R7 = 0 + 40, R6 = 160
        expect(what + " [R3H]", reg(emu, "R3H"), bits(10f));
        expect(what + " [R2H]", reg(emu, "R2H"), bits(90f));
        expect(what + " [R7H]", reg(emu, "R7H"), bits(40f));
        expect(what + " [R6H]", reg(emu, "R6H"), bits(160f));
        expect(what + " [XAR6]", reg(emu, "XAR6"), A + 8);
        expect(what + " [XAR7]", reg(emu, "XAR7"), B + 8);
        expect(what + " [RPTC]", emu.readRegister("RPTC").longValue() & 0xFFFFL, 0L);
    }

    private void standaloneMac(EmulatorHelper emu) throws Exception {
        cases++;
        String what = "MACF32 R7H,R3H,*XAR6++,*XAR7++ (no RPT)";
        loadVectors(emu);
        emu.writeRegister("R2H", bits(5f));
        emu.writeRegister("R7H", bits(99f));
        if (!stepAt(emu, 0xE250, 0x1F86, what)) {
            return;
        }
        expect(what + " [R3H]", reg(emu, "R3H"), bits(5f));
        expect(what + " [R2H]", reg(emu, "R2H"), bits(10f));
        expect(what + " [R7H]", reg(emu, "R7H"), bits(99f));
        expect(what + " [R6H]", reg(emu, "R6H"), 0L);
        expect(what + " [XAR7]", reg(emu, "XAR7"), B + 2);
    }

    private void writeLong(EmulatorHelper emu, long word, long value) throws Exception {
        emu.writeMemoryValue(space.getAddress(word * 2), 2, value & 0xFFFFL);
        emu.writeMemoryValue(space.getAddress((word + 1) * 2), 2, (value >>> 16) & 0xFFFFL);
    }

    private static long reg(EmulatorHelper emu, String name) {
        return emu.readRegister(name).longValue() & 0xFFFFFFFFL;
    }

    private static long bits(float f) {
        return Float.floatToRawIntBits(f) & 0xFFFFFFFFL;
    }

    private void expect(String what, long got, long want) {
        if (got == want) {
            return;
        }
        println(String.format("EmuFpuConvMacTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuFpuConvMacTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
