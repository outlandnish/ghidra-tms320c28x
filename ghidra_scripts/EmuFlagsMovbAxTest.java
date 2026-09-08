// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for MOVB AX.LSB/MSB from loc16 (issue #90 group C). Both the plain-loc16
// forms and the *+XARn[ARm] indirect forms wrote AX (AH or AL) without setting N/Z. SPRU430F:
// "After the move, AX is tested for a negative condition" and "for a zero condition" -- the
// N/Z are tested on the FULL AX after the byte load, so the preserved-half of AX contributes.
//
// Tests the plain @loc16 form only -- the indirect (*+XARn[ARm]) forms share the exact
// same setNZ16(AX) tail, so the plain form is a representative cover.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuFlagsMovbAxTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuFlagsMovbAxTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    // op_hi7=0x63 << 1 | ax_bit -> MOVB AX.LSB, loc16
    private static final long MOVB_AL_LSB = 0xC600L;   // AX bit=0 (AL), loc16 low byte
    private static final long MOVB_AH_LSB = 0xC700L;
    // op_hi7=0x1C << 1 | ax_bit -> MOVB AX.MSB, loc16
    private static final long MOVB_AL_MSB = 0x3800L;
    private static final long MOVB_AH_MSB = 0x3900L;
    // *-SP[1] loc16 low byte: loc_b76=01, loc_off6=1 -> 0x41
    private static final long LOC_SP1 = 0x41L;
    private static final long SP_BASE = 0x8000L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. MOVB AL.LSB, [scratch=0xff] -> AL=0xff. STALE Z=1 -> 0, STALE N (=0 since bit 15
            //    of AL=0xff is 0) stays 0. Positive-nonzero byte load.
            check(emu, sp, MOVB_AL_LSB | LOC_SP1, /*preAcc*/0x11110000L, /*loc*/0x00FF,
                /*wantAcc*/0x111100FFL, /*wantAL*/0x00FF, /*wantN*/0, /*wantZ*/0,
                "MOVB AL.LSB,[0xff] : AL=0xff, Z clear");

            // 2. MOVB AL.LSB, [0x00]. Should clear AL to 0. Z must set (AL byte is 0).
            check(emu, sp, MOVB_AL_LSB | LOC_SP1, 0x11110000L, 0x0000,
                0x11110000L, 0x0000, 0, 1,
                "MOVB AL.LSB,[0x00] : AL=0, Z set (STALE Z=0)");

            // 3. MOVB AH.MSB, [0xff]. AH's HIGH byte := 0xff, low byte preserved. If AH was 0x0000,
            //    new AH = 0xff00 which is NEGATIVE (bit 15 set). N must set.
            check(emu, sp, MOVB_AH_MSB | LOC_SP1, /*preAcc*/0x00000000L, 0x00FF,
                /*wantAcc*/0xFF000000L, /*wantAH*/0xFF00, 1, 0,
                "MOVB AH.MSB,[0xff] : AH=0xff00, N set (STALE N=0)");

            // 4. STALE-FLAG for MOVB AL.MSB. Set AL=0x0080 first via ACC, then MOVB AL.MSB [0x00]
            //    clears the high byte -- result AL=0x0080. N stays 0 (bit 15 = 0), Z stays 0.
            check(emu, sp, MOVB_AL_MSB | LOC_SP1, /*preAcc*/0x00000080L, 0x0000,
                /*wantAcc*/0x00000080L, /*wantAL*/0x0080, 0, 0,
                "MOVB AL.MSB,[0x00] : AL preserves low byte, Z clear");

            if (failures == 0) {
                println("EmuFlagsMovbAxTest.java> PASS: MOVB AX.LSB/MSB set N/Z (4 cases)");
            } else {
                println("EmuFlagsMovbAxTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long word0, long preAcc, long locVal,
            long wantAcc, long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", preAcc);
        emu.writeRegister("SP", SP_BASE);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, locVal & 0xffffL);
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
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuFlagsMovbAxTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuFlagsMovbAxTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
