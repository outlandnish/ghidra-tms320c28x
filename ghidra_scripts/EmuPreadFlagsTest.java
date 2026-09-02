// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for PREAD loc16,*XAR7 setting N/Z from the word it loads.
//
// The constructor was a bare `loc16 = *[ram]:2 XAR7;` with no flag update. As with
// ADDB ACC,#8bit (EmuAddbAccFlagsTest), decode parity is blind to this: the mnemonic and the
// operand are correct whether or not the flags move.
//
// It breaks real firmware. TI's inlined .cinit walk in _c_int00 reads each record's count and
// then tests its SIGN, because a negative count is how the format says "this record's destination
// is 32-bit rather than 16-bit":
//
//     PREAD @AL,*XAR7      ; AL = count word, e.g. 0xffff (= -1)
//     SB    skip,GEQ       ; if AL >= 0, skip the negate  -> must NOT be taken for 0xffff
//     NEG   AL             ; count = 1
//     SETC  TC             ; remember: 32-bit destination
//
// With N never written the branch read a stale flag and was taken, so the walk used 0xffff as a
// literal count and truncated the destination to 16 bits instead of building the real 32-bit one.
// Instead of copying one word it copied 65535, scribbling ~85k words across M0/LS/GS RAM.
//
// Case 3 is the one that reproduces that: it seeds N=0 first, so a missing update leaves N clear
// and the assertion fails exactly the way the firmware did. Cases 1-2 alone would pass against an
// implementation that set N from something stale but coincidentally right.
//
// Run headless (any TMS320C28x program works; the test drives memory itself):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuPreadFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuPreadFlagsTest extends GhidraScript {

    private static final long CODE = 0xc100L;        // GS RAM
    private static final long DATA = 0xc200L;        // the "program memory" PREAD will read
    private static final long PREAD_AL = 0x24A9L;    // PREAD @AL,*XAR7  (op_hi8=0x24, loc8=0xA9=@AL)

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. negative word -> N set, Z clear
            check(emu, sp, 0xffffL, 1, 0, "PREAD 0xffff -> N set");
            // 2. positive word -> N clear, Z clear
            check(emu, sp, 0x0001L, 0, 0, "PREAD 0x0001 -> N clear");
            // 3. zero -> Z set, N clear
            check(emu, sp, 0x0000L, 0, 1, "PREAD 0x0000 -> Z set");

            if (failures == 0) println("EmuPreadFlagsTest.java> PASS: PREAD sets N/Z (3 cases)");
            else println("EmuPreadFlagsTest.java> FAIL: " + failures + " check(s) failed");
        }
        finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long word, long wantN, long wantZ,
            String what) throws Exception {
        emu.writeMemoryValue(sp.getAddress(DATA * 2), 2, word);
        emu.writeMemoryValue(sp.getAddress(CODE * 2), 2, PREAD_AL);
        emu.writeRegister("XAR7", DATA);
        // Seed both flags to the OPPOSITE of what is expected, so a constructor that never writes
        // them fails instead of coincidentally matching.
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("PC", CODE);
        if (!emu.step(monitor)) {
            println("EmuPreadFlagsTest.java> FAIL (" + what + "): " + emu.getLastError());
            failures++;
            return;
        }
        expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xffffL, word);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuPreadFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
}
