// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paul van der Wateren
//
// Emulation test for MOVB ACC,#8bit (0x02CC) N/Z. SPRU430F p.281: N and Z are tested on
// ACC after the zero-extended load. The constructor set neither (the issue #110 MOV audit
// covered the other ACC loads but not this one), so a following SB EQ/NEQ/LT read stale
// flags. cl2000 emits `MOVB ACC,#0` ahead of conditional branches routinely.
//
// Every case pre-seeds the asserted flags to their opposite.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuMovbAccFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuMovbAccFlagsTest extends GhidraScript {

    private static final long CODE = 0xc100L;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            check(emu, sp, 0x00L, 0x00000000L, 0, 1, "MOVB ACC,#0    : ACC=0, Z=1 N=0");
            check(emu, sp, 0x05L, 0x00000005L, 0, 0, "MOVB ACC,#5    : ACC=5, Z=0 N=0");
            // Bit 7 set: zero-extension keeps ACC positive, so N must be CLEARED.
            check(emu, sp, 0xffL, 0x000000ffL, 0, 0, "MOVB ACC,#0xff : ACC=0xff zero-extended, N=0");

            if (failures == 0) {
                println("EmuMovbAccFlagsTest.java> PASS: MOVB ACC,#8bit sets N/Z (3 cases)");
            } else {
                println("EmuMovbAccFlagsTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long imm8, long wantAcc,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", 0x80001234L);          // junk, negative
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 2;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x0200L | (imm8 & 0xffL));
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuMovbAccFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuMovbAccFlagsTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
