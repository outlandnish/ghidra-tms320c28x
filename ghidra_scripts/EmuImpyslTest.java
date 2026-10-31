// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paul van der Wateren
//
// Emulation test for IMPYSL P,XT,loc32 (0x5643), previously <UNDEF>. SPRU430F p.205:
//   ACC = ACC - unsigned P;  P = low 32 bits of (signed XT * signed [loc32])
// Flags on the subtraction: N, Z; C cleared on borrow else set; V set on signed overflow
// (sticky, otherwise unaffected); OVCU decremented on unsigned borrow. PM is left at 0 here,
// matching the IMPYAL model (P is the unshifted low 32 bits).
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuImpyslTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuImpyslTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;      // *-SP[1] loc32 selector

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            //     acc          p            xt           mem          wantAcc      wantP        N Z C V ovcDelta
            check(emu, sp, 10L,         3L,          0xfffffffeL, 7L,          7L,          0xfffffff2L, 0,0,1,0, 0,
                "IMPYSL : 10-3=7, P = -2*7 = -14");
            check(emu, sp, 3L,          3L,          2L,          3L,          0L,          6L,          0,1,1,0, 0,
                "IMPYSL : 3-3=0 -> Z=1, C=1 (no borrow)");
            check(emu, sp, 1L,          2L,          1L,          1L,          0xffffffffL, 1L,          1,0,0,0, -1,
                "IMPYSL : 1-2 borrows -> C=0, N=1, OVCU-1");
            check(emu, sp, 0x80000000L, 1L,          1L,          1L,          0x7fffffffL, 1L,          0,0,1,1, 0,
                "IMPYSL : 0x80000000-1 signed overflow -> V=1, no borrow");

            if (failures == 0) {
                println("EmuImpyslTest.java> PASS: IMPYSL ACC-=P, P=XT*[loc32], N/Z/C/V/OVCU (4 cases)");
            } else {
                println("EmuImpyslTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, long acc, long p, long xt, long mem,
            long wantAcc, long wantP, long wantN, long wantZ, long wantC, long wantV,
            long ovcDelta, String what) throws Exception {
        final long ovc0 = 5L;
        emu.writeRegister("ACC", acc);
        emu.writeRegister("P", p);
        emu.writeRegister("XT", xt);
        emu.writeRegister("OVC", ovc0);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (mem >> 16) & 0xffffL);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        emu.writeRegister("V", 0L);                     // V is sticky: only a set is observable
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x5643L);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [P]",   emu.readRegister("P").longValue() & 0xffffffffL, wantP);
        expect(what + " [N]",   emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]",   emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]",   emu.readRegister("C").longValue(), wantC);
        expect(what + " [V]",   emu.readRegister("V").longValue(), wantV);
        expect(what + " [OVC]", emu.readRegister("OVC").longValue() & 0x3fL, (ovc0 + ovcDelta) & 0x3fL);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuImpyslTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuImpyslTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
