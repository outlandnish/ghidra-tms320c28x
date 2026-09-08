// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #112 leftover-family flag/semantics audit. Closes out
// the systematic per-family sweep with three specific holes:
//
//   INC/DEC loc16 (tms320c28x_alu.sinc) -- were setting N/Z/V but not C. Per
//     SPRU430F p.222 / p.246 both must set C: INC on carry-out (0xFFFF+1 -> 0),
//     DEC on no-borrow (C=1 unless v==0). C is what compilers reach for when
//     turning `if (--n < 0)` into a branch off C, so the hole matters.
//
//   NORM ACC,<indirect> (tms320c28x_ext56.sinc) -- 5 constructors (0x5624/565a/
//     5620/5677/5630) had `{ }` decode-only bodies. Their :NORM "ACC,"loc_areg
//     siblings in _more.sinc already model the full spec: shift ACC left when
//     bits 31/30 match, set TC accordingly, N/Z from the resulting ACC. Same
//     macro (normAcc) now drives both sets.
//
// ZAPA is deliberately NOT covered here -- its existing `# ...` comment in
// tms320c28x_ext56.sinc flags the SPRU430F N=1/Z=0 text as suspect and defers
// pending firmware evidence. No test until we have that evidence.
//
// Every case pre-seeds the asserted flag to its opposite; a body that leaves
// the flag alone (the pre-fix state) will fail.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuLeftoverFamilyTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuLeftoverFamilyTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;   // *-SP[1] loc16 selector

    private static final long INC_LOC = 0x0A00L; // INC loc16   0x0A << 8 | loc
    private static final long DEC_LOC = 0x0B00L; // DEC loc16   0x0B << 8 | loc

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ============================================================
            // INC/DEC loc16 -- newly added C flag (issue #112)
            // ============================================================

            // 1. INC : 0xFFFF+1 -> 0. C set (carry-out), Z set, V clear (unsigned wrap).
            //    A body that only writes V/N/Z leaves C stale -- fails on C.
            incDec(emu, sp, INC_LOC, 0xFFFFL, /*wantMem*/0x0000L,
                /*wantN*/0, /*wantZ*/1, /*wantC*/1,
                "INC loc16 : 0xFFFF+1 -> 0, C set (regression)");
            // 2. INC : 5+1 -> 6. C clear (no carry).
            incDec(emu, sp, INC_LOC, 5L, 6L, 0, 0, 0,
                "INC loc16 : 5+1 -> 6, C clear");
            // 3. DEC : 1-1 -> 0. C set (no borrow), Z set.
            incDec(emu, sp, DEC_LOC, 1L, 0L, 0, 1, 1,
                "DEC loc16 : 1-1 -> 0, C set (no borrow) (regression)");
            // 4. DEC : 0-1 -> 0xFFFF. C clear (borrow), N set.
            incDec(emu, sp, DEC_LOC, 0L, 0xFFFFL, 1, 0, 0,
                "DEC loc16 : 0-1 -> 0xFFFF, C clear (borrow), N set (regression)");

            // ============================================================
            // NORM ACC,* / *++ / *-- / *0++ / *0-- (issue #112)
            // ============================================================

            // 5. NORM * (0x5624): ACC=0x40000000. Bits 31/30 = 0/1, DIFFERENT -> no shift,
            //    TC=1, N/Z from unchanged ACC.
            norm(emu, sp, /*op*/0x5624L, /*acc*/0x40000000L,
                /*wantAcc*/0x40000000L, /*wantN*/0, /*wantZ*/0, /*wantTC*/1,
                "NORM ACC,* : 0x40000000 already normal, TC=1 (regression)");
            // 6. NORM *++ (0x565a): ACC=0x20000000. Bits 31/30 = 0/0, SAME -> shift ->
            //    0x40000000, TC=0. N/Z from result.
            norm(emu, sp, 0x565aL, 0x20000000L, 0x40000000L, 0, 0, 0,
                "NORM ACC,*++ : 0x20000000 -> 0x40000000, TC=0 (regression)");
            // 7. NORM *-- (0x5620): ACC=0 -> shift condition is (ACC != 0), so no shift.
            //    TC=1, Z=1.
            norm(emu, sp, 0x5620L, 0L, 0L, 0, 1, 1,
                "NORM ACC,*-- : ACC=0 no shift, TC=1 Z=1 (regression)");
            // 8. NORM *0++ (0x5677): ACC=0xC0000000. Bits 31/30 = 1/1, SAME -> shift ->
            //    0x80000000, TC=0. N=1.
            norm(emu, sp, 0x5677L, 0xC0000000L, 0x80000000L, 1, 0, 0,
                "NORM ACC,*0++ : 0xC0000000 -> 0x80000000, N=1 TC=0 (regression)");
            // 9. NORM *0-- (0x5630): ACC=0x80000000. Bits 31/30 = 1/0, DIFFERENT ->
            //    no shift, TC=1.
            norm(emu, sp, 0x5630L, 0x80000000L, 0x80000000L, 1, 0, 1,
                "NORM ACC,*0-- : 0x80000000 already normal, TC=1 (regression)");

            if (failures == 0) {
                println("EmuLeftoverFamilyTest.java> PASS: INC/DEC C + NORM ext56 forms (issue #112, 9 cases)");
            } else {
                println("EmuLeftoverFamilyTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void incDec(EmulatorHelper emu, AddressSpace sp, long op, long mem,
            long wantMem, long wantN, long wantZ, long wantC, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        byte[] b = emu.readMemory(sp.getAddress((SP_BASE - 1) * 2), 2);
        long got = ((b[0] & 0xffL) | ((b[1] & 0xffL) << 8));
        expect(what + " [mem]", got, wantMem);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
    }

    private void norm(EmulatorHelper emu, AddressSpace sp, long op, long acc,
            long wantAcc, long wantN, long wantZ, long wantTC, String what) throws Exception {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("N",  wantN  == 1 ? 0L : 1L);
        emu.writeRegister("Z",  wantZ  == 1 ? 0L : 1L);
        emu.writeRegister("TC", wantTC == 1 ? 0L : 1L);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]",  emu.readRegister("N").longValue(),  wantN);
        expect(what + " [Z]",  emu.readRegister("Z").longValue(),  wantZ);
        expect(what + " [TC]", emu.readRegister("TC").longValue(), wantTC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuLeftoverFamilyTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuLeftoverFamilyTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
