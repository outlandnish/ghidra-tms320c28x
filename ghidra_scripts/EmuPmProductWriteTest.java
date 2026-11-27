// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the PM product shift on the WRITE side of the 32x32 low-half
// multiplies: IMPYL P, IMPYXUL, IMPYAL, IMPYSL, IMACL. SPRU430F (each page):
//   temp(37:0) = lower_38 bits(product);
//   PM = +4 / +1  ->  P = temp << 4 / << 1 (low bits zero)
//   PM = 0        ->  P = temp(31:0)
//   PM = -n       ->  P = temp(31+n:n)
// Each instruction is a pm_shift pair. The pm_shift=1 twin is normally selected by
// TMS320C28xPmShiftAnalyzer, which -noanalysis does not run, so this test sets the
// context bit on the emulator directly. One negative control pins the default: with
// pm_shift=0 the constructor stores the low 32 bits whatever PM holds.
//
// The products are chosen so bits 32..37 are non-zero: a body that ignores PM, or
// shifts the 32-bit P instead of the 64-bit product, gives a different P.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuPmProductWriteTest.java -noanalysis
//@category C28x.Test
import java.math.BigInteger;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public class EmuPmProductWriteTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long XAR7_BASE = 0x9000L;
    private static final long LOC_SP1 = 0x41L;      // *-SP[1] loc32 selector

    private static final long IMPYL_P = 0x5605L;
    private static final long IMPYXUL = 0x5665L;
    private static final long IMPYAL  = 0x564CL;
    private static final long IMPYSL  = 0x5643L;
    private static final long IMACL   = 0x564DL;    // word2 = 0xC7 (*XAR7) << 8 | loc32

    private int failures = 0;
    private int cases = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Register pmShift = currentProgram.getLanguage().getRegister("pm_shift");
        if (pmShift == null) {
            println("EmuPmProductWriteTest.java> FAIL: no pm_shift context register");
            return;
        }
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 0x40000003 * 0xe = 0x3_8000_002a: bits 33..34 set above the low word.
            //            op       pmShift pm  xt           mem          wantP
            check(emu, sp, pmShift, IMPYL_P, 1, -1, 0x40000003L, 0x0000000eL, 0xc0000015L,
                "IMPYL P  PM=-1 : P = product(32:1)");
            check(emu, sp, pmShift, IMPYL_P, 1,  1, 0x40000003L, 0x0000000eL, 0x00000054L,
                "IMPYL P  PM=+1 : P = product << 1, bit 31 lost");
            check(emu, sp, pmShift, IMPYL_P, 1,  4, 0x40000003L, 0x0000000eL, 0x000002a0L,
                "IMPYL P  PM=+4 : P = product << 4");
            // -0x40000003 * 0xe = 0xffff_fffc_7fff_ffd6; PM=-6 takes bits 37..6, sign-filled.
            check(emu, sp, pmShift, IMPYL_P, 1, -6, 0xbffffffdL, 0x0000000eL, 0xf1ffffffL,
                "IMPYL P  PM=-6 : negative product, P = product(37:6)");
            // XT signed * loc32 UNSIGNED: 2 * 0xc0000000 = 0x1_8000_0000; PM=-2 -> 0x60000000.
            // A signed loc32 would give -0x8000_0000 -> 0xe0000000 instead.
            check(emu, sp, pmShift, IMPYXUL, 1, -2, 0x00000002L, 0xc0000000L, 0x60000000L,
                "IMPYXUL  PM=-2 : unsigned loc32, P = product(33:2)");
            check(emu, sp, pmShift, IMPYAL,  1, -3, 0x40000003L, 0x0000000eL, 0x70000005L,
                "IMPYAL   PM=-3 : P = product(34:3)");
            check(emu, sp, pmShift, IMPYSL,  1, -2, 0x40000003L, 0x0000000eL, 0xe000000aL,
                "IMPYSL   PM=-2 : P = product(33:2)");
            check(emu, sp, pmShift, IMACL,   1, -4, 0x40000003L, 0x0000000eL, 0x38000002L,
                "IMACL    PM=-4 : P = product(35:4)");
            check(emu, sp, pmShift, IMPYL_P, 1,  0, 0x40000003L, 0x0000000eL, 0x8000002aL,
                "IMPYL P  PM=0, pm_shift=1 : low 32 bits");
            // Negative control: pm_shift=0 is the unproven default and stores the low 32 bits.
            check(emu, sp, pmShift, IMPYL_P, 0, -2, 0x40000003L, 0x0000000eL, 0x8000002aL,
                "IMPYL P  PM=-2, pm_shift=0 : default keeps low 32 bits");

            if (failures == 0) {
                println("EmuPmProductWriteTest.java> PASS: low-38 product writes apply PM (" +
                    cases + " cases)");
            } else {
                println("EmuPmProductWriteTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, Register pmShift, long op,
            int pmShiftBit, int pm, long xt, long mem, long wantP, String what) throws Exception {
        cases++;
        // IMACL multiplies [loc32] by Prog[*XAR7]; the others multiply XT by [loc32].
        // For IMACL `xt` is the loc32 value and `mem` is the XAR7 word pair.
        long loc32 = op == IMACL ? xt : mem;
        emu.writeRegister("ACC", 0L);
        emu.writeRegister("P", 0L);
        emu.writeRegister("XT", xt);
        emu.writeRegister("PM", pm & 0xffL);
        emu.writeRegister("SP", SP_BASE);
        emu.writeRegister("XAR7", XAR7_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32 & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (loc32 >> 16) & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(XAR7_BASE * 2), 2, mem & 0xffffL);
        emu.writeMemoryValue(sp.getAddress((XAR7_BASE + 1) * 2), 2, (mem >> 16) & 0xffffL);

        long here = codeCursor; codeCursor += 4;
        long word2 = op == IMACL ? (0xC700L | LOC_SP1) : LOC_SP1;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, op);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, word2);
        emu.writeRegister("PC", here);

        // Before the first step the emulator holds no context, so start from the program's
        // disassembly context at this address (it carries the pspec defaults, rpt_phase=1).
        RegisterValue ctx = currentProgram.getProgramContext()
            .getDisassemblyContext(sp.getAddress(here * 2));
        emu.setContextRegister(ctx.assign(pmShift, BigInteger.valueOf(pmShiftBit)));

        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [P]", emu.readRegister("P").longValue() & 0xffffffffL, wantP);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuPmProductWriteTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuPmProductWriteTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
