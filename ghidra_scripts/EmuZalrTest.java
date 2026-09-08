// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for ZALR ACC,loc16 -- "Zero AL and Load AH With Rounding".
//
// SPRU430F p.489 states it as two halves:
//
//     AH = [loc16];
//     AL = 0x8000;
//
// but the constructor writes ACC once, as (loc16 << 16) | 0x8000. The two are the
// same value; the single store just spares the decompiler having to glue two 16-bit
// definitions back together, which it renders as CONCAT22(AH, AL) at every later
// read of ACC.
//
// WHY THIS TEST EXISTS. ZALR does not occur in either production image this module is
// measured against (0 sites in a DIR dis2000 dump, and the #75 idiom survey found 0/0),
// so firmware parity cannot cover it; and no decode fixture can, because the mnemonic
// comes from the pattern and the pattern is untouched. Rewriting the body was therefore
// completely unguarded.
//
// What this DOES guard is the semantics: that AH takes [loc16] and AL takes 0x8000, and
// not the reverse, and that the 16-bit operand is zero-extended rather than sign-extended
// into the high half. Those are what a one-store rewrite can get wrong.
//
// What it does NOT do is tell the two spellings apart -- they compute the same value, so
// emulation cannot distinguish them. That difference is p-code SHAPE and is verified by
// reading the emitted ops: two 2-byte writes (register 0x0 and 0x2) become one 4-byte
// write of ACC. See the constructor comment.
//
// @AR0 is used as the operand because it is register-direct (loc byte 0xa0): it needs no
// DP, no stack frame and no memory, so the test asserts the instruction and nothing else.
//
// Run headless (any TMS320C28x program works as the import target; the test is
// host-driven and never reads the program's own bytes):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuZalrTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuZalrTest extends GhidraScript {

    // ZALR ACC,loc16 -- 0101 0110 0001 0011 : 0000 0000 LLLL LLLL
    private static final long ZALR = 0x5613L;
    private static final long LOC_AR0 = 0x00A0L;   // @AR0, register-direct

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int failures = 0;
        // A value with all four bytes distinct and the top bit set, so a swapped or
        // sign-extended half cannot coincide with the right answer.
        for (long value : new long[] {0x1234L, 0xABCDL, 0x0000L, 0xFFFFL, 0x8001L}) {
            EmulatorHelper emu = new EmulatorHelper(currentProgram);
            try {
                emu.writeMemoryValue(sp.getAddress(0xc100L * 2), 2, ZALR);
                emu.writeMemoryValue(sp.getAddress(0xc101L * 2), 2, LOC_AR0);
                emu.writeRegister("XAR0", value);       // AR0 is the low half of XAR0
                emu.writeRegister("ACC", 0xDEADBEEFL);  // must be fully overwritten
                emu.writeRegister("PC", 0xc100L);

                if (!emu.step(monitor)) {
                    println("EmuZalrTest.java> FAIL: emu.step: " + emu.getLastError());
                    failures++;
                    continue;
                }

                long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
                long ah = emu.readRegister("AH").longValue() & 0xFFFFL;
                long al = emu.readRegister("AL").longValue() & 0xFFFFL;
                long expected = (value << 16) | 0x8000L;

                if (acc != expected || ah != value || al != 0x8000L) {
                    println(String.format("EmuZalrTest.java> FAIL: @AR0=0x%04x expected"
                        + " ACC=0x%08x AH=0x%04x AL=0x8000, got ACC=0x%08x AH=0x%04x"
                        + " AL=0x%04x", value, expected, value, acc, ah, al));
                    failures++;
                }
            }
            finally {
                emu.dispose();
            }
        }

        if (failures == 0) {
            println("EmuZalrTest.java> PASS: ZALR stores ACC once,"
                + " AH = [loc16] and AL = 0x8000 (5 cases)");
        }
        else {
            println("EmuZalrTest.java> FAIL: " + failures + " ZALR cases");
        }
    }
}
