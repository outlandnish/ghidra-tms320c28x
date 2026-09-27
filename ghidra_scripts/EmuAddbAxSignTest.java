// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 abedegno
//
// Emulation test for the sign extension of ADDB AX,#8bitSigned.
//
// SPRU430F (section 6.3, ADDB AX,#8bitSigned) gives the constant as a signed two's complement
// value from -128 to 127, sign-extended before it is added to AL or AH. It is the only 8-bit
// immediate form in the core set that is signed: ADDB ACC, SUBB ACC, CMPB AX, MOVB AX, ANDB/ORB/
// XORB AX and the 7-bit SP/XARn forms all zero-extend. The constructor zero-extended it, so
// `ADDB AL,#-2` added 254. The disassembly text looked the same either way, so only emulation
// (and the decompiler's `x + 0xfe`) could see it.
//
// There is no SUBB AX, so the compiler writes every small 16-bit subtraction as ADDB AX with a
// negative constant. Found on a real image: a Modbus master computes its CRC length as
// `length - 2` with `ADDB AL,#-2`; with zero extension it ran the CRC over length + 254 bytes
// and rejected every reply.
//
// Each case pre-loads ACC, writes one ADDB AX instruction (1001 110A CCCC CCCC, A = 0 for AL,
// 1 for AH) into the emulator, steps it, and checks both halves of ACC and N/Z/C/V.
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuAddbAxSignTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuAddbAxSignTest extends GhidraScript {

    private static final long CODE = 0x9000L;   // word address; the emulator creates the memory
    private int failures = 0;
    private long next = CODE;                    // each case gets its own address: the emulator caches decodes

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            //    what                              ah?    ACC in       imm8  ACC out      N  Z  C  V
            check(emu, sp, "CRC length: 61 + (-2)", false, 0x1234003DL, 0xFE, 0x1234003BL, 0, 0, 1, 0);
            check(emu, sp, "2 + (-2) -> 0",          false, 0x00000002L, 0xFE, 0x00000000L, 0, 1, 1, 0);
            check(emu, sp, "AH: 0x10 + (-90)",       true,  0x0010ABCDL, 0xA6, 0xFFB6ABCDL, 1, 0, 0, 0);
            check(emu, sp, "0x8000 + (-1): neg ovf", false, 0x00008000L, 0xFF, 0x00007FFFL, 0, 0, 1, 1);
            check(emu, sp, "0x7FFF + 1: pos ovf",    false, 0x00007FFFL, 0x01, 0x00008000L, 1, 0, 0, 1);
            check(emu, sp, "positive constant 127",  true,  0x00010000L, 0x7F, 0x00800000L, 0, 0, 0, 0);
            if (failures == 0) println("EmuAddbAxSignTest.java> PASS: ADDB AX,#8bit sign-extends its constant (6 cases)");
            else println("EmuAddbAxSignTest.java> FAIL: " + failures + " check(s) failed");
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, String what, boolean ah, long accIn,
                       int imm8, long accOut, int n, int z, int c, int v) throws Exception {
        long at = next++;
        emu.writeMemoryValue(sp.getAddress(at * 2), 2, 0x9C00L | (ah ? 0x100L : 0L) | imm8);
        emu.writeRegister("ACC", accIn);
        // Start every flag from the opposite of the expected value, so a flag the constructor
        // leaves alone cannot pass by accident. V is sticky (set on overflow, otherwise unchanged),
        // so it starts at 0.
        emu.writeRegister("N", 1 - n);
        emu.writeRegister("Z", 1 - z);
        emu.writeRegister("C", 1 - c);
        emu.writeRegister("V", 0);
        emu.writeRegister("PC", at);
        if (!emu.step(monitor)) {
            println("EmuAddbAxSignTest.java> FAIL (" + what + "): " + emu.getLastError());
            failures++;
            return;
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xFFFFFFFFL, accOut);
        expect(what + " [N]", emu.readRegister("N").longValue(), n);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), z);
        expect(what + " [C]", emu.readRegister("C").longValue(), c);
        expect(what + " [V]", emu.readRegister("V").longValue(), v);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuAddbAxSignTest.java> FAIL: %s -- expected 0x%x, got 0x%x", what, want, got));
        failures++;
    }
}
