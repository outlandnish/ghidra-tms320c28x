// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 abedegno
//
// Emulation test for the flags of ADD loc16,#16bitSigned.
//
// SPRU430F (section 6.3, ADD loc16,#16bitSigned) has this instruction set N and Z from the
// stored result, C on a carry out of bit 15, and V on signed overflow (cleared when there is
// none). The constructor set no flags at all. The listing is identical either way, so only
// emulation (and the decompiler, which then tests a stale flag) can see it.
//
// Compilers use the instruction on a register half as well as on memory. Found on a real
// image: a runtime float-divide routine tests the result exponent with
// `ADD @AL,#0xff01 ; SB ...,GT`; with the flags left over from earlier instructions every
// division returned either the largest float or zero.
//
// Each case writes one ADD loc16,#imm16 (0000 1000 LLLL LLLL, then the constant) into the
// emulator, steps it, and checks the destination and N/Z/C/V. Every flag starts at the
// opposite of the expected value, so a flag the constructor leaves alone cannot pass.
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuAddLoc16ImmFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuAddLoc16ImmFlagsTest extends GhidraScript {

    private static final long CODE = 0x9000L;   // word address; the emulator creates the memory
    private static final long DATA = 0x9100L;   // word address of the memory operand
    private static final int AL = 0xA9, AH = 0xA8, XAR4_0 = 0xC4;   // loc16: @AL, @AH, *+XAR4[0]

    private int failures = 0;
    private long next = CODE;                    // each case gets its own address: the emulator caches decodes

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            //    what                                  loc     value in  imm16   value out  N  Z  C  V
            check(emu, sp, "exponent test, result > 0",  AL,     0x0100, 0xFF01, 0x0001,    0, 0, 1, 0);
            check(emu, sp, "exponent test, result < 0",  AL,     0x0080, 0xFF01, 0xFF81,    1, 0, 0, 0);
            check(emu, sp, "3 + (-3) -> 0",              AH,     0x0003, 0xFFFD, 0x0000,    0, 1, 1, 0);
            check(emu, sp, "0x7FFF + 1: pos ovf",        AL,     0x7FFF, 0x0001, 0x8000,    1, 0, 0, 1);
            check(emu, sp, "0x8000 + (-1): neg ovf",     AH,     0x8000, 0xFFFF, 0x7FFF,    0, 0, 1, 1);
            check(emu, sp, "memory: 0x1234 + 0x10",      XAR4_0, 0x1234, 0x0010, 0x1244,    0, 0, 0, 0);
            check(emu, sp, "memory: 5 + (-10)",          XAR4_0, 0x0005, 0xFFF6, 0xFFFB,    1, 0, 0, 0);
            check(emu, sp, "memory: 0xFFFF + 1 -> 0",    XAR4_0, 0xFFFF, 0x0001, 0x0000,    0, 1, 1, 0);
            if (failures == 0) println("EmuAddLoc16ImmFlagsTest.java> PASS: ADD loc16,#16bitSigned sets N/Z/C/V (8 cases)");
            else println("EmuAddLoc16ImmFlagsTest.java> FAIL: " + failures + " check(s) failed");
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, String what, int loc, int in,
                       int imm16, int out, int n, int z, int c, int v) throws Exception {
        long at = next;
        next += 2;
        emu.writeMemoryValue(sp.getAddress(at * 2), 2, 0x0800L | loc);
        emu.writeMemoryValue(sp.getAddress((at + 1) * 2), 2, imm16);
        emu.writeRegister("ACC", 0x5A5A5A5AL);
        emu.writeRegister("XAR4", DATA);
        emu.writeMemoryValue(sp.getAddress(DATA * 2), 2, 0xA5A5L);
        if (loc == AL) emu.writeRegister("AL", in);
        else if (loc == AH) emu.writeRegister("AH", in);
        else emu.writeMemoryValue(sp.getAddress(DATA * 2), 2, in);
        emu.writeRegister("N", 1 - n);
        emu.writeRegister("Z", 1 - z);
        emu.writeRegister("C", 1 - c);
        emu.writeRegister("V", 1 - v);
        emu.writeRegister("PC", at);
        if (!emu.step(monitor)) {
            println("EmuAddLoc16ImmFlagsTest.java> FAIL (" + what + "): " + emu.getLastError());
            failures++;
            return;
        }
        long got;
        if (loc == AL) got = emu.readRegister("AL").longValue();
        else if (loc == AH) got = emu.readRegister("AH").longValue();
        else {
            byte[] b = emu.readMemory(sp.getAddress(DATA * 2), 2);
            got = (b[0] & 0xFF) | (b[1] & 0xFF) << 8;
        }
        expect(what + " [result]", got & 0xFFFFL, out);
        if (loc == AL) expect(what + " [AH untouched]", emu.readRegister("AH").longValue(), 0x5A5A);
        if (loc == AH) expect(what + " [AL untouched]", emu.readRegister("AL").longValue(), 0x5A5A);
        if (loc == XAR4_0) expect(what + " [ACC untouched]", emu.readRegister("ACC").longValue() & 0xFFFFFFFFL, 0x5A5A5A5AL);
        expect(what + " [PC]", emu.readRegister("PC").longValue(), at + 2);
        expect(what + " [N]", emu.readRegister("N").longValue(), n);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), z);
        expect(what + " [C]", emu.readRegister("C").longValue(), c);
        expect(what + " [V]", emu.readRegister("V").longValue(), v);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuAddLoc16ImmFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x", what, want, got));
        failures++;
    }
}
