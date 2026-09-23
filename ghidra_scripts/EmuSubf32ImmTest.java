// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 abedegno
//
// Emulation test for the operand order of SUBF32 RaH,#16FHi,RbH.
//
// The immediate form subtracts the REGISTER from the IMMEDIATE (SPRUEO2A, SUBF32 RaH,#16FHi,RbH:
// RaH = #16FHi:0 - RbH). That is the reverse of the three-register form, RaH = RbH - RcH, and
// the constructor had copied the register form's order, computing RbH - imm. The disassembly
// text was right either way, so only emulation (and the decompiler's output) could see it.
//
// Found on a real image: a DSP current-limit routine computes a derating factor as
// `SUBF32 R1H,#1.0,R1H` (1.0 - factor) and multiplies a limit by it. With the reversed order
// the result was always negative and every limit clamped to its floor at every input.
//
// Each case pre-loads RbH, writes one SUBF32 imm instruction into the emulator, steps it and
// checks RaH. The encoding is LSW 1110 1000 11II IIII, MSW IIII IIII IIbb baaa, where the
// six LSW I bits are the HIGH bits of the 16-bit immediate (the upper half of an IEEE single).
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuSubf32ImmTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuSubf32ImmTest extends GhidraScript {

    private static final long CODE = 0x9000L;   // word address; the emulator creates the memory
    private int failures = 0;
    private long next = CODE;                    // each case gets its own address: the emulator caches decodes

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // RaH = imm - RbH
            check(emu, sp, "1.0 - 0.25", 0x3F80, 0.25f, 1, 0, 0.75f);
            check(emu, sp, "480.0 - 500.0", 0x43F0, 500.0f, 3, 4, -20.0f);
            check(emu, sp, "same register: 1.0 - R1H into R1H", 0x3F80, 0.9f, 1, 1, 1.0f - 0.9f);
            if (failures == 0) println("EmuSubf32ImmTest.java> PASS: SUBF32 RaH,#16FHi,RbH computes imm - RbH (3 cases)");
            else println("EmuSubf32ImmTest.java> FAIL: " + failures + " check(s) failed");
        } finally {
            emu.dispose();
        }
    }

    private void check(EmulatorHelper emu, AddressSpace sp, String what, int imm16, float rb, int rbReg,
                       int raReg, float want) throws Exception {
        long at = next;
        next += 4;
        long w1 = 0xE8C0L | (imm16 >> 10);
        long w2 = ((long) (imm16 & 0x3FF) << 6) | ((long) rbReg << 3) | raReg;
        emu.writeMemoryValue(sp.getAddress(at * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((at + 1) * 2), 2, w2);
        emu.writeRegister("R" + rbReg + "H", Float.floatToRawIntBits(rb) & 0xFFFFFFFFL);
        emu.writeRegister("PC", at);
        if (!emu.step(monitor)) {
            println("EmuSubf32ImmTest.java> FAIL (" + what + "): " + emu.getLastError());
            failures++;
            return;
        }
        float got = Float.intBitsToFloat((int) emu.readRegister("R" + raReg + "H").longValue());
        if (Math.abs(got - want) > 1e-6f) {
            println(String.format("EmuSubf32ImmTest.java> FAIL: %s -- expected %s, got %s", what, want, got));
            failures++;
        }
    }
}
