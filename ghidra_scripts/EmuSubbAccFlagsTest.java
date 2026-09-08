// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for SUBB ACC,#8bit flag updates. Sibling of EmuAddbAccFlagsTest -- same hole,
// found the same way, and this one was the more damaging of the two.
//
// The constructor originally had no flag logic at all: `{ ACC = ACC - zext(imm8:1); }`. Decode
// tests are structurally blind to that, because the mnemonic and operand were always right and
// run_fw_parity only compares text against dis2000. Only emulation reaches it.
//
// SPRU430F's own worked example for this instruction is the decrement idiom, and TI's C runtime
// builds its word-fill loop out of it:
//
//     SUBB ACC,#1             ; Z must be SET when the counter reaches 0
//     MOV  *XAR6++,AR5
//     SB   loop,NEQ           ; and the branch must then NOT be taken
//
// With Z never written, that branch reads a stale flag and the loop never terminates -- for ANY
// counter value, so it is not a corner case. EmulateStartup could not replay startup on an image
// whose runtime uses this fill: it spun until the step budget expired, and (before the apply gate)
// wrote back ~666k words of garbage RAM, which took one image's reachability from 81% to 8.2%.
//
// Case 3 is the one that reproduces the firmware failure. Cases 1 and 2 pass even under a
// partially-wrong body that derives Z from the operand alone; case 3 pins the STALE-flag
// behaviour by setting Z=1 first and requiring a non-zero result to clear it. Case 4 covers the
// borrow direction of C, which SPRU430F specifies inverted (C is CLEARED on borrow).
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuSubbAccFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuSubbAccFlagsTest extends GhidraScript {

    private static final long CODE = 0xc100L;        // inside GS RAM on the F28377D map
    private static final long MOV_AL_I16 = 0x28A9L;  // MOV @AL,#16bit  (2 words)
    private static final long MOV_AH_I16 = 0x28A8L;  // MOV @AH,#16bit  (2 words)
    private static final long SUBB_ACC = 0x1900L;    // SUBB ACC,#8bit  (| imm8)

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. the fill-loop case: the counter hits zero, so Z must be set and the loop ends.
            check(emu, sp, 0x0001L, 0x0000L, 1, 0x00000000L, 1, "1 - 1 -> 0, Z set");

            // 2. an ordinary non-zero result leaves Z clear.
            check(emu, sp, 0x0010L, 0x0000L, 1, 0x0000000FL, 0, "0x10 - 1 -> 0xf, Z clear");

            // 3. STALE-FLAG case -- the one that matters. Drive ACC to 0 first so Z is 1, then
            //    subtract 0 from a non-zero ACC: Z must be RECOMPUTED to 0, not left set. This is
            //    the state the fill loop is in on every iteration after the first, and the only
            //    case the original no-flags body could not pass.
            emu.writeRegister("ACC", 0L);
            long pc = CODE;
            pc = emit(emu, sp, pc, MOV_AL_I16, 0x0001L);
            pc = emit(emu, sp, pc, MOV_AH_I16, 0x0000L);
            pc = emit1(emu, sp, pc, SUBB_ACC | 1L);        // -> ACC 0, Z 1
            pc = emit(emu, sp, pc, MOV_AL_I16, 0x1234L);
            pc = emit(emu, sp, pc, MOV_AH_I16, 0x0009L);   // -> ACC 0x91234
            pc = emit1(emu, sp, pc, SUBB_ACC | 0L);        // - 0 -> still 0x91234, Z must clear
            emu.writeRegister("PC", CODE);
            for (int i = 0; i < 6; i++) {
                if (!emu.step(monitor)) {
                    println("EmuSubbAccFlagsTest.java> FAIL: step " + i + ": " + emu.getLastError());
                    failures++;
                    break;
                }
            }
            expect("stale-Z: ACC 0x91234 after -0",
                emu.readRegister("ACC").longValue() & 0xffffffffL, 0x91234L);
            expect("stale-Z: Z cleared by a non-zero result", emu.readRegister("Z").longValue(), 0L);

            // 4. borrow direction. SPRU430F: C is CLEARED if the subtraction borrows, SET if not.
            checkC(emu, sp, 0x0005L, 1, 1, "5 - 1 does not borrow, C set");
            checkC(emu, sp, 0x0000L, 1, 0, "0 - 1 borrows, C cleared");

            if (failures == 0) {
                println("EmuSubbAccFlagsTest.java> PASS: SUBB ACC,#8bit sets Z and C (5 cases)");
            } else {
                println("EmuSubbAccFlagsTest.java> FAIL: " + failures + " check(s) failed");
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** Load ACC from an AH:AL pair, subtract imm8, and check the result and Z. */
    private void check(EmulatorHelper emu, AddressSpace sp, long al, long ah, long imm8,
            long wantAcc, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", 0L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);       // start from the opposite value
        long pc = CODE;
        pc = emit(emu, sp, pc, MOV_AL_I16, al);
        pc = emit(emu, sp, pc, MOV_AH_I16, ah);
        pc = emit1(emu, sp, pc, SUBB_ACC | (imm8 & 0xff));
        emu.writeRegister("PC", CODE);
        for (int i = 0; i < 3; i++) {
            if (!emu.step(monitor)) {
                println("EmuSubbAccFlagsTest.java> FAIL (" + what + "): " + emu.getLastError());
                failures++;
                return;
            }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    /** Same shape, asserting the carry/borrow flag instead. */
    private void checkC(EmulatorHelper emu, AddressSpace sp, long al, long imm8, long wantC,
            String what) throws Exception {
        emu.writeRegister("ACC", 0L);
        emu.writeRegister("C", wantC == 1 ? 0L : 1L);       // start from the opposite value
        long pc = CODE;
        pc = emit(emu, sp, pc, MOV_AL_I16, al);
        pc = emit(emu, sp, pc, MOV_AH_I16, 0L);
        pc = emit1(emu, sp, pc, SUBB_ACC | (imm8 & 0xff));
        emu.writeRegister("PC", CODE);
        for (int i = 0; i < 3; i++) {
            if (!emu.step(monitor)) {
                println("EmuSubbAccFlagsTest.java> FAIL (" + what + "): " + emu.getLastError());
                failures++;
                return;
            }
        }
        expect(what + " [C]", emu.readRegister("C").longValue(), wantC);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuSubbAccFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    /** Write a 2-word instruction; returns the next word address. */
    private long emit(EmulatorHelper emu, AddressSpace sp, long word, long w1, long w2) throws Exception {
        emu.writeMemoryValue(sp.getAddress(word * 2), 2, w1);
        emu.writeMemoryValue(sp.getAddress((word + 1) * 2), 2, w2);
        return word + 2;
    }

    /** Write a 1-word instruction; returns the next word address. */
    private long emit1(EmulatorHelper emu, AddressSpace sp, long word, long w1) throws Exception {
        emu.writeMemoryValue(sp.getAddress(word * 2), 2, w1);
        return word + 1;
    }
}
