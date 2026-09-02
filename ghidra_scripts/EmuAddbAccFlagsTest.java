// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for ADDB ACC,#8bit flag updates.
//
// The constructor originally had no flag logic at all -- just `ACC = ACC + zext(imm8:1)`. Nothing
// in the decode tests could see that: the mnemonic and the operand were always right, and
// run_fw_parity only compares text against dis2000. It is a semantic hole, so only emulation
// reaches it.
//
// It is not academic. TI's C startup tests a weak linker symbol against the "absent" sentinel with
// exactly this idiom:
//
//     MOV  @AL,#0xffff
//     MOV  @AH,#0xffff        ; ACC = 0xffffffff, i.e. the symbol is absent
//     ADDB ACC,#1             ; -> 0, so Z must be SET
//     SB   skip,EQ            ; and the branch must be taken
//
// With Z never written, the branch read a stale flag from some earlier instruction, fell through,
// and _c_int00 went on to "call" the copy-table walker with 0x3fffff -- the absent pointer -- and
// walked garbage. That is how this was found: EmulateStartup replaying a real application image.
//
// Case 3 is the one that actually reproduces the firmware failure. Cases 1 and 2 pass even with a
// partially-wrong implementation that sets Z only from the operand; case 3 pins the STALE-flag
// behaviour by deliberately setting Z=1 first, then requiring a non-zero result to clear it.
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuAddbAccFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuAddbAccFlagsTest extends GhidraScript {

    private static final long CODE = 0xc100L;      // inside GS RAM on the F28377D map
    private static final long MOV_AL_I16 = 0x28A9L;  // MOV @AL,#16bit  (2 words)
    private static final long MOV_AH_I16 = 0x28A8L;  // MOV @AH,#16bit  (2 words)
    private static final long ADDB_ACC = 0x0900L;    // ADDB ACC,#8bit  (| imm8)

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // 1. the firmware case: 0xffffffff + 1 == 0, so Z must be set.
            check(emu, sp, 0xffffL, 0xffffL, 1, 0x00000000L, 1, "0xffffffff + 1 -> 0, Z set");

            // 2. an ordinary non-zero result leaves Z clear.
            check(emu, sp, 0x0010L, 0x0000L, 1, 0x00000011L, 0, "0x10 + 1 -> 0x11, Z clear");

            // 3. STALE-FLAG case -- the one that matters. Run the wrap-to-zero first so Z is 1,
            //    then add 0 to a non-zero ACC: Z must be RECOMPUTED to 0, not left set. This is
            //    precisely the sequence _c_int00 executes (the -1 test, then `MOV @AL/@AH` of a
            //    real address followed by `ADDB ACC,#0`), and the only case the original
            //    no-flags body could not pass.
            emu.writeRegister("ACC", 0L);
            long pc = CODE;
            pc = emit(emu, sp, pc, MOV_AL_I16, 0xffffL);
            pc = emit(emu, sp, pc, MOV_AH_I16, 0xffffL);
            pc = emit1(emu, sp, pc, ADDB_ACC | 1L);        // -> ACC 0, Z 1
            pc = emit(emu, sp, pc, MOV_AL_I16, 0x1234L);
            pc = emit(emu, sp, pc, MOV_AH_I16, 0x0009L);   // -> ACC 0x91234
            pc = emit1(emu, sp, pc, ADDB_ACC | 0L);        // + 0 -> still 0x91234, Z must clear
            emu.writeRegister("PC", CODE);
            for (int i = 0; i < 6; i++) {
                if (!emu.step(monitor)) {
                    println("EmuAddbAccFlagsTest.java> FAIL: step " + i + ": " + emu.getLastError());
                    failures++;
                    break;
                }
            }
            expect("stale-Z: ACC 0x91234 after +0", emu.readRegister("ACC").longValue() & 0xffffffffL, 0x91234L);
            expect("stale-Z: Z cleared by a non-zero result", emu.readRegister("Z").longValue(), 0L);

            if (failures == 0) println("EmuAddbAccFlagsTest.java> PASS: ADDB ACC,#8bit sets Z (3 cases)");
            else println("EmuAddbAccFlagsTest.java> FAIL: " + failures + " check(s) failed");
        }
        finally {
            emu.dispose();
        }
    }

    /** Load ACC from an AH:AL pair, add imm8, and check the result and Z. */
    private void check(EmulatorHelper emu, AddressSpace sp, long al, long ah, long imm8,
            long wantAcc, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", 0L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);       // start from the opposite value
        long pc = CODE;
        pc = emit(emu, sp, pc, MOV_AL_I16, al);
        pc = emit(emu, sp, pc, MOV_AH_I16, ah);
        pc = emit1(emu, sp, pc, ADDB_ACC | (imm8 & 0xff));
        emu.writeRegister("PC", CODE);
        for (int i = 0; i < 3; i++) {
            if (!emu.step(monitor)) {
                println("EmuAddbAccFlagsTest.java> FAIL (" + what + "): " + emu.getLastError());
                failures++;
                return;
            }
        }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuAddbAccFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
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
