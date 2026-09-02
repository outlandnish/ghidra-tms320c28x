// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the *XAR7 REPEAT SHADOW on RPT || PREAD.
//
// SPRU430F, PREAD loc16,*XAR7, Repeat: "When repeated, the *XAR7 program-memory address is copied
// to an internal shadow register and the address is post-incremented by 1 during each repetition."
//
// Two consequences, and this test pins both, because getting either one alone still corrupts a
// block copy:
//
//   1. the SOURCE walks forward across repetitions -- otherwise `RPT || PREAD` degenerates from a
//      copy into a fill, writing the first word N times;
//   2. the ARCHITECTURAL XAR7 is left where it started -- the increment happens on the shadow.
//      TI's .cinit walk depends on this: after the copy it advances the pointer itself with
//      `XAR7 += AR1+1`, so a model that also advanced XAR7 would double-count and desynchronise
//      the walk from the second record onward.
//
// SLEIGH reads *XAR7 every iteration and has no shadow, so this is modelled in
// TMS320C28xEmulateInstructionStateModifier, where the RPT re-issue already lives. Symptom when
// it is missing, seen on a real application image: the .cinit walk wrote each 32-bit value with its
// low word correct and the high word a duplicate of that low word -- a copy degenerating into a
// fill, because every iteration re-read the same *XAR7 instead of the next one.
//
// This is a matched-pair test: it exercises the JAR, not the .sla. If it fails after a spec-only
// rebuild, check that the modifier jar was rebuilt too (see CLAUDE.md).
//
// Run headless (any TMS320C28x program works; the test drives memory itself):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuPreadRepeatTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuPreadRepeatTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SRC = 0xc200L;          // "program memory" the copy reads
    private static final long DST = 0xc300L;          // data memory the copy writes
    private static final long RPT_IMM = 0xF600L;      // RPT #8bit          (| imm8)
    private static final long PREAD_XAR6PP = 0x2486L; // PREAD *XAR6++,*XAR7 (verified vs firmware)

    private static final long[] SRC_WORDS = { 0x1111L, 0x2222L, 0x3333L };

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            for (int i = 0; i < SRC_WORDS.length; i++)
                emu.writeMemoryValue(sp.getAddress((SRC + i) * 2), 2, SRC_WORDS[i]);
            for (int i = 0; i < SRC_WORDS.length; i++)
                emu.writeMemoryValue(sp.getAddress((DST + i) * 2), 2, 0L);   // poison

            // RPT #2 || PREAD *XAR6++,*XAR7  -> 3 executions (RPT #N repeats N+1 times)
            emu.writeMemoryValue(sp.getAddress(CODE * 2), 2, RPT_IMM | (SRC_WORDS.length - 1));
            emu.writeMemoryValue(sp.getAddress((CODE + 1) * 2), 2, PREAD_XAR6PP);

            emu.writeRegister("XAR7", SRC);
            emu.writeRegister("XAR6", DST);
            emu.writeRegister("PC", CODE);

            // 1 step for the RPT itself, then one per repetition.
            for (int i = 0; i < 1 + SRC_WORDS.length; i++) {
                if (!emu.step(monitor)) {
                    println("EmuPreadRepeatTest.java> FAIL: step " + i + ": " + emu.getLastError());
                    failures++;
                    return;
                }
            }

            // (1) the source walked forward: a real copy, not a fill
            for (int i = 0; i < SRC_WORDS.length; i++) {
                byte[] b = emu.readMemory(sp.getAddress((DST + i) * 2), 2);
                long got = (b[0] & 0xffL) | ((b[1] & 0xffL) << 8);
                expect("copied word " + i, got, SRC_WORDS[i]);
            }
            // (2) the shadow is internal: XAR7 is unchanged, XAR6 advanced by the copy
            expect("XAR7 unchanged (shadow is internal)",
                emu.readRegister("XAR7").longValue() & 0xffffffffL, SRC);
            expect("XAR6 post-incremented by the copy",
                emu.readRegister("XAR6").longValue() & 0xffffffffL, DST + SRC_WORDS.length);

            if (failures == 0)
                println("EmuPreadRepeatTest.java> PASS: RPT||PREAD walks the source, XAR7 preserved");
            else println("EmuPreadRepeatTest.java> FAIL: " + failures + " check(s) failed");
        }
        finally {
            emu.dispose();
        }
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuPreadRepeatTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
}
