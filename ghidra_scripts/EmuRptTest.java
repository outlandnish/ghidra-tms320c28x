// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation smoke test for the pure-SLEIGH RPT and RPTB block-repeat wrappers
// (tms320c28x_rpt.sinc). Neither loop is expressible in single-instruction p-code,
// so the loop-back behaviour lives in `:^instruction` prefix wrappers gated on the
// `rpt_active` / `rptb_flag` / `rpt_phase` context bits. This test drives the two
// canonical idioms:
//
//   - RPT #15 || SUBCU ACC,@AR1  — 16-bit unsigned divide, 100 / 7 → q=14 r=2
//     (ACC = 0x00020000e — AL=14, AH=2). Fires the RPT wrapper 15 times.
//
//   - RPTB end, #4 over a 9-word block (the assembler's minimum) ending in ADDB ACC,#1,
//     then ADDB ACC,#0x10 at the EXCLUSIVE end label (dis2000: RSIZE = block words,
//     label = RPTB+2+RSIZE). 5 passes + the post-block insn once: ACC=0 → 0x15.
//     Also count 0 (one pass, 0x11) and a 2-word last block insn (MOVL XAR4,#imm).
//
// A wrong wrapper firing sequence (or a plain constructor winning the SLEIGH pattern
// resolution race) shows up as ACC/PC values that don't match, or as an early exit
// via emu.step returning false. The test is host-driven (writes bytes into emulator
// memory, then steps), so no fixture .bin is needed.
//
// Run headless (any TMS320C28x program will do as the import target; the emulator
// state doesn't touch the program):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuRptTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuRptTest extends GhidraScript {
    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int fails = 0;
        fails += runRpt(sp);
        fails += runRptb(sp);
        println("EmuRptTest.java> " + (fails == 0 ? "PASS" : "FAIL (" + fails + " sub-cases)"));
    }

    private int runRpt(AddressSpace sp) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // Place at word 0xc010: RPT #15 (0xF60F) then SUBCU ACC,@AR1 (0x1FA1).
            emu.writeMemoryValue(sp.getAddress(0xc010L * 2), 2, 0xF60FL);
            emu.writeMemoryValue(sp.getAddress(0xc011L * 2), 2, 0x1FA1L);
            emu.writeRegister("ACC", 100L);
            emu.writeRegister("AR1", 7L);
            emu.writeRegister("PC",  0xc010L);

            int steps = 0;
            while (emu.readRegister("PC").longValue() < 0xc012L) {
                if (!emu.step(monitor)) {
                    println("RPT FAIL: emu.step at step " + steps + ": " + emu.getLastError());
                    return 1;
                }
                if (++steps > 100) {
                    println("RPT FAIL: loop did not terminate within 100 steps");
                    return 1;
                }
            }
            long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
            if (acc == 0x0002000eL && steps == 17) {
                println("RPT PASS: ACC=0x" + Long.toHexString(acc) + " steps=" + steps);
                return 0;
            }
            println("RPT FAIL: expected ACC=0x0002000e steps=17, got ACC=0x"
                + Long.toHexString(acc) + " steps=" + steps);
            return 1;
        } finally {
            emu.dispose();
        }
    }

    private static final long NOP = 0x7700L, ADDB_ACC_1 = 0x0901L, ADDB_ACC_16 = 0x0910L;

    private int runRptb(AddressSpace sp) throws Exception {
        long[] oneWordLast = {NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, ADDB_ACC_1};
        // MOVL XAR4,#0x12345 = 8f01 2345 (dis2000) as the 2-word last block insn.
        long[] twoWordLast = {NOP, NOP, NOP, NOP, NOP, NOP, ADDB_ACC_1, 0x8f01L, 0x2345L};
        return runRptbCase(sp, "RPTB x5", oneWordLast, 4, 0x15L)
            + runRptbCase(sp, "RPTB x1", oneWordLast, 0, 0x11L)
            + runRptbCase(sp, "RPTB 2-word last", twoWordLast, 4, 0x15L);
    }

    // RPTB end,#count at word 0xc020 (LSW 0xB580|RSIZE, MSW count), the block from 0xc022,
    // then ADDB ACC,#0x10 at the exclusive end label; stop once PC passes that insn.
    private int runRptbCase(AddressSpace sp, String name, long[] block, int count, long wantAcc)
            throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            long w = 0xc020L;
            emu.writeMemoryValue(sp.getAddress(w++ * 2), 2, 0xB580L | block.length);
            emu.writeMemoryValue(sp.getAddress(w++ * 2), 2, count);
            for (long insn : block) {
                emu.writeMemoryValue(sp.getAddress(w++ * 2), 2, insn);
            }
            long end = w;
            emu.writeMemoryValue(sp.getAddress(end * 2), 2, ADDB_ACC_16);
            emu.writeRegister("ACC", 0L);
            emu.writeRegister("PC",  0xc020L);

            int steps = 0;
            while (emu.readRegister("PC").longValue() <= end) {
                if (!emu.step(monitor)) {
                    println(name + " FAIL: emu.step at step " + steps + ": " + emu.getLastError());
                    return 1;
                }
                if (++steps > 200) {
                    println(name + " FAIL: loop did not terminate within 200 steps");
                    return 1;
                }
            }
            long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
            long xar4 = emu.readRegister("XAR4").longValue() & 0xFFFFFFFFL;
            boolean xar4Ok = block[block.length - 2] != 0x8f01L || xar4 == 0x12345L;
            if (acc == wantAcc && xar4Ok) {
                println(name + " PASS: ACC=0x" + Long.toHexString(acc) + " steps=" + steps);
                return 0;
            }
            println(name + " FAIL: expected ACC=0x" + Long.toHexString(wantAcc) + ", got ACC=0x"
                + Long.toHexString(acc) + " XAR4=0x" + Long.toHexString(xar4) + " steps=" + steps);
            return 1;
        } finally {
            emu.dispose();
        }
    }
}
