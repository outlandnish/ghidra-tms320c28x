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
//   - RPTB #0, #4 || ADD ACC,#1  — 1-word 5-iteration block, ACC=0 → 5.
//     Fires the RPTB wrapper 4 times (5 total ADD passes).
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

    private int runRptb(AddressSpace sp) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // Place at word 0xc020: RPTB #0, #4 (LSW 0xB580, MSW 0x0004) then ADD ACC,#1 (0x0901).
            emu.writeMemoryValue(sp.getAddress(0xc020L * 2), 2, 0xB580L);
            emu.writeMemoryValue(sp.getAddress(0xc021L * 2), 2, 0x0004L);
            emu.writeMemoryValue(sp.getAddress(0xc022L * 2), 2, 0x0901L);
            emu.writeRegister("ACC", 0L);
            emu.writeRegister("PC",  0xc020L);

            int steps = 0;
            while (steps < 20) {
                if (!emu.step(monitor)) {
                    println("RPTB FAIL: emu.step at step " + steps + ": " + emu.getLastError());
                    return 1;
                }
                steps++;
                if (emu.readRegister("PC").longValue() >= 0xc023L
                        && emu.readRegister("PC").longValue() < 0xd000L) {
                    break;
                }
            }
            long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
            long pc  = emu.readRegister("PC").longValue()  & 0xFFFFFFFFL;
            if (acc == 5L && pc == 0xc023L && steps == 6) {
                println("RPTB PASS: ACC=" + acc + " PC=0x" + Long.toHexString(pc) + " steps=" + steps);
                return 0;
            }
            println("RPTB FAIL: expected ACC=5 PC=0xc023 steps=6, got ACC=" + acc
                + " PC=0x" + Long.toHexString(pc) + " steps=" + steps);
            return 1;
        } finally {
            emu.dispose();
        }
    }
}
