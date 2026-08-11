// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the FPU status-flag instructions. The disassembly regression
// (tests/run_disasm_test.*) checks the LISTING; this checks the SEMANTICS, by actually
// running the p-code and reading the STF sub-registers back.
//
// It covers the things that are easy to get silently wrong and that no decode test can
// see: SETFLG's split 11-bit FLAG mask (whose halves run the opposite way from the
// #16FHi immediates, so a swap moves RND32 onto NI while the listing still looks
// plausible), the requirement that an unselected flag keeps its value, and SAVE/RESTORE
// round-tripping the register set through the shadows.
//
// NOT yet covered: the FPU_CMP_OPERAND / TMU_COND_OPERAND / FPU_MINMAX_FLUSH behaviours
// in TMS320C28xEmulateInstructionStateModifier. Those need the modifier jar installed
// (tests/build_modifier.*) and a denormal/NaN input fixture, which is a separate test.
//
// Expects tests/fpu_flags.bin imported at address 0. Run headless:
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuFlagTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.List;

public class EmuFlagTest extends GhidraScript {

	private final List<String> failures = new ArrayList<>();
	private EmulatorHelper emu;

	@Override
	public void run() throws Exception {
		Address base = currentProgram.getMemory().getBlocks()[0].getStart();
		emu = new EmulatorHelper(currentProgram);
		try {
			// Start with every modelled STF flag set, so "unselected flags are preserved"
			// is a real assertion rather than 0 == 0.
			emu.writeRegister(emu.getPCRegister(), base.getOffset());
			for (String r : new String[] { "STF_LV", "STF_LU", "STF_NF", "STF_ZF", "STF_NI",
				"STF_ZI", "STF_TF", "STF_RND", "STF_SHDWS" }) {
				emu.writeRegister(r, 1);
			}
			// Distinctive float register values so the SAVE/RESTORE round trip is visible.
			for (int i = 0; i < 8; i++) {
				emu.writeRegister("R" + i + "H", 0x1000 + i);
			}

			// 0x0  SETFLG RNDF32=1 -- FLAG bit 9. If the split-FLAG halves were swapped
			// this would land on NI instead, so it is the load-bearing case.
			step();
			expect("SETFLG RNDF32=1", "STF_RND", 1);
			expect("SETFLG RNDF32=1", "STF_NI", 1);      // untouched, still the preset 1

			// 0x2  SETFLG RNDF32=0 -- same mask, value 0.
			step();
			expect("SETFLG RNDF32=0", "STF_RND", 0);
			expect("SETFLG RNDF32=0", "STF_TF", 1);      // unselected -> preserved

			// 0x4  SETFLG LVF=0,LUF=0
			step();
			expect("SETFLG LVF=0,LUF=0", "STF_LV", 0);
			expect("SETFLG LVF=0,LUF=0", "STF_LU", 0);
			expect("SETFLG LVF=0,LUF=0", "STF_NF", 1);   // unselected -> preserved

			// 0x6  SETFLG TF=1  (already 1; proves the mask does not clear it)
			step();
			expect("SETFLG TF=1", "STF_TF", 1);

			// 0x8  SETFLG NF=0,ZF=1 -- two flags, different values, in one mask.
			step();
			expect("SETFLG NF=0,ZF=1", "STF_NF", 0);
			expect("SETFLG NF=0,ZF=1", "STF_ZF", 1);

			// 0xa  SAVE RNDF32=1 -- copies R0H-R7H + STF to the shadows, sets SHDWS,
			// and applies the SETFLG in the same cycle.
			emu.writeRegister("STF_LU", 1);             // make the shadow copy distinguishable
			step();
			expect("SAVE RNDF32=1", "STF_SHDWS", 1);
			expect("SAVE RNDF32=1", "STF_RND", 1);
			expect("SAVE RNDF32=1", "R3H_s", 0x1003);   // register set reached the shadows

			// 0xc  SAVE LVF=0,LUF=0 -- clears LUF in the working set only.
			step();
			expect("SAVE LVF=0,LUF=0", "STF_LU", 0);

			// 0xe  RESTORE -- working set comes back from the shadows, SHDWS clears.
			emu.writeRegister("R3H", 0xDEAD);
			step();
			expect("RESTORE", "R3H", 0x1003);           // restored from the shadow
			expect("RESTORE", "STF_SHDWS", 0);
			expect("RESTORE", "STF_LU", 1);             // STF came back from the shadow too
		}
		finally {
			emu.dispose();
		}

		if (failures.isEmpty()) {
			println("PASS: all emulation flag assertions");
		}
		else {
			for (String f : failures) {
				println("FAIL " + f);
			}
			throw new AssertionError(failures.size() + " emulation flag assertion(s) failed");
		}
	}

	private void step() throws Exception {
		if (!emu.step(monitor)) {
			throw new AssertionError("emulation step failed: " + emu.getLastError());
		}
	}

	private void expect(String where, String reg, long want) {
		long got = emu.readRegister(reg).longValue();
		if (got != want) {
			failures.add(String.format("%s: %s = 0x%x, expected 0x%x", where, reg, got, want));
		}
	}
}
