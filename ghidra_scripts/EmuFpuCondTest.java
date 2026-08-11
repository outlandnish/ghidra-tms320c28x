// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the FPU operand/result conditioning intrinsics.
//
// The C28x FPU is not IEEE-clean (SPRUHS1C 7.3.2/7.3.3/7.3.7): denormals are treated as
// zero, negative zero as positive zero, and NaN as infinity. tms320c28x_fpu.sinc models
// that with two pcodeops -- TMU_COND_OPERAND on TMU inputs and FPU_MINMAX_FLUSH on the
// MAX/MIN result -- whose behaviour lives in TMS320C28xEmulateInstructionStateModifier.
//
// A pcodeop is opaque to everything except that class, so this is the ONLY thing that can
// tell whether the behaviour is registered and correct. Two distinct failure modes, both
// covered:
//   * jar missing entirely -- the pspec names the modifier class, so EmulatorHelper fails
//     to instantiate it and the run dies with ClassNotFoundException. Verified by moving
//     the jar aside: it errors loudly, it cannot pass vacuously.
//   * pcodeop NAME wrong (renamed in the .sla, typo in tryRegister) -- that one IS
//     swallowed by the tryRegister guard, the op stays opaque, and the emulator quietly
//     leaves the destination unconditioned. Which is why every assertion below checks a
//     conditioned VALUE rather than merely that stepping succeeded.
//
// Expects tests/fpu_cond.bin, which is asm2000 output for:
//     MINF32 R0H,R1H / MINF32 R0H,R1H / MAXF32 R0H,R1H
//     SQRTF32 R0H,R1H / MPY2PIF32 R0H,R1H / DIVF32 R0H,R1H,R2H
// each followed by four NOPs (pipeline padding), so a case is 1 step + 4 skips.
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.List;

public class EmuFpuCondTest extends GhidraScript {

	// IEEE-754 single bit patterns worth conditioning.
	private static final long DENORM_MIN = 0x00000001L; // smallest denormal, non-zero
	private static final long DENORM_MID = 0x003FFFFFL; // a larger denormal
	private static final long NEG_ZERO = 0x80000000L;
	private static final long POS_ZERO = 0x00000000L;
	private static final long QNAN = 0x7FC00000L;
	private static final long NEG_QNAN = 0xFFC00000L;
	private static final long POS_INF = 0x7F800000L;
	private static final long ONE = 0x3F800000L;

	private final List<String> failures = new ArrayList<>();
	private EmulatorHelper emu;

	@Override
	public void run() throws Exception {
		Address base = currentProgram.getMemory().getBlocks()[0].getStart();
		emu = new EmulatorHelper(currentProgram);
		try {
			emu.writeRegister(emu.getPCRegister(), base.getOffset());

			// --- FPU_MINMAX_FLUSH -------------------------------------------------
			// Case 1: MINF32 R0H,R1H with a denormal that WINS the compare. A non-zero
			// denormal result must flush to zero; unconditioned it would stay 0x00000001.
			set("R0H", DENORM_MIN);
			set("R1H", ONE);
			runCase();
			expect("MINF32 denormal result", "R0H", POS_ZERO);

			// Case 2: same instruction, -0.0 winning. A true signed zero is NOT a denormal
			// and must pass through with its sign intact -- this is what separates
			// FPU_MINMAX_FLUSH from the compare-input conditioning, which folds -0 to +0.
			set("R0H", NEG_ZERO);
			set("R1H", ONE);
			runCase();
			expect("MINF32 -0.0 result", "R0H", NEG_ZERO);

			// Case 3: MAXF32 R0H,R1H with NaN on both sides. IEEE compares are false, so
			// RbH is taken; a NaN result must become infinity with the sign DROPPED
			// (the MIN/MAX flush is the unsigned variant), i.e. -NaN still gives +inf.
			set("R0H", QNAN);
			set("R1H", NEG_QNAN);
			runCase();
			expect("MAXF32 NaN result", "R0H", POS_INF);

			// --- TMU_COND_OPERAND -------------------------------------------------
			// Case 4: SQRTF32 R0H,R1H over a denormal. Conditioned to +0 the root is 0;
			// unconditioned, sqrt of 0x003FFFFF is a small but clearly non-zero normal.
			set("R0H", 0xDEADBEEFL);
			set("R1H", DENORM_MID);
			runCase();
			expect("SQRTF32 denormal input", "R0H", POS_ZERO);

			// Case 5: MPY2PIF32 R0H,R1H over a denormal -- 0 * 2pi = 0. Unconditioned the
			// product of a denormal and 2pi is still non-zero.
			set("R0H", 0xDEADBEEFL);
			set("R1H", DENORM_MID);
			runCase();
			expect("MPY2PIF32 denormal input", "R0H", POS_ZERO);

			// Case 6: DIVF32 R0H,R1H,R2H with a denormal NUMERATOR -- 0 / 1.0 = 0.
			// Unconditioned this is denormal/1.0, which stays denormal and non-zero.
			set("R0H", 0xDEADBEEFL);
			set("R1H", DENORM_MID);
			set("R2H", ONE);
			runCase();
			expect("DIVF32 denormal numerator", "R0H", POS_ZERO);
		}
		finally {
			emu.dispose();
		}

		if (failures.isEmpty()) {
			println("PASS: all FPU conditioning assertions");
		}
		else {
			for (String f : failures) {
				println("FAIL " + f);
			}
			throw new AssertionError(failures.size() + " FPU conditioning assertion(s) failed");
		}
	}

	/** Execute the 2-word FPU instruction, then step over its four NOPs of padding. */
	private void runCase() throws Exception {
		for (int i = 0; i < 5; i++) {
			if (!emu.step(monitor)) {
				throw new AssertionError("emulation step failed: " + emu.getLastError());
			}
		}
	}

	private void set(String reg, long value) {
		emu.writeRegister(reg, value);
	}

	private void expect(String where, String reg, long want) {
		long got = emu.readRegister(reg).longValue() & 0xFFFFFFFFL;
		if (got != want) {
			failures.add(String.format("%s: %s = 0x%08x, expected 0x%08x", where, reg, got, want));
		}
	}
}
