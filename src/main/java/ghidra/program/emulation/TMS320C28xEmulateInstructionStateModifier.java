// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
/* ###
 * TMS320C28x emulation support.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package ghidra.program.emulation;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Emulation support for TMS320C28x behaviour that plain SLEIGH cannot express: the
 * single-instruction RPT repeat under emulation, the VCU-II CRC accumulate, and the FPU
 * non-IEEE conditioning / flag semantics.
 *
 * <p><b>What moved to SLEIGH, and what had to stay.</b> RPT and RPTB are now modeled in
 * SLEIGH via a {@code :^instruction} prefix wrapper gated on the {@code rpt_active} /
 * {@code rptb_flag} / {@code rpt_phase} context bits (see
 * {@code data/languages/tms320c28x_rpt.sinc} for the wrappers and
 * {@code tms320c28x_more.sinc} / {@code tms320c28x_fpu.sinc} for the bodies). The wrapper
 * approach is adopted from mwdmwd/ghidra-c28x (Apache-2.0) and buys something the old
 * state-modifier loop never could: the DECOMPILER sees the repeat. The {@code countSignBits}
 * CALLOTHER was likewise retired in favour of a pure-SLEIGH CSB ACC built on the
 * {@code lzcount} primitive (see {@code tms320c28x_ext56.sinc}).
 *
 * <p><b>RPTB emulates from SLEIGH alone; RPT does not.</b> The wrappers are armed by
 * {@code globalset}, and Ghidra's emulator applies a {@code globalset} context commit one
 * instruction too late: the value intended for the target address only becomes visible
 * after that instruction has already been decoded and executed. RPTB targets the block-end
 * address, several instructions ahead, so the commit has landed by the time it matters and
 * the wrapper fires correctly. RPT targets {@code inst_next} — the very next instruction —
 * so the commit is always late, the plain base constructor wins the pattern match, and the
 * wrapper's p-code never runs ({@code RPTC} is never decremented). Measured directly by
 * dumping {@code contextreg} per emulated step:
 *
 * <pre>
 *   PC=0xc011  RPTC=15  ctx=0x04000000   rpt_phase=1, rpt_active=0  -&gt; base matches
 *   PC=0xc012  RPTC=15  ctx=0x10000000   rpt_active=1, rpt_phase=0  -&gt; wrapper, one word late
 * </pre>
 *
 * This holds whether the bytes are written straight into emulator memory or properly
 * disassembled into the program first, so {@link #postExecuteCallback} below retains the
 * RPT arm / re-issue logic — and ONLY that. It is what keeps the {@code RPT #15 || SUBCU}
 * unsigned divide and {@code RPT || VCRCxx} block CRC emulating. The RPTB half of the old
 * callback is gone for good; SLEIGH handles it.
 *
 * <p>The two mechanisms do not fight: because the wrapper never fires at {@code inst_next}
 * under emulation, the callback is the only thing driving the RPT loop there, while under
 * disassembly the callback does not run at all and the wrapper is the only thing modelling
 * it. Verified by the RPT and RPTB cases of {@code ghidra_scripts/EmuRptTest.java}.
 *
 * <p>What remains in this class:
 * <ul>
 *   <li><b>RPT loop re-issue</b> — see {@link #postExecuteCallback}.</li>
 *   <li><b>VCRC8L / VCRC16P1L / VCRC32L</b> — the VCU-II CRC accumulate (polynomials 0x07 /
 *       0x8005 / 0x04C11DB7 per SPRUHS1, MSB-first, low byte, CRCMSGFLIP=0). Kept as a
 *       pcodeop rather than open-coded in SLEIGH because the intrinsic name renders as
 *       {@code VCRC = VCRC8L(VCRC, src)} in the decompiler, which is the direct signal
 *       used to identify CAN CRC compute/check code. Open-coding the 8-iteration MSB-first
 *       bit loop would replace that with an unreadable shift-and-XOR salad. The bit loop is
 *       validated against the standard catalog check values (CRC-8/SMBUS, CRC-16/BUYPASS,
 *       CRC-32/MPEG-2). Silicon message-bit reflection (CRCMSGFLIP=1) is NOT modeled --
 *       confirm against a captured frame before trusting the numeric result for an
 *       equivalence check. Tracked for eventual pure-SLEIGH migration; see the follow-up
 *       issue linked from THIRD-PARTY.md.
 *   <li><b>TMU_COND_OPERAND / FPU_MINMAX_FLUSH / FPU_UNDERFLOW / FPU_OVERFLOW</b> — the
 *       non-IEEE FPU input/result conditioning and the LU/LV latched exception flags
 *       (SPRUHS1C §7.3, §7.5.2). Open-coding these inline would land three internal
 *       branches per invocation in the decompiled listing; kept as intrinsics for the
 *       same readability reason as VCRC.
 * </ul>
 */
public class TMS320C28xEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	// RPT opcodes: high byte 0xF6 (RPT #imm8) / 0xF7 (RPT loc16), single word.
	private static final int RPT_IMM_OPHI8 = 0xF6;
	private static final int RPT_LOC_OPHI8 = 0xF7;
	// loc16 register-direct mode selector (@ARn): loc byte bits[7:3] == 0b10100.
	private static final int LOC_MODE5_REGDIRECT = 0x14;

	// RPT (single-instruction-repeat) state. Not nestable on this core (a single RPTC), so
	// one level is hardware-accurate.
	private boolean rptActive = false;
	private long rptWord;      // word address of the instruction being repeated
	private long rptRemaining; // re-executions still owed after the natural first pass

	public TMS320C28xEmulateInstructionStateModifier(Emulate emulate) {
		super(emulate);
		// Register the custom compute pcodeops. Guard each so a name that a future .sla no longer
		// defines degrades just that op to Ghidra's default (opaque) instead of throwing out of the
		// constructor and disabling every other behavior with it.
		tryRegister("VCRC8L", new VcrcBehavior(0x07L, 8));
		tryRegister("VCRC16P1L", new VcrcBehavior(0x8005L, 16));
		tryRegister("VCRC32L", new VcrcBehavior(0x04C11DB7L, 32));
		tryRegister("TMU_COND_OPERAND", new FpuConditionBehavior(true, false));
		tryRegister("FPU_MINMAX_FLUSH", new FpuConditionBehavior(false, true));
		tryRegister("FPU_UNDERFLOW", new FpuArithFlagBehavior(false));
		tryRegister("FPU_OVERFLOW", new FpuArithFlagBehavior(true));
	}

	private void tryRegister(String name, OpBehaviorOther behavior) {
		try {
			registerPcodeOpBehavior(name, behavior);
		}
		catch (LowlevelError e) {
			// pcodeop not defined in this language revision -- leave it opaque.
		}
	}

	/**
	 * Drive the RPT single-instruction repeat under emulation, which the SLEIGH wrapper
	 * cannot do (see the class comment: {@code globalset(inst_next, ...)} lands one
	 * instruction late in the emulator). After each instruction, arm on an RPT opcode and
	 * then re-issue the following instruction until the count is exhausted -- precisely what
	 * the hardware does. RPTB is deliberately NOT handled here; its wrapper works, because
	 * its {@code globalset} target is far enough ahead.
	 *
	 * <p>Word addresses throughout: this is a wordsize=2 space, so {@code Address.getOffset()}
	 * is a byte offset (word&nbsp;&times;&nbsp;2).
	 */
	@Override
	public void postExecuteCallback(Emulate emu, Address lastExecuteAddress,
			PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress)
			throws LowlevelError {

		MemoryState mem = emu.getMemoryState();
		AddressSpace space = lastExecuteAddress.getAddressSpace();
		long lastByteOff = lastExecuteAddress.getOffset();
		int w0 = (int) (mem.getValue(space, lastByteOff, 2) & 0xFFFF);
		int ophi8 = w0 >>> 8;

		// --- arm a single-instruction RPT ----------------------------------------
		if (ophi8 == RPT_IMM_OPHI8 || ophi8 == RPT_LOC_OPHI8) {
			long count;
			if (ophi8 == RPT_IMM_OPHI8) {                    // RPT #imm8
				count = w0 & 0xFF;
			}
			else {                                           // RPT loc16
				int loc = w0 & 0xFF;
				if ((loc >>> 3) == LOC_MODE5_REGDIRECT) {    // @ARn
					count = mem.getValue("AR" + (loc & 7)) & 0xFFFF;
				}
				else {
					rptActive = false;                       // unknown count source: execute once
					return;
				}
			}
			// The next instruction (currentAddress) executes count+1 times: once naturally,
			// then `count` redirects back to it.
			rptWord = currentAddress.getOffset() >> 1;
			rptRemaining = count;
			rptActive = count > 0;
			return;
		}

		// --- re-issue the repeated instruction until the RPT count is exhausted ---
		if (rptActive && (lastByteOff >> 1) == rptWord) {
			if (rptRemaining > 0) {
				rptRemaining--;
				emu.setExecuteAddress(space.getAddress(rptWord << 1));
			}
			else {
				rptActive = false;
			}
		}
	}

	// =========================================================================
	// CALLOTHER behaviors
	// =========================================================================

	/**
	 * FPU operand / result conditioning, SPRUHS1C §7.5.2. The C28x FPU is not IEEE-clean:
	 * denormals are treated as zero and NaNs as infinity. The SLEIGH side calls these as
	 * intrinsics rather than open-coding the bit tests, because inline they cost three
	 * internal branches per invocation and land in the decompiled output; see the macro
	 * comments in tms320c28x_fpu.sinc.
	 *
	 * <p>Two variants are wired up, differing in how they treat the sign and the ±0 case:
	 * <ul>
	 * <li><b>TMU input</b> (TMU_COND_OPERAND, {@code signedNaN}): denormal or ±0 becomes
	 * +0, and a NaN keeps its sign, becoming ±inf.</li>
	 * <li><b>MAX/MIN result</b> (FPU_MINMAX_FLUSH, {@code preserveZeroSign}): a true ±0
	 * passes through unchanged (only a non-zero denormal is flushed), because this is a
	 * value on its way to a register rather than an arithmetic input.</li>
	 * </ul>
	 *
	 * <p>The compare-input variant ({@code signedNaN = false}, sign dropped on NaN) is what
	 * the FPU applies to CMPF32/MAXF32/MINF32 operands, but the SLEIGH side deliberately
	 * does not model it -- see the comment on {@code update_stf_cmp} in
	 * tms320c28x_fpu.sinc. The parameterisation is kept so wiring it back up is a
	 * one-line change here plus one in the sinc.
	 */
	private static final class FpuConditionBehavior implements OpBehaviorOther {
		private static final long EXP_MASK = 0x7F800000L;
		private static final long MANT_MASK = 0x007FFFFFL;
		private static final long SIGN_MASK = 0x80000000L;

		private final boolean signedNaN;
		private final boolean preserveZeroSign;

		FpuConditionBehavior(boolean signedNaN, boolean preserveZeroSign) {
			this.signedNaN = signedNaN;
			this.preserveZeroSign = preserveZeroSign;
		}

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (out == null || inputs.length < 1) {
				return;
			}
			MemoryState mem = emu.getMemoryState();
			long v = mem.getValue(inputs[0]) & 0xFFFFFFFFL;
			long exp = v & EXP_MASK;
			long result;
			if (exp == 0) {
				// zero or denormal
				result = (preserveZeroSign && (v & MANT_MASK) == 0) ? v : 0L;
			}
			else if (exp == EXP_MASK && (v & MANT_MASK) != 0) {
				// NaN -> infinity
				result = signedNaN ? ((v & SIGN_MASK) | EXP_MASK) : EXP_MASK;
			}
			else {
				result = v;
			}
			mem.setValue(out, result);
		}
	}

	/**
	 * The latched exception flags LUF / LVF, SPRUHS1C 7.3.4 and 7.3.5.
	 *
	 * <p>Underflow is "the operation generated a value too small to represent in the given
	 * format" (zero is returned) and overflow "too large" (±Inf is returned). Neither is
	 * decidable from the rounded 32-bit result alone -- {@code 0.0f * 5.0f} returns a zero
	 * that is not an underflow, and {@code Inf + 1.0f} an infinity that is not an
	 * overflow. So the operands and the operation come in and the true result is recomputed
	 * in double precision, which is exact for every one of these operations on float
	 * inputs and cannot itself under- or overflow at these magnitudes.
	 *
	 * <p>Inputs are conditioned first: 7.3.3 makes a denormal operand read as zero and
	 * 7.3.7 makes a NaN read as infinity, so an underflow verdict is decided on what the
	 * hardware actually fed the multiplier, not on the raw register bits.
	 *
	 * <p>Because a denormal result is never generated (7.3.3), the underflow test is
	 * "exact result is non-zero but smaller in magnitude than the smallest NORMAL float" --
	 * a would-be-denormal is flushed to zero and counts. Overflow requires finite operands,
	 * so an infinity merely propagating through does not latch.
	 *
	 * <p>inputs[0] = operation selector, [1] = a, [2] = b (ignored by 1-operand kinds),
	 * [3] = the current latch. The sticky OR is applied here so the SLEIGH side is one
	 * CALLOTHER and one register write per flag.
	 */
	private static final class FpuArithFlagBehavior implements OpBehaviorOther {
		private static final int KIND_MPY = 0;
		private static final int KIND_ADD = 1;
		private static final int KIND_SUB = 2;
		private static final int KIND_DIV = 3;
		private static final int KIND_SQRT = 4;
		private static final int KIND_EINV = 5;
		private static final int KIND_EISQRT = 6;

		/** Smallest positive NORMAL float; anything below is denormal and gets flushed. */
		private static final double MIN_NORMAL = 1.17549435e-38;
		private static final double MAX_FLOAT = 3.4028234663852886e38;

		private final boolean overflow;

		FpuArithFlagBehavior(boolean overflow) {
			this.overflow = overflow;
		}

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (out == null || inputs.length < 4) {
				return;
			}
			MemoryState mem = emu.getMemoryState();
			int kind = (int) mem.getValue(inputs[0]);
			double a = condition((int) mem.getValue(inputs[1]));
			double b = condition((int) mem.getValue(inputs[2]));
			boolean latched = (mem.getValue(inputs[3]) & 1) != 0;

			double exact;
			switch (kind) {
				case KIND_MPY: exact = a * b; break;
				case KIND_ADD: exact = a + b; break;
				case KIND_SUB: exact = a - b; break;
				case KIND_DIV: exact = a / b; break;
				case KIND_SQRT: exact = Math.sqrt(a); break;
				case KIND_EINV: exact = 1.0 / a; break;
				case KIND_EISQRT: exact = 1.0 / Math.sqrt(a); break;
				default: mem.setValue(out, latched ? 1 : 0); return;
			}

			boolean set;
			if (overflow) {
				// A result that is infinite only because an operand already was is not an
				// overflow -- the value was representable all along.
				boolean operandsFinite = !Double.isInfinite(a) && !Double.isInfinite(b);
				set = operandsFinite && !Double.isNaN(exact) && Math.abs(exact) > MAX_FLOAT;
			}
			else {
				set = exact != 0.0 && !Double.isNaN(exact) && !Double.isInfinite(exact)
					&& Math.abs(exact) < MIN_NORMAL;
			}
			mem.setValue(out, (latched || set) ? 1 : 0);
		}

		/** SPRUHS1C 7.3.3 / 7.3.7: denormal reads as zero, NaN reads as infinity. */
		private static double condition(int bits) {
			int exp = bits & 0x7F800000;
			if (exp == 0) {
				return 0.0;                       // zero or denormal
			}
			if (exp == 0x7F800000 && (bits & 0x007FFFFF) != 0) {
				return (bits < 0) ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
			}
			return Float.intBitsToFloat(bits);
		}
	}

	/**
	 * VCU-II CRC accumulate: {@code VCRC = CRCwidth(VCRC, src[7:0])}, MSB-first, no reflection.
	 * inputs[0] = current VCRC, inputs[1] = the loc16 source (low byte feeds the CRC). Only the
	 * width-relevant low bits of VCRC are updated (upper bits preserved), matching the manual's
	 * {@code VCRC[w-1:0] = ...} definition.
	 */
	private static final class VcrcBehavior implements OpBehaviorOther {
		private final long poly;
		private final int width;

		VcrcBehavior(long poly, int width) {
			this.poly = poly;
			this.width = width;
		}

		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (out == null || inputs.length < 2) {
				return;
			}
			MemoryState mem = emu.getMemoryState();
			long vcrc = mem.getValue(inputs[0]);
			int dataByte = (int) (mem.getValue(inputs[1]) & 0xFF);
			long mask = (width == 32) ? 0xFFFFFFFFL : ((1L << width) - 1);
			long crc = vcrc & mask;
			crc ^= ((long) dataByte << (width - 8)) & mask;
			for (int i = 0; i < 8; i++) {
				long top = crc & (1L << (width - 1));
				crc = (top != 0) ? (((crc << 1) ^ poly) & mask) : ((crc << 1) & mask);
			}
			long result = (vcrc & ~mask & 0xFFFFFFFFL) | (crc & mask);
			mem.setValue(out, result);
		}
	}

}
