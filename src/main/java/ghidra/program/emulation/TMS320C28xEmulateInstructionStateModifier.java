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
 * Emulation support for TMS320C28x features that plain SLEIGH p-code cannot express.
 *
 * <p>Two categories are handled here:
 *
 * <p><b>1. Hardware repeat loops (RPTB / RPT).</b> These are zero-overhead repeats with an
 * <i>implicit</i> loop-back: the CPU compares PC to a block-end / re-issues a single instruction
 * with no branch opcode to hang p-code on. A constructor's p-code can only affect its own
 * instruction, so SLEIGH cannot model the loop. Ghidra's built-in processors solve exactly this
 * class of problem with a state modifier (e.g. Hexagon's hardware loops), which is what
 * {@link #postExecuteCallback} does: after each instruction it checks whether we reached the end
 * of an active repeat and, if so, redirects the PC — precisely what the hardware does.
 * <ul>
 *   <li><b>RPTB</b> — repeat a block {@code [inst_next, inst_next+RSIZE)} for {@code RC+1} passes.
 *   <li><b>RPT</b> — repeat the single following instruction {@code N+1} times. The C28x uses
 *       {@code RPT #15 || SUBCU} for unsigned division and {@code RPT || VCRCxx} for block CRC,
 *       so modeling RPT (together with the SUBCU / VCRC p-code below) makes those idioms emulate.
 * </ul>
 * Neither RPTB nor RPT can nest on this core (single RB / RPTC), so one level of state each is
 * hardware-accurate. Word addresses are used throughout: this is a wordsize=2 space, so
 * {@code Address.getOffset()} is a byte offset (word&nbsp;&times;&nbsp;2).
 *
 * <p><b>2. Custom compute pcodeops (CALLOTHER).</b> A few instructions compute values with no
 * SLEIGH primitive. Their constructors emit a named pcodeop and this class supplies the behavior:
 * <ul>
 *   <li><b>VCRC8L / VCRC16P1L / VCRC32L</b> — the VCU-II CRC accumulate (polynomials 0x07 /
 *       0x8005 / 0x04C11DB7 per SPRUHS1, MSB-first, low byte, CRCMSGFLIP=0). Lets the emulator
 *       reproduce a CAN-message CRC. The MSB-first bit loop is validated against the standard
 *       catalog check values (CRC-8/SMBUS, CRC-16/BUYPASS, CRC-32/MPEG-2). Silicon message-bit
 *       reflection (the CRCMSGFLIP=1 path) is NOT modeled — confirm against a captured frame
 *       before trusting the numeric result for an equivalence check.
 *   <li><b>countSignBits</b> — CSB ACC (leading redundant sign bits minus one, into T).
 * </ul>
 */
public class TMS320C28xEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	// RPTB opcode: LSW high byte == 0xB5 (bit7 selects loc16(0)/#imm(1) count, bits0-6 = RSIZE).
	private static final int RPTB_OPHI8 = 0xB5;
	// RPT opcodes: high byte 0xF6 (RPT #imm8) / 0xF7 (RPT loc16), single word.
	private static final int RPT_IMM_OPHI8 = 0xF6;
	private static final int RPT_LOC_OPHI8 = 0xF7;
	// loc16 register-direct mode selector (@ARn): loc byte bits[7:3] == 0b10100.
	private static final int LOC_MODE5_REGDIRECT = 0x14;

	// RPTB (block-repeat) state.
	private boolean active = false;
	private long startWord;   // first instruction of the block (word address)
	private long endWord;     // one-past the last instruction of the block (word address)
	private long remaining;   // repeats still to perform after the current pass

	// RPT (single-instruction-repeat) state.
	private boolean rptActive = false;
	private long rptWord;      // word address of the instruction being repeated
	private long rptRemaining; // re-executions still owed after the natural first pass

	public TMS320C28xEmulateInstructionStateModifier(Emulate emulate) {
		super(emulate);
		// Register the custom compute pcodeops. Guard each so a name that a future .sla no longer
		// defines degrades just that op to Ghidra's default (opaque) instead of throwing out of the
		// constructor and disabling the RPTB/RPT loop support with it.
		tryRegister("VCRC8L", new VcrcBehavior(0x07L, 8));
		tryRegister("VCRC16P1L", new VcrcBehavior(0x8005L, 16));
		tryRegister("VCRC32L", new VcrcBehavior(0x04C11DB7L, 32));
		tryRegister("countSignBits", new CountSignBitsBehavior());
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
			// The next instruction (currentAddress) executes count+1 times: once naturally, then
			// `count` redirects back to it.
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
				return;
			}
			rptActive = false;   // done; fall through so RPTB handling still runs this pass
		}

		// --- arm the loop if an RPTB just executed --------------------------------
		if (ophi8 == RPTB_OPHI8) {
			int rsize = w0 & 0x7F;
			int sel = (w0 >>> 7) & 1;
			int w1 = (int) (mem.getValue(space, lastByteOff + 2, 2) & 0xFFFF);
			long count;
			if (sel == 1) {                                  // RPTB #RSIZE, #imm
				count = w1 & 0xFFFF;
			}
			else {                                           // RPTB #RSIZE, loc16
				int loc = w1 & 0xFF;
				if ((loc >>> 3) == LOC_MODE5_REGDIRECT) {    // @ARn
					count = mem.getValue("AR" + (loc & 7)) & 0xFFFF;
				}
				else {
					active = false;                          // unsupported count source: don't loop
					return;
				}
			}
			startWord = (lastByteOff >> 1) + 2;              // instruction after the 2-word RPTB
			endWord = startWord + rsize;                     // block end (exclusive)
			remaining = count;                               // block executes count+1 times total
			active = rsize > 0;
			return;
		}

		// --- at block end, loop back until the count is exhausted ------------------
		if (active && (currentAddress.getOffset() >> 1) == endWord) {
			if (remaining > 0) {
				remaining--;
				emu.setExecuteAddress(space.getAddress(startWord << 1));
			}
			else {
				active = false;
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

	/**
	 * CSB ACC: number of leading bits equal to the sign bit, minus one, into T (0..31).
	 * inputs[0] = ACC. Zero and all-ones both yield 32 sign bits -> T = 31.
	 */
	private static final class CountSignBitsBehavior implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (out == null || inputs.length < 1) {
				return;
			}
			MemoryState mem = emu.getMemoryState();
			long acc = mem.getValue(inputs[0]) & 0xFFFFFFFFL;
			long sign = (acc >>> 31) & 1;
			int count = 0;
			for (int i = 31; i >= 0; i--) {
				if (((acc >>> i) & 1) == sign) {
					count++;
				}
				else {
					break;
				}
			}
			mem.setValue(out, (count - 1) & 0xFFFF);
		}
	}
}
