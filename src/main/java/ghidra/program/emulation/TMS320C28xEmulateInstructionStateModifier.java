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
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Emulation support for the C28x <b>RPTB</b> (repeat-block) zero-overhead hardware loop.
 *
 * <p>RPTB repeats a block of instructions {@code [inst_next, inst_next+RSIZE)} for
 * {@code RC+1} passes. There is <i>no</i> branch instruction at the loop-back point — the
 * CPU compares PC to the block-end after every instruction — so SLEIGH cannot model it
 * (a constructor's p-code can only affect its own instruction, and the block end is an
 * arbitrary instruction with no opcode to hang loop-back p-code on). Ghidra's built-in
 * processors solve exactly this class of problem with a state modifier (e.g. Hexagon's
 * hardware loops), which is what this class does: after each instruction it checks whether
 * we have reached the end of an active RPTB block and, if the repeat count is not yet
 * exhausted, redirects the PC back to the block start — precisely what the hardware does.
 *
 * <p>The C28x RPTB cannot be nested (there is a single RB register), so one level of loop
 * state is hardware-accurate. Word addresses are used throughout: this is a wordsize=2
 * space, so {@code Address.getOffset()} is a byte offset (word&nbsp;&times;&nbsp;2).
 */
public class TMS320C28xEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	// RPTB opcode: LSW high byte == 0xB5 (bit7 selects loc16(0)/#imm(1) count, bits0-6 = RSIZE).
	private static final int RPTB_OPHI8 = 0xB5;
	// loc16 register-direct mode selector (@ARn): loc byte bits[7:3] == 0b10100.
	private static final int LOC_MODE5_REGDIRECT = 0x14;

	private boolean active = false;
	private long startWord;   // first instruction of the block (word address)
	private long endWord;     // one-past the last instruction of the block (word address)
	private long remaining;   // repeats still to perform after the current pass

	public TMS320C28xEmulateInstructionStateModifier(Emulate emulate) {
		super(emulate);
	}

	@Override
	public void postExecuteCallback(Emulate emu, Address lastExecuteAddress,
			PcodeOp[] lastExecutePcode, int lastPcodeIndex, Address currentAddress)
			throws LowlevelError {

		MemoryState mem = emu.getMemoryState();
		AddressSpace space = lastExecuteAddress.getAddressSpace();
		long lastByteOff = lastExecuteAddress.getOffset();

		// --- arm the loop if an RPTB just executed --------------------------------
		int w0 = (int) (mem.getValue(space, lastByteOff, 2) & 0xFFFF);
		if ((w0 >>> 8) == RPTB_OPHI8) {
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
}
