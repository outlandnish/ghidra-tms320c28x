// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// How a TI switch dispatch LOOKS to a matcher on this module, shared by the two passes
// that recognize one: TMS320C28xSwitchAnalyzer (canonicalizes the index so Decompiler
// Switch Analysis can enumerate the table) and TMS320C28xProgramReadSwitchAnalyzer
// (installs an override for the PREAD form, which DSA cannot enumerate at all).
//
// These lived twice, once per analyzer, and the copies drifted: issue #62 fixed the
// switch analyzer to match PRINTED FIELDS rather than Ghidra operand indices -- this
// module's SLEIGH bakes registers into constructor display sections, so `PREAD @AH,*XAR7`
// reports ZERO operands and `MOVL @XAR7,ACC` reports an operand with an empty object
// list -- and the PREAD analyzer's copy kept the old operand-index predicates and
// silently matched nothing. One home so the next such fix cannot reach only one pass.
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

/** Instruction-shape predicates for the TI switch-dispatch schedules. */
final class TMS320C28xSwitchShapes {

	/** Code addresses are 22-bit; the upper bits of a table entry are not address. */
	static final long CODE_ADDRESS_MASK = 0x003fffffL;

	private TMS320C28xSwitchShapes() {
	}

	/**
	 * {@code LB *XAR7} -- the terminal computed branch.
	 *
	 * <p>Opcode 0x7620 renders {@code *XAR7} as a print literal here, so the instruction
	 * carries ZERO operands -- distinct from the immediate long branch {@code LB <target>},
	 * which has one. Match by mnemonic + operand count + the {@code *XAR7} print form, and
	 * confirm the resolved computed-jump flow, rather than looking for XAR7 as operand 0
	 * (upstream mwdmwd's shape, which is absent on this module).
	 */
	static boolean isComputedXar7Branch(Instruction instruction) {
		return isMnemonic(instruction, "lb") && instruction.getNumOperands() == 0 &&
			instruction.toString().toUpperCase().endsWith("*XAR7") &&
			instruction.getFlowType().isJump() && instruction.getFlowType().isComputed();
	}

	/**
	 * {@code MOVL XAR7,*+XAR7[0]} -- the data-space table entry load.
	 *
	 * <p>Printed-field matched: the destination is baked into the display section, so the
	 * instruction reports ONE operand (the {@code *+XAR7[0]} source) and the destination is
	 * not at operand 0 at all.
	 */
	static boolean isNativeLongwordLoad(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || instruction.getNumOperands() == 0 ||
			!isPrintedRegister(instruction, 0, "XAR7")) {
			return false;
		}
		Object[] objects = instruction.getOpObjects(instruction.getNumOperands() - 1);
		if (objects.length != 2 || !(objects[0] instanceof Register register) ||
			!(objects[1] instanceof Scalar offset)) {
			return false;
		}
		return register.getName().equalsIgnoreCase("XAR7") && offset.getSignedValue() == 0;
	}

	/**
	 * {@code PREAD @AL,*XAR7} -- one half of the program-space table entry load.
	 *
	 * <p>BOTH fields are display literals here, so this arrives with no operands at all;
	 * match the destination as printed and the {@code *XAR7} tail.
	 */
	static boolean isPreadInto(Instruction instruction, String destination) {
		return isMnemonic(instruction, "pread") && isPrintedRegister(instruction, 0, destination) &&
			instruction.toString().toUpperCase().endsWith("*XAR7");
	}

	/**
	 * {@code MOVL XAR7,#table} -- the table base load. Printed-field matched for the same
	 * reason as {@link #isNativeLongwordLoad}: only the immediate is a real operand, so the
	 * base is not at operand 1.
	 */
	static Scalar immediateTableBase(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || !isPrintedRegister(instruction, 0, "XAR7")) {
			return null;
		}
		return onlyScalarOperand(instruction);
	}

	static Address tableAddress(Instruction tableInstruction, Scalar scalar) {
		return wordAddress(tableInstruction.getAddress(), scalar.getUnsignedValue() & CODE_ADDRESS_MASK);
	}

	/** {@code ADDU ACC,@ARn} -- the unsigned accumulate; yields the index register. */
	static String unsignedAccumulateSource(Instruction instruction) {
		return isMnemonic(instruction, "addu") && isRegisterOperand(instruction, 0, "ACC")
				? auxiliaryRegisterOperand(instruction, 1)
				: null;
	}

	/**
	 * {@code MOVZ ARn,@AL} -- the scaled index read back out of the accumulator's low half.
	 * Printed-field matched: the destination is baked into the display section, so this can
	 * arrive carrying a single operand.
	 */
	static boolean isMovzAccumulatorLow(Instruction instruction, String register) {
		return isMnemonic(instruction, "movz") && isPrintedRegister(instruction, 0, register) &&
			isPrintedRegister(instruction, 1, "AL");
	}

	/** The auxiliary register AR0..AR7 named by an operand, or null. */
	static String auxiliaryRegisterOperand(Instruction instruction, int operand) {
		for (int number = 0; number <= 7; number++) {
			String name = "AR" + number;
			if (isRegisterOperand(instruction, operand, name)) {
				return name;
			}
		}
		return null;
	}

	/**
	 * The immediate of an add or subtract on a 16-bit register, as a signed delta.
	 *
	 * <p>Sign-extended HERE, from the width the mnemonic implies, rather than through
	 * {@code Scalar.getSignedValue()}, which extends from whatever width SLEIGH happened to
	 * build the scalar at. Both directions of that go wrong: a bound folded into a 16-bit
	 * register arrives as {@code ADD @AR6,#0xf9fe} on a scalar wide enough that it reads as a
	 * large positive number and is silently rejected, while the byte forms carry a genuinely
	 * 8-bit immediate -- {@code ADDB @AH,#0xff} is minus one, not 255.
	 *
	 * <p>{@code ADDB}/{@code SUBB} on an auxiliary register take a 7-bit UNSIGNED immediate
	 * (SPRU430F), which the 8-bit two's-complement read below leaves unchanged, so one rule
	 * covers both operand forms of the byte mnemonics.
	 */
	static Long recoverWordImmediateDelta(Instruction instruction, String register) {
		if (instruction == null || !isRegisterOperand(instruction, 0, register)) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		if (scalar == null) {
			return null;
		}
		boolean byteForm = isMnemonic(instruction, "addb") || isMnemonic(instruction, "subb");
		long raw = scalar.getUnsignedValue();
		if (raw > (byteForm ? 0xff : 0xffff)) {
			return null;
		}
		long value = byteForm ? (byte) raw : (short) raw;
		if (isMnemonic(instruction, "add") || isMnemonic(instruction, "addb")) {
			return value;
		}
		if ((isMnemonic(instruction, "sub") || isMnemonic(instruction, "subb")) && value >= 0) {
			return -value;
		}
		return null;
	}

	static boolean isImmediateAdd(Instruction instruction, String mnemonic, String destination,
			long value) {
		Scalar scalar = scalarOperand(instruction, 1);
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) && scalar != null &&
			scalar.getUnsignedValue() == value;
	}

	static boolean isRegisterMove(Instruction instruction, String mnemonic, String destination,
			String source) {
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) &&
			isRegisterOperand(instruction, 1, source);
	}

	static boolean isMnemonic(Instruction instruction, String mnemonic) {
		return instruction != null && instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
	}

	static boolean isRegisterOperand(Instruction instruction, int operand, String registerName) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		Register register = instruction.getRegister(operand);
		if (register != null) {
			return register.getName().equalsIgnoreCase(registerName);
		}
		// Register-valued loc32 subtables may expose the operand as dynamic even though the
		// rendered operand and its sole object are the register itself.
		Object[] objects = instruction.getOpObjects(operand);
		if (objects.length == 1 && objects[0] instanceof Register objectRegister &&
			objectRegister.getName().equalsIgnoreCase(registerName)) {
			return true;
		}
		for (Object object : objects) {
			if (object instanceof Register objectRegister &&
				objectRegister.getName().equalsIgnoreCase(registerName)) {
				return true;
			}
		}
		// This module's SLEIGH renders some registers into the print form rather than exposing
		// them as operand objects, so an operand can be present but carry nothing to match
		// against: `MOVL ACC,@XAR7` reports two operands with an EMPTY object list on operand 0.
		// Fall back to the rendered text, accepting the "@" register-direct and "*" indirect
		// markers this module prints, so callers that matched via getRegister still work here.
		String text = instruction.getDefaultOperandRepresentation(operand);
		if (text == null) {
			return false;
		}
		String bare = text.startsWith("@") || text.startsWith("*") ? text.substring(1) : text;
		return bare.equalsIgnoreCase(registerName);
	}

	static Scalar scalarOperand(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? null
				: instruction.getScalar(operand);
	}

	/**
	 * The sole scalar among an instruction's operands, or null when there is not exactly one.
	 * Used where the printed field carrying the immediate is not at a stable operand index
	 * because an earlier field is a display literal.
	 */
	static Scalar onlyScalarOperand(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Scalar found = null;
		for (int i = 0; i < instruction.getNumOperands(); i++) {
			Scalar scalar = instruction.getScalar(i);
			if (scalar == null) {
				continue;
			}
			if (found != null) {
				return null;
			}
			found = scalar;
		}
		return found;
	}

	/**
	 * The comma-separated fields of an instruction as printed, mnemonic removed.
	 *
	 * <p>Ghidra's operand numbering and the TI listing text only agree when every printed
	 * field is backed by an operand. On this module they routinely do not, because several
	 * constructors bake a register into their display section: {@code MOVL XAR7,#0x8159a}
	 * prints two fields but exposes ONE operand (the immediate), and
	 * {@code MOVL XAR7,*+XAR7[0]} prints two but exposes one (the source). Predicates written
	 * against the schedules in the analyzers' doc comments -- which are listing text -- have
	 * to index the text, not the operand array, or they silently read the wrong field and
	 * never match.
	 *
	 * <p>Splitting on commas is safe for the operand forms admitted here; the only multi-part
	 * field is a shift ({@code @AR6<<#0x1}), which carries no comma.
	 */
	private static String[] printedFields(Instruction instruction) {
		if (instruction == null) {
			return new String[0];
		}
		String text = instruction.toString();
		String mnemonic = instruction.getMnemonicString();
		if (text.regionMatches(true, 0, mnemonic, 0, mnemonic.length())) {
			text = text.substring(mnemonic.length());
		}
		text = text.trim();
		if (text.isEmpty()) {
			return new String[0];
		}
		String[] fields = text.split(",");
		for (int i = 0; i < fields.length; i++) {
			fields[i] = fields[i].trim();
		}
		return fields;
	}

	/**
	 * One printed field, with this module's {@code @} register-direct marker stripped so
	 * {@code @XAR7} and {@code XAR7} compare equal.
	 */
	static String printedField(Instruction instruction, int index) {
		String[] fields = printedFields(instruction);
		if (index < 0 || index >= fields.length) {
			return "";
		}
		String field = fields[index];
		return field.startsWith("@") ? field.substring(1) : field;
	}

	static boolean isPrintedRegister(Instruction instruction, int index, String name) {
		return printedField(instruction, index).equalsIgnoreCase(name);
	}

	static Instruction contiguousPrevious(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Instruction previous = instruction.getPrevious();
		return previous != null && previous.getMaxAddress().next().equals(instruction.getMinAddress())
				? previous
				: null;
	}

	/** Convert an architectural C28 word address to Ghidra's byte-offset Address. */
	static Address wordAddress(Address basis, long wordOffset) {
		int wordSize = basis.getAddressSpace().getAddressableUnitSize();
		return basis.getAddressSpace().getAddress(Math.multiplyExact(wordOffset, wordSize));
	}
}
