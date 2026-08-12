// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

/**
 * SPRU514 §7.3.1 class-priority parameter allocator for TMS320C28x EABI.
 *
 * <p>The cspec's pentry model allocates in declaration order and cannot
 * express SPRU's cross-class reservation rule: a later {@code long} or
 * {@code long long} arg pre-reserves ACC / ACC:P, which then removes AL/AH
 * from the class-6 (16-bit) pool for earlier {@code int} args. This
 * allocator pre-scans all params, reserves higher-priority classes first,
 * then fills class-6 slots from what remains — matching what
 * {@code cl2000 --abi=eabi} emits in DWARF.
 *
 * <p>SPRU §7.3.1 class priority (lowest number wins):
 * <ol>
 *   <li>hidden struct-return pointer → XAR6 (handled by cspec's hiddenret, not here)</li>
 *   <li>32-bit float → first four go to R0H..R3H</li>
 *   <li>pointer (4 bytes) → first two go to XAR4, XAR5</li>
 *   <li>long long (8 bytes) → first only, ACC:P (= AH:AL:PH:PL)</li>
 *   <li>long / 32-bit int → first only, ACC (= AH:AL)</li>
 *   <li>16-bit int → AL, AH, AR4, AR5 in order, "if available" (SPRU rule f)</li>
 * </ol>
 * Anything that doesn't fit a register slot spills to the stack at
 * {@code stack[+2 + running_offset]} with 2-word alignment (matches the
 * cspec's {@code offset=2 space=stack} + LCR's RPC push).
 *
 * <p>Return-value allocation is untouched — the cspec's output pentries
 * already match SPRU-truth for every case except {@code hiddenret} on
 * oversized structs, which is out of scope for this allocator (see
 * {@code tests/abi_probe.NOTES.md}).
 */
public final class TMS320C28xAbiAllocator {

	// Names must match the cspec register file. AH/AL are 16-bit sub-pieces
	// of ACC; PH/PL of P; ARn is the 16-bit low half of XARn; R0H..R3H are
	// the 32-bit high halves of the FPU F0..F3 doubles.
	private static final String[] FLOAT_POOL = { "R0H", "R1H", "R2H", "R3H" };
	private static final String[] PTR_POOL = { "XAR4", "XAR5" };
	private static final int STACK_START_OFFSET = 2; // matches cspec pentry offset

	private TMS320C28xAbiAllocator() {
	}

	/**
	 * Compute SPRU-priority storage for each param in declaration order.
	 *
	 * @param program the program (source of Register / stack-space lookups)
	 * @param paramTypes declared types, in declaration order
	 * @return storage per param, same length and order as {@code paramTypes}
	 * @throws InvalidInputException if the program's register file lacks a
	 *         required register — indicates a language/cspec drift, not user error
	 */
	public static VariableStorage[] computeParamStorage(Program program, DataType[] paramTypes)
			throws InvalidInputException {
		return computeParamStorage(program, paramTypes, false);
	}

	/**
	 * SPRU §7.3.1 vararg rule: when a signature has an ellipsis, the last named
	 * parameter is spilled to the stack so {@code va_list} can walk contiguously
	 * from that slot into the caller-pushed vararg spill area. Earlier named
	 * args follow the normal class-priority rules.
	 *
	 * @param varArgs true when the signature has trailing ellipsis
	 */
	public static VariableStorage[] computeParamStorage(Program program, DataType[] paramTypes,
			boolean varArgs) throws InvalidInputException {
		int n = paramTypes.length;
		VariableStorage[] out = new VariableStorage[n];

		Classification[] cls = new Classification[n];
		for (int i = 0; i < n; i++) {
			cls[i] = classify(paramTypes[i]);
		}

		// Pre-reserve: first long long claims ACC:P (excludes any later long claiming ACC too).
		// First long claims ACC only if no long long already did.
		// First up-to-2 pointers claim XAR4/XAR5. First up-to-4 floats claim R0H..R3H.
		//
		// The class-6 (16-bit int) pool starts as [AL, AH, AR4, AR5] and loses:
		//   AL, AH   if ACC or ACC:P was reserved
		//   AR4      if XAR4 was reserved by a pointer
		//   AR5      if XAR5 was reserved by a pointer
		boolean accReserved = false;
		boolean accPReserved = false;
		int ptrReserved = 0;
		int floatReserved = 0;
		for (Classification c : cls) {
			switch (c) {
				case LONGLONG:
					if (!accPReserved) {
						accPReserved = true;
					}
					break;
				case LONG:
					// Only the first long reserves ACC; later longs spill, but only if a long long
					// didn't already claim the space (in which case even the first long spills).
					if (!accReserved && !accPReserved) {
						accReserved = true;
					}
					break;
				case PTR:
					if (ptrReserved < PTR_POOL.length) {
						ptrReserved++;
					}
					break;
				case FLOAT:
					if (floatReserved < FLOAT_POOL.length) {
						floatReserved++;
					}
					break;
				default:
					break;
			}
		}

		// class-6 pool after reservation
		boolean alFree = !(accReserved || accPReserved);
		boolean ahFree = !(accReserved || accPReserved);
		boolean ar4Free = ptrReserved < 1;
		boolean ar5Free = ptrReserved < 2;

		// Running counters for the "first X gets the register, rest spill" priorities.
		boolean longLongTaken = false;
		boolean longTaken = false;
		int ptrTaken = 0;
		int floatTaken = 0;
		int stackWords = 0;

		for (int i = 0; i < n; i++) {
			DataType dt = paramTypes[i];
			int size = dt.getLength();
			switch (cls[i]) {
				case LONGLONG:
					if (!longLongTaken) {
						longLongTaken = true;
						out[i] = accPJoin(program);
					}
					else {
						out[i] = stackSlot(program, stackWords, size);
						stackWords += words(size);
					}
					break;
				case LONG:
					if (!longTaken && !accPReserved) {
						longTaken = true;
						out[i] = accJoin(program);
					}
					else {
						out[i] = stackSlot(program, stackWords, size);
						stackWords += words(size);
					}
					break;
				case PTR:
					if (ptrTaken < PTR_POOL.length) {
						out[i] = reg(program, PTR_POOL[ptrTaken]);
						ptrTaken++;
					}
					else {
						out[i] = stackSlot(program, stackWords, size);
						stackWords += words(size);
					}
					break;
				case FLOAT:
					if (floatTaken < FLOAT_POOL.length) {
						out[i] = reg(program, FLOAT_POOL[floatTaken]);
						floatTaken++;
					}
					else {
						out[i] = stackSlot(program, stackWords, size);
						stackWords += words(size);
					}
					break;
				case INT16:
					// Fill from [AL, AH, AR4, AR5], skipping any consumed by reservation above.
					if (alFree) {
						alFree = false;
						out[i] = reg(program, "AL");
					}
					else if (ahFree) {
						ahFree = false;
						out[i] = reg(program, "AH");
					}
					else if (ar4Free) {
						ar4Free = false;
						out[i] = reg(program, "AR4");
					}
					else if (ar5Free) {
						ar5Free = false;
						out[i] = reg(program, "AR5");
					}
					else {
						out[i] = stackSlot(program, stackWords, size);
						stackWords += words(size);
					}
					break;
				default:
					// Unknown / unhandled — spill to stack rather than mis-place.
					out[i] = stackSlot(program, stackWords, size);
					stackWords += words(size);
					break;
			}
		}

		// Vararg spill: the last named arg lands on the stack so va_list can walk
		// contiguously into the caller-pushed vararg area. This runs AFTER the
		// class-priority pass so earlier named args keep their register slots.
		if (varArgs && n > 0 && !out[n - 1].isStackStorage()) {
			int size = paramTypes[n - 1].getLength();
			out[n - 1] = stackSlot(program, stackWords, size);
		}
		return out;
	}

	// --- classification -----------------------------------------------------

	private enum Classification {
		LONGLONG, LONG, PTR, FLOAT, INT16, OTHER
	}

	private static Classification classify(DataType dt) {
		if (dt == null) {
			return Classification.OTHER;
		}
		DataType t = unwrap(dt);
		if (t instanceof Pointer) {
			return Classification.PTR;
		}
		if (t instanceof AbstractFloatDataType) {
			return t.getLength() == 4 ? Classification.FLOAT : Classification.OTHER;
		}
		int len = t.getLength();
		if (len == 8) {
			return Classification.LONGLONG;
		}
		if (len == 4) {
			return Classification.LONG;
		}
		if (len == 1 || len == 2) {
			return Classification.INT16;
		}
		return Classification.OTHER;
	}

	private static DataType unwrap(DataType dt) {
		DataType t = dt;
		while (t instanceof ghidra.program.model.data.TypeDef) {
			t = ((ghidra.program.model.data.TypeDef) t).getBaseDataType();
		}
		return t;
	}

	// --- storage builders ---------------------------------------------------

	private static VariableStorage reg(Program program, String name) throws InvalidInputException {
		Register r = program.getRegister(name);
		if (r == null) {
			throw new InvalidInputException("register " + name + " not in language");
		}
		return new VariableStorage(program, r);
	}

	private static VariableStorage accJoin(Program program) throws InvalidInputException {
		// Join AH:AL — matches the cspec's Class 5 pentry so downstream prints "AH:AL".
		return new VariableStorage(program, program.getRegister("AH"), program.getRegister("AL"));
	}

	private static VariableStorage accPJoin(Program program) throws InvalidInputException {
		// Join AH:AL:PH:PL — matches the cspec's Class 4 pentry so downstream prints "AH:AL:PH:PL".
		return new VariableStorage(program,
			program.getRegister("AH"), program.getRegister("AL"),
			program.getRegister("PH"), program.getRegister("PL"));
	}

	private static VariableStorage stackSlot(Program program, int wordOffset, int size)
			throws InvalidInputException {
		// stackWords are the running COUNT of prior stack args in words; the actual offset
		// is STACK_START_OFFSET + wordOffset (bytes are word-addressed so +1 = next word).
		return new VariableStorage(program, STACK_START_OFFSET + wordOffset, size);
	}

	private static int words(int byteSize) {
		// 2-word alignment matches the cspec's align="2" on the stack pentry; every C type
		// on C28x is a whole number of 16-bit words so the size is already word-aligned.
		return byteSize;
	}
}
