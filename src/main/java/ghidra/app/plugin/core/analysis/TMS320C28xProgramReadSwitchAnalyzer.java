// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Recovers TI cl2000 "program-read" (PREAD) switch dispatches, which Ghidra's generic
// Decompiler Switch Analysis cannot enumerate. The shipped C28x firmware loads a switch
// target from a program-memory .long table with a PAIRED PREAD:
//
//   MOVL XAR7,#table ; MOVL ACC,XAR7 ; ADDU ACC,@ARn ; MOVL XAR7,ACC
//   PREAD @AL,*XAR7 ; ADDB XAR7,#1 ; PREAD @AH,*XAR7 ; MOVL XAR7,ACC ; LB *XAR7
//
// The target is thus ACC = CONCAT22(load16, load16). DSA models that split load and gives
// up ("Jumptable with 0 entries; treating indirect jump as call") even after the branch is
// perfectly canonicalized to a single BRANCHIND -- verified against shipped C28x firmware
// (at 0xa44e0) where a byte-identical NATIVE data-space dispatch (MOVL XAR7,*+XAR7[0])
// recovers but the PREAD one never does. So instead of leaning on DSA, this analyzer reads
// the validated .long table itself and installs a decompiler jump-table OVERRIDE
// (JumpTable.writeOverride) with the recovered case targets.
//
// It runs after DSA (priority FUNCTION_ANALYSIS.after > CODE_ANALYSIS) so that dispatches
// DSA already recovered on its own (the native forms) are left untouched, and only the
// still-unresolved PREAD computed branches get an override. See issue #18.
//
// Caveat: a recovered case whose body only clears an interrupt flag (AND/OR IFR,#mask)
// decompiles as an empty `break` -- IFR is a scratch register whose write is never read
// again, so the decompiler dead-code-eliminates it. The write is still shown in the
// listing; surfacing it in the decompiler needs a side-effecting IFR model. See issue #29.
package ghidra.app.plugin.core.analysis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Installs decompiler jump-table overrides for TI cl2000 program-read (PREAD) switch
 * dispatches that Decompiler Switch Analysis cannot recover. See file header for the
 * dispatch shape and rationale.
 */
public class TMS320C28xProgramReadSwitchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x PREAD Switch Overrides";
	private static final String DESCRIPTION =
		"Recovers program-read (PREAD) switch tables that Decompiler Switch Analysis misses";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final int MAX_ENTRIES = 1024;
	private static final long TABLE_ENTRY_WORDS = 2;
	private static final long CODE_ADDRESS_MASK = 0x003fffffL;

	public TMS320C28xProgramReadSwitchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// After Decompiler Switch Analysis (CODE_ANALYSIS=400) and after functions exist,
		// so native dispatches DSA already resolved are left alone and writeOverride() has a
		// function to attach to.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		FunctionManager functions = program.getFunctionManager();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction branch = instructions.next();
			if (!isComputedXar7Branch(branch) || isAlreadyResolved(program, branch)) {
				continue;
			}
			Function function = functions.getFunctionContaining(branch.getMinAddress());
			if (function == null) {
				continue;
			}
			Address table = recoverProgramReadTable(branch);
			if (table == null) {
				continue;
			}
			List<Address> targets = recoverTableTargets(program, table, branch);
			if (targets == null) {
				continue;
			}
			try {
				installOverride(program, function, branch, targets);
				Msg.info(this, "PREAD switch override at " + branch.getMinAddress() +
					" table=" + table + " cases=" + targets.size());
			}
			catch (InvalidInputException | RuntimeException exception) {
				log.appendException(exception);
			}
		}
		return true;
	}

	/**
	 * Match the program-read dispatch tail ending at the {@code LB *XAR7} and return the
	 * program-memory table base, or null if this is not a PREAD dispatch.
	 *
	 * <pre>
	 * MOVL XAR7,#table   (tableInstruction)
	 * MOVL ACC,XAR7      (baseCopy)
	 * ADDU ACC,@ARn      (indexAdd)      -- unsigned, no shift; scale is folded into ARn
	 * MOVL XAR7,ACC      (addressCopy)
	 * PREAD @AL,*XAR7    (lowRead)
	 * ADDB XAR7,#1       (increment)
	 * PREAD @AH,*XAR7    (highRead)
	 * MOVL XAR7,ACC      (finalCopy)
	 * LB   *XAR7         (branch)
	 * </pre>
	 */
	private static Address recoverProgramReadTable(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction addressCopy = contiguousPrevious(lowRead);
		Instruction indexAdd = contiguousPrevious(addressCopy);
		Instruction baseCopy = contiguousPrevious(indexAdd);
		Instruction tableInstruction = contiguousPrevious(baseCopy);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isPreadInto(highRead, "AH") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isPreadInto(lowRead, "AL") ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC") ||
			!isUnsignedAccAdd(indexAdd) ||
			!isRegisterMove(baseCopy, "movl", "ACC", "XAR7")) {
			return null;
		}
		Scalar tableScalar = immediateTableBase(tableInstruction);
		if (tableScalar == null) {
			return null;
		}
		return tableAddress(tableInstruction, tableScalar);
	}

	/**
	 * Read consecutive 2-word .long entries from {@code table} until one is not a valid code
	 * address inside the branch's own memory block, and return the recovered case targets.
	 * The count is data-driven (bounded by the guard the compiler emitted, which places
	 * non-code immediately after the table); requires at least three distinct targets.
	 */
	private static List<Address> recoverTableTargets(Program program, Address table,
			Instruction branch) {
		Memory memory = program.getMemory();
		MemoryBlock tableBlock = memory.getBlock(table);
		MemoryBlock branchBlock = memory.getBlock(branch.getMinAddress());
		if (tableBlock == null || !tableBlock.isInitialized() || !tableBlock.isLoaded() ||
			!tableBlock.isRead() || branchBlock == null || !branchBlock.isExecute()) {
			return null;
		}
		int wordSize = table.getAddressSpace().getAddressableUnitSize();
		List<Address> targets = new ArrayList<>();
		Set<Long> distinct = new HashSet<>();
		try {
			for (int index = 0; index < MAX_ENTRIES; index++) {
				Address entry = table.add((long) index * TABLE_ENTRY_WORDS * wordSize);
				if (!tableBlock.contains(entry) ||
					!tableBlock.contains(entry.add((long) TABLE_ENTRY_WORDS * wordSize - 1))) {
					break;
				}
				long low = memory.getShort(entry, false) & 0xffffL;
				long high = memory.getShort(entry.add(wordSize), false) & 0xffffL;
				long rawTarget = (high << 16) | low;
				if ((rawTarget & ~CODE_ADDRESS_MASK) != 0) {
					break;
				}
				Address target = wordAddress(table, rawTarget & CODE_ADDRESS_MASK);
				MemoryBlock targetBlock = memory.getBlock(target);
				if (targetBlock != branchBlock || !targetBlock.isExecute() ||
					!targetBlock.isInitialized()) {
					break;
				}
				targets.add(target);
				distinct.add(rawTarget);
			}
		}
		catch (MemoryAccessException exception) {
			return null;
		}
		return distinct.size() >= 3 ? targets : null;
	}

	private void installOverride(Program program, Function function, Instruction branch,
			List<Address> targets) throws InvalidInputException {
		Address lb = branch.getMinAddress();
		Address entry = function.getEntryPoint();
		ReferenceManager references = program.getReferenceManager();
		FunctionManager functions = program.getFunctionManager();
		// Computed-jump references so the case blocks are reachable in the listing and the
		// function body can absorb them below; mirrors what Decompiler Switch Analysis records.
		for (Address target : targets) {
			references.addMemoryReference(lb, target, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
		}
		// Delete the spurious per-case functions Ghidra created before the switch was known
		// (each case block looked like orphan code); required so the body fold below succeeds.
		for (Address target : targets) {
			Function caseFunction = functions.getFunctionAt(target);
			if (caseFunction != null && !caseFunction.getEntryPoint().equals(entry)) {
				functions.removeFunction(target);
			}
		}
		// Install the decompiler jump-table override with the recovered case targets.
		new JumpTable(lb, new ArrayList<>(targets), true, 0).writeOverride(function);
		// Re-form the function body so the case blocks fold in, following the new references
		// (mirrors DSA). Best-effort: the override alone already recovers the switch.
		new CreateFunctionCmd(null, entry, null, SourceType.ANALYSIS, false, true).applyTo(program);
	}

	private static boolean isAlreadyResolved(Program program, Instruction branch) {
		int computedJumps = 0;
		for (Reference reference :
				program.getReferenceManager().getReferencesFrom(branch.getMinAddress())) {
			if (reference.getReferenceType().isJump() && reference.getReferenceType().isComputed()) {
				computedJumps++;
			}
		}
		return computedJumps >= 2;
	}

	// --- instruction matchers (mirrors of TMS320C28xSwitchAnalyzer's private helpers) ------

	private static boolean isComputedXar7Branch(Instruction instruction) {
		return isMnemonic(instruction, "lb") && instruction.getNumOperands() == 0 &&
			instruction.toString().toUpperCase().endsWith("*XAR7") &&
			instruction.getFlowType().isJump() && instruction.getFlowType().isComputed();
	}

	private static boolean isUnsignedAccAdd(Instruction instruction) {
		// ADDU ACC,@ARn -- unsigned (zero-extended) add of a 16-bit AR into ACC.
		return isMnemonic(instruction, "addu") && isRegisterOperand(instruction, 0, "ACC") &&
			instruction != null && instruction.getNumOperands() == 2 &&
			registerName(instruction, 1) != null && registerName(instruction, 1).startsWith("AR");
	}

	// PREAD @AH,*XAR7 renders as one operand (@AH) with "*XAR7" baked into the mnemonic print
	// form (like LB *XAR7), so match the destination register and the "*XAR7" tail rather than
	// a second XAR7 operand.
	private static boolean isPreadInto(Instruction instruction, String destination) {
		return isMnemonic(instruction, "pread") &&
			isRegisterOperand(instruction, 0, destination) &&
			instruction.toString().toUpperCase().endsWith("*XAR7");
	}

	// MOVL XAR7,#imm renders as a single scalar operand with "XAR7,#" in the mnemonic print form
	// (XAR7 is a print literal here, not an operand), so read the table base from operand 0.
	private static Scalar immediateTableBase(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") ||
			!instruction.toString().toUpperCase().contains("XAR7,#")) {
			return null;
		}
		return scalarOperand(instruction, 0);
	}

	private static Address tableAddress(Instruction tableInstruction, Scalar scalar) {
		return wordAddress(tableInstruction.getAddress(), scalar.getUnsignedValue() & CODE_ADDRESS_MASK);
	}

	private static boolean isImmediateAdd(Instruction instruction, String mnemonic,
			String destination, long value) {
		Scalar scalar = scalarOperand(instruction, 1);
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) && scalar != null &&
			scalar.getUnsignedValue() == value;
	}

	private static boolean isRegisterMove(Instruction instruction, String mnemonic,
			String destination, String source) {
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) &&
			isRegisterOperand(instruction, 1, source);
	}

	private static boolean isMnemonic(Instruction instruction, String mnemonic) {
		return instruction != null && instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
	}

	private static String registerName(Instruction instruction, int operand) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return null;
		}
		Object[] objects = instruction.getOpObjects(operand);
		if (objects.length == 1 &&
			objects[0] instanceof ghidra.program.model.lang.Register register) {
			return register.getName();
		}
		return null;
	}

	private static boolean isRegisterOperand(Instruction instruction, int operand,
			String registerName) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		ghidra.program.model.lang.Register register = instruction.getRegister(operand);
		if (register != null && register.getName().equalsIgnoreCase(registerName)) {
			return true;
		}
		Object[] objects = instruction.getOpObjects(operand);
		if (objects.length == 1 &&
			objects[0] instanceof ghidra.program.model.lang.Register objectRegister &&
			objectRegister.getName().equalsIgnoreCase(registerName)) {
			return true;
		}
		return instruction.getDefaultOperandRepresentation(operand)
			.equalsIgnoreCase("*" + registerName);
	}

	private static Scalar scalarOperand(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? null
				: instruction.getScalar(operand);
	}

	private static Instruction contiguousPrevious(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Instruction previous = instruction.getPrevious();
		return previous != null && previous.getMaxAddress().next().equals(instruction.getMinAddress())
				? previous
				: null;
	}

	/** Convert an architectural C28 word address to Ghidra's byte-offset Address. */
	private static Address wordAddress(Address basis, long wordOffset) {
		int wordSize = basis.getAddressSpace().getAddressableUnitSize();
		return basis.getAddressSpace().getAddress(Math.multiplyExact(wordOffset, wordSize));
	}
}
