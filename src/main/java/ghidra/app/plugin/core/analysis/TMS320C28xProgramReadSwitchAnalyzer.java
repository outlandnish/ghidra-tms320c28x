// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Recovers TI cl2000 "program-read" (PREAD) switch dispatches, which Ghidra's generic
// Decompiler Switch Analysis cannot enumerate. The shipped C28x firmware loads a switch
// target from a program-memory .long table with a PAIRED PREAD:
//
//   MOVL XAR7,#table ; MOVL ACC,@XAR7 ; [index fold] ; ADDU ACC,@ARn ; MOVL @XAR7,ACC
//   PREAD @AL,*XAR7 ; ADDB XAR7,#1 ; PREAD @AH,*XAR7 ; MOVL @XAR7,ACC ; LB *XAR7
//
// The target is thus ACC = CONCAT22(load16, load16). DSA models that split load and gives
// up ("Jumptable with 0 entries; treating indirect jump as call") even after the branch is
// perfectly canonicalized to a single BRANCHIND -- verified against shipped C28x firmware
// where a byte-identical NATIVE data-space dispatch (MOVL XAR7,*+XAR7[0]) recovers but the
// PREAD one never does. So instead of leaning on DSA, this analyzer reads the validated
// .long table itself and installs a decompiler jump-table OVERRIDE (JumpTable.writeOverride)
// with the recovered case targets.
//
// The optional index fold is the accumulate-indexed family of issue #66, whose selector is
// scaled BEFORE it is bounded -- so the low bound is folded, pre-scaled, into the index
// register rather than into ACC, and lands between the base copy and the accumulate.
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

import static ghidra.app.plugin.core.analysis.TMS320C28xSwitchShapes.*;

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
	// How far back of the table load the range guard may sit. The observed schedule puts two
	// instructions in between (the scale and the index load); six leaves room for a variant
	// with a few more, while still keeping the scan inside one straight-line run.
	private static final int MAX_GUARD_DISTANCE = 6;

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
			Instruction tableInstruction = recoverProgramReadTable(branch);
			if (tableInstruction == null) {
				continue;
			}
			Integer count = recoverCaseCount(tableInstruction);
			if (count == null) {
				continue;
			}
			Address table = tableAddress(tableInstruction, immediateTableBase(tableInstruction));
			List<Address> targets = recoverTableTargets(program, table, branch, count);
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
	 * instruction that loads the table base, or null if this is not a PREAD dispatch.
	 *
	 * <pre>
	 * MOVL XAR7,#table   (tableInstruction)
	 * MOVL ACC,@XAR7     (baseCopy)
	 * SUBB XAR4,#2       (adjustment)    -- optional; see below
	 * ADDU ACC,@ARn      (indexAdd)      -- unsigned, no shift; scale is folded into ARn
	 * MOVL @XAR7,ACC     (addressCopy)
	 * PREAD @AL,*XAR7    (lowRead)
	 * ADDB XAR7,#1       (increment)
	 * PREAD @AH,*XAR7    (highRead)
	 * MOVL @XAR7,ACC     (finalCopy)
	 * LB   *XAR7         (branch)
	 * </pre>
	 *
	 * <p>The adjustment is the low-bound fold of the accumulate-indexed family (issue #66).
	 * The index is scaled BEFORE it is bounded, so the immediate is pre-scaled and is applied
	 * to the index register rather than to ACC -- and it does not move where the entries are
	 * read from: the compiler subtracts {@code entrySize * lowestCase}, so the lowest in-range
	 * selector addresses the immediate table base exactly, which is where the walk below
	 * already starts. Only its presence has to be tolerated, and only on the register the
	 * accumulate then sources -- {@code SUBB XAR4} against {@code ADDU ACC,@AR4} is the same
	 * register in its 32-bit form.
	 */
	private static Instruction recoverProgramReadTable(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction addressCopy = contiguousPrevious(lowRead);
		Instruction indexAdd = contiguousPrevious(addressCopy);
		String index = unsignedAccumulateSource(indexAdd);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isPreadInto(highRead, "AH") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isPreadInto(lowRead, "AL") ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC") || index == null) {
			return null;
		}

		// The bound fold is absent from a zero-based switch, so its slot in the schedule
		// holds the base copy instead.
		Instruction baseCopy = contiguousPrevious(indexAdd);
		if (isIndexAdjustment(baseCopy, index)) {
			baseCopy = contiguousPrevious(baseCopy);
		}
		if (!isRegisterMove(baseCopy, "movl", "ACC", "XAR7")) {
			return null;
		}
		Instruction tableInstruction = contiguousPrevious(baseCopy);
		return immediateTableBase(tableInstruction) == null ? null : tableInstruction;
	}

	/** An immediate add or subtract on {@code index}, in either its 16- or 32-bit form. */
	private static boolean isIndexAdjustment(Instruction instruction, String index) {
		return recoverWordImmediateDelta(instruction, index) != null ||
			recoverWordImmediateDelta(instruction, "X" + index) != null;
	}

	/**
	 * How many cases the range guard admits, or null when no guard proves a bound.
	 *
	 * <pre>
	 * MOV  AH,@AL      ; the selector, copied so the fold does not destroy it
	 * ADDB AH,#-low    ; low-bound fold (absent when zero-based)
	 * CMPB AH,#high    ; the bound
	 * SB   default,HI  ; above -&gt; default; falls through into the dispatch
	 * </pre>
	 *
	 * <p>This bound is not optional. The table has no terminator, and reading entries until
	 * one stops looking like a code address does not stop at the end of the table -- TI packs
	 * these tables back to back, so the walk runs straight on into the NEXT switch's table and
	 * every entry there is a perfectly good code address. Measured on shipped firmware: a
	 * 14-case table read that way yields 27 cases, the extra 13 being another function's case
	 * blocks. So the count comes from the guard, and an unguarded dispatch is declined.
	 *
	 * <p>The guard sits further back than in the data-space schedules -- the scale and the
	 * index load stand between it and the table load -- so scan back over the straight-line
	 * run rather than indexing a fixed slot.
	 */
	private static Integer recoverCaseCount(Instruction tableInstruction) {
		Instruction current = contiguousPrevious(tableInstruction);
		Instruction next = tableInstruction;
		for (int steps = 0; steps < MAX_GUARD_DISTANCE && current != null; steps++) {
			Address fallThrough = current.getFallThrough();
			if (fallThrough == null || !fallThrough.equals(next.getMinAddress())) {
				return null;
			}
			if (current.getFlowType().isJump() && current.getFlowType().isConditional()) {
				return recoverBoundedCount(current);
			}
			next = current;
			current = contiguousPrevious(current);
		}
		return null;
	}

	/**
	 * The case count proved by {@code guard}, a conditional branch to the default path taken
	 * when the selector is unsigned-above the compared bound.
	 */
	private static Integer recoverBoundedCount(Instruction guard) {
		Instruction compare = contiguousPrevious(guard);
		Scalar high = scalarOperand(compare, 1);
		if (!"HI".equalsIgnoreCase(printedField(guard, 1)) || !isMnemonic(compare, "cmpb") ||
			high == null) {
			return null;
		}
		long count = high.getUnsignedValue() + 1;
		return count < 2 || count > MAX_ENTRIES ? null : (int) count;
	}

	/**
	 * Read the {@code count} 2-word .long entries at {@code table} and return the case
	 * targets, or null unless EVERY one is a valid code address inside the branch's own
	 * memory block. Requires at least three distinct targets.
	 *
	 * <p>All-or-nothing on purpose: the count comes from the guard, so an entry that is not
	 * code means the recovered shape is not this table, not that the table ended early.
	 */
	private static List<Address> recoverTableTargets(Program program, Address table,
			Instruction branch, int count) {
		Memory memory = program.getMemory();
		MemoryBlock tableBlock = memory.getBlock(table);
		MemoryBlock branchBlock = memory.getBlock(branch.getMinAddress());
		if (tableBlock == null || !tableBlock.isInitialized() || !tableBlock.isLoaded() ||
			!tableBlock.isRead() || branchBlock == null || !branchBlock.isExecute()) {
			return null;
		}
		int wordSize = table.getAddressSpace().getAddressableUnitSize();
		List<Address> targets = new ArrayList<>(count);
		Set<Long> distinct = new HashSet<>();
		try {
			for (int index = 0; index < count; index++) {
				Address entry = table.add((long) index * TABLE_ENTRY_WORDS * wordSize);
				if (!tableBlock.contains(entry) ||
					!tableBlock.contains(entry.add((long) TABLE_ENTRY_WORDS * wordSize - 1))) {
					return null;
				}
				long low = memory.getShort(entry, false) & 0xffffL;
				long high = memory.getShort(entry.add(wordSize), false) & 0xffffL;
				long rawTarget = (high << 16) | low;
				if ((rawTarget & ~CODE_ADDRESS_MASK) != 0) {
					return null;
				}
				Address target = wordAddress(table, rawTarget & CODE_ADDRESS_MASK);
				MemoryBlock targetBlock = memory.getBlock(target);
				if (targetBlock != branchBlock || !targetBlock.isExecute() ||
					!targetBlock.isInitialized()) {
					return null;
				}
				targets.add(target);
				distinct.add(rawTarget);
			}
		}
		catch (MemoryAccessException | RuntimeException exception) {
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

}
