// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Copyright the mwdmwd/ghidra-c28x contributors (https://github.com/mwdmwd/ghidra-c28x)
//
// Ported from mwdmwd/ghidra-c28x (Apache-2.0). Local changes: the processor-name
// string ("TMS320C28x" here vs "TMS320C28" upstream), the class rename, and the
// XAR7 detection in isComputedXar7Branch() / isRegisterOperand(). Upstream matches
// XAR7 as operand 0 of "LB", but this module's SLEIGH renders "LB *XAR7" with
// XAR7 as a mnemonic-attached print literal (zero operands), so the terminal
// computed branch is recognized by mnemonic + operand-count + the "*XAR7"
// print form + jump/computed flow type. The isRegisterOperand helper also gains
// an operand-representation fallback so "*XAR7" indirect operands (e.g. as seen
// in MOVL XAR7,*+XAR7[0]) remain recognizable. See THIRD-PARTY.md.
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Canonicalizes validated TI compiler switch dispatches before the generic
 * decompiler switch analyzer runs.
 * <p>
 * The C28x ABI does not prescribe SXM at function boundaries. Consequently,
 * ordinary index instructions must retain their SXM/OVM-sensitive semantics.
 * Validated switch guards, however, prove the bounded selector arithmetic on
 * the path into a dispatch. This analyzer recovers a complete switch descriptor,
 * validates the table and targets, and selects equivalent canonical SLEIGH
 * constructors only at the proven index (and, for the saved 32-bit-selector
 * schedule, its range subtraction) and {@code LB *XAR7}. Stock Decompiler Switch
 * Analysis then recovers the references, function body, and original case values.
 */
public class TMS320C28xSwitchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x TI Switch Canonicalizer";
	private static final String DESCRIPTION =
		"Recognizes guarded TI switch tables and canonicalizes their unsigned index";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String CONTEXT_NAME = "switch_canonical";
	private static final int MAX_ENTRIES = 1024;
	private static final int MAX_DISPATCH_INSTRUCTIONS = 20;
	private static final long CODE_ADDRESS_MASK = 0x003fffffL;
	private static final long TABLE_ENTRY_WORDS = 2;

	public TMS320C28xSwitchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after initial instruction discovery and before CODE_ANALYSIS, where
		// the generic Decompiler Switch Analysis is scheduled.
		setPriority(AnalysisPriority.DISASSEMBLY.after());
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
		ProgramContext context = program.getProgramContext();
		Register switchContext = context.getRegister(CONTEXT_NAME);
		if (switchContext == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " + CONTEXT_NAME);
			return false;
		}

		Listing listing = program.getListing();
		List<SwitchDescriptor> matches = new ArrayList<>();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (!isComputedXar7Branch(instruction)) {
				continue;
			}
			if (BigInteger.ONE.equals(context.getValue(switchContext,
					instruction.getMinAddress(), false))) {
				continue;
			}

			SwitchDescriptor descriptor = recoverSwitchDescriptor(program, instruction, monitor);
			if (descriptor != null) {
				matches.add(descriptor);
			}
		}

		AddressSet redisassemble = new AddressSet();
		AddressSet switchBranches = new AddressSet();
		for (SwitchDescriptor descriptor : matches) {
			Instruction branch = listing.getInstructionAt(descriptor.branchAddress);
			if (branch == null) {
				continue;
			}
			try {
				List<Instruction> canonicalInstructions = new ArrayList<>();
				canonicalInstructions.add(descriptor.indexExpression.instruction);
				if (descriptor.guardCanonicalInstruction != null) {
					canonicalInstructions.add(descriptor.guardCanonicalInstruction);
				}
				for (Instruction canonical : canonicalInstructions) {
					listing.clearCodeUnits(canonical.getMinAddress(), canonical.getMaxAddress(), false);
					context.setValue(switchContext, canonical.getMinAddress(), canonical.getMaxAddress(),
						BigInteger.ONE);
					redisassemble.add(canonical.getMinAddress());
				}
				listing.clearCodeUnits(branch.getMinAddress(), branch.getMaxAddress(), false);
				context.setValue(switchContext, branch.getMinAddress(), branch.getMaxAddress(),
					BigInteger.ONE);
				redisassemble.add(branch.getMinAddress());
				switchBranches.add(branch.getMinAddress());
				long highestCase = descriptor.lowestCase + descriptor.count - 1;
				Msg.info(this,
					"recognized " + descriptor.variant.description + " switch at " +
						descriptor.branchAddress + " table=" + descriptor.tableBase + " cases=" +
						descriptor.lowestCase + "-" + highestCase + " default=" +
						descriptor.defaultPath);
			}
			catch (ContextChangeException exception) {
				log.appendException(exception);
			}
		}

		if (!redisassemble.isEmpty()) {
			AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
			manager.disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
			// Redisassembly only reports the changed canonical sites. Explicitly resubmit
			// the downstream LB sites so switch analysis sees the new function P-Code.
			manager.scheduleOneTimeAnalysis(new DecompilerSwitchAnalyzer(), switchBranches);
		}
		return true;
	}

	private static SwitchDescriptor recoverSwitchDescriptor(Program program, Instruction branch,
			TaskMonitor monitor) throws CancelledException {
		DispatchCandidate dispatch = recoverDispatch(branch);
		if (dispatch == null) {
			return null;
		}

		Guard guard = recoverSoleUnsignedGuard(program, dispatch, monitor);
		if (guard == null || !hasConsistentIndexArithmetic(dispatch.indexExpression, guard.low)) {
			return null;
		}
		if (!hasExclusiveStraightLineDispatch(program, guard, dispatch)) {
			return null;
		}

		List<Address> targets = validateTable(program, dispatch.tableBase, guard.count, branch);
		if (targets == null) {
			return null;
		}
		return new SwitchDescriptor(branch.getMinAddress(), dispatch.tableBase, guard.count,
			guard.low, guard.defaultPath, guard.canonicalInstruction, dispatch.indexExpression,
			targets, dispatch.variant);
	}

	private static DispatchCandidate recoverDispatch(Instruction branch) {
		DispatchCandidate candidate = recoverProgramReadSavedLongDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverProgramReadDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativePlDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativeSavedLongDispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		candidate = recoverNativeAr6Dispatch(branch);
		if (candidate != null) {
			return candidate;
		}
		return recoverNativeDirectDispatch(branch);
	}

	/**
	 * Recover the default-memory sibling of the saved-selector native form.
	 * TI cl2000 22.6.1.LTS emits this exact finite schedule for a 32-bit
	 * selector from -O0 through -O4: the selector is kept in XAR7 across an
	 * inverted HI guard, then a two-word program-space target is assembled
	 * with PREAD AL/AH before LB *XAR7.
	 */
	private static DispatchCandidate recoverProgramReadSavedLongDispatch(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction add = contiguousPrevious(lowRead);
		Instruction adjustmentInstruction = contiguousPrevious(add);
		Instruction scaleInstruction = contiguousPrevious(adjustmentInstruction);
		Instruction tableInstruction = contiguousPrevious(scaleInstruction);
		Instruction selectorCopy = contiguousPrevious(tableInstruction);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		Long subtraction = recoverAccImmediateSubtraction(adjustmentInstruction);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isRegisterMove(highRead, "pread", "AH", "XAR7") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isRegisterMove(lowRead, "pread", "AL", "XAR7") ||
			!isRegisterMove(add, "addl", "XAR7", "ACC") ||
			!isLslAccByOne(scaleInstruction) || tableScalar == null || subtraction == null ||
			!isRegisterMove(selectorCopy, "movl", "ACC", "XAR7")) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		IndexExpression expression =
			new IndexExpression(adjustmentInstruction, "XAR7", TABLE_ENTRY_WORDS,
				-subtraction.longValue());
		return new DispatchCandidate(selectorCopy, branch, table, expression,
			DispatchVariant.PROGRAM_READ_SAVED_LONG);
	}

	private static DispatchCandidate recoverProgramReadDispatch(Instruction branch) {
		Instruction finalCopy = contiguousPrevious(branch);
		Instruction highRead = contiguousPrevious(finalCopy);
		Instruction increment = contiguousPrevious(highRead);
		Instruction lowRead = contiguousPrevious(increment);
		Instruction addressCopy = contiguousPrevious(lowRead);
		if (!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isRegisterMove(highRead, "pread", "AH", "XAR7") ||
			!isImmediateAdd(increment, "addb", "XAR7", 1) ||
			!isRegisterMove(lowRead, "pread", "AL", "XAR7") ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC")) {
			return null;
		}
		return recoverPlAddressComputation(addressCopy, branch, DispatchVariant.PROGRAM_READ);
	}

	private static DispatchCandidate recoverNativePlDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction addressCopy = contiguousPrevious(load);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(addressCopy, "movl", "XAR7", "ACC")) {
			return null;
		}
		return recoverPlAddressComputation(addressCopy, branch, DispatchVariant.NATIVE_PL);
	}

	/**
	 * Recover 32-bit-selector schedules used by TI firmware that keep the
	 * unadjusted selector in either XAR7 or P across a range guard:
	 *
	 * <pre>
	 * MOVL ACC,XAR7 | MOVL ACC,P
	 * MOVL XAR7,#table
	 * LSL  ACC,1
	 * SUB  ACC,#(2 * low)
	 * ADDL XAR7,ACC
	 * MOVL XAR7,*+XAR7[0]
	 * LB   *XAR7
	 * </pre>
	 *
	 * LSL already has unambiguous 32-bit semantics. The analyzer canonicalizes
	 * the following SUB, whose ordinary P-Code must retain SXM/OVM behavior, and
	 * the validated LB.
	 */
	private static DispatchCandidate recoverNativeSavedLongDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction add = contiguousPrevious(load);
		Instruction adjustmentInstruction = contiguousPrevious(add);
		Instruction scaleInstruction = contiguousPrevious(adjustmentInstruction);
		Instruction tableInstruction = contiguousPrevious(scaleInstruction);
		Instruction selectorCopy = contiguousPrevious(tableInstruction);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		Long subtraction = recoverAccImmediateSubtraction(adjustmentInstruction);
		String savedRegister;
		DispatchVariant variant;
		if (isRegisterMove(selectorCopy, "movl", "ACC", "XAR7")) {
			savedRegister = "XAR7";
			variant = DispatchVariant.NATIVE_SAVED_LONG;
		}
		else if (isRegisterMove(selectorCopy, "movl", "ACC", "P")) {
			savedRegister = "P";
			variant = DispatchVariant.NATIVE_SAVED_P;
		}
		else {
			return null;
		}
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(add, "addl", "XAR7", "ACC") ||
			!isLslAccByOne(scaleInstruction) || tableScalar == null || subtraction == null) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		IndexExpression expression =
			new IndexExpression(adjustmentInstruction, savedRegister, TABLE_ENTRY_WORDS,
				-subtraction.longValue());
		return new DispatchCandidate(selectorCopy, branch, table, expression, variant);
	}

	private static DispatchCandidate recoverPlAddressComputation(Instruction addressCopy,
			Instruction branch, DispatchVariant variant) {
		Instruction add = contiguousPrevious(addressCopy);
		Instruction baseCopy = contiguousPrevious(add);
		Instruction adjustmentInstruction = contiguousPrevious(baseCopy);
		Instruction scaledCopy = contiguousPrevious(adjustmentInstruction);
		if (!isRegisterMove(add, "addu", "ACC", "PL") ||
			!isRegisterMove(baseCopy, "movl", "ACC", "XAR7") ||
			!isRegisterMove(scaledCopy, "mov", "PL", "AL")) {
			return null;
		}

		Long adjustment = recoverRegisterImmediateAdjustment(adjustmentInstruction, "PL");
		if (adjustment == null) {
			return null;
		}

		IndexAndTable pair = recoverAdjacentIndexAndTable(contiguousPrevious(scaledCopy));
		if (pair == null) {
			return null;
		}
		Address table = tableAddress(pair.tableInstruction, pair.tableScalar);
		IndexExpression expression =
			new IndexExpression(pair.indexInstruction, pair.indexSource, TABLE_ENTRY_WORDS,
				adjustment.longValue());
		return new DispatchCandidate(pair.entryInstruction, branch, table, expression, variant);
	}

	/**
	 * Recover the finite zero-based AR6 schedule observed at firmware
	 * 0x90615-0x90621:
	 *
	 * <pre>
	 * MOVZ AR6,mem16
	 * MOV  AL,AR6
	 * CMPB AL,#high
	 * SB   default,HI
	 * MOVL XAR7,#table
	 * SETC SXM
	 * MOVL ACC,XAR7
	 * ADD  ACC,AR6 << #1
	 * MOVL XAR7,ACC
	 * MOVL XAR7,*+XAR7[0]
	 * LB   *XAR7
	 * </pre>
	 *
	 * Every instruction and operand is matched exactly.  MOVZ and the unsigned
	 * guard prove a nonnegative bounded selector, while SETC SXM makes the ADD's
	 * extension mode explicit.  The analyzer canonicalizes only that ADD and the
	 * validated computed branch.
	 */
	private static DispatchCandidate recoverNativeAr6Dispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction finalCopy = contiguousPrevious(load);
		Instruction indexAdd = contiguousPrevious(finalCopy);
		Instruction baseCopy = contiguousPrevious(indexAdd);
		Instruction setSxm = contiguousPrevious(baseCopy);
		Instruction tableInstruction = contiguousPrevious(setSxm);
		Scalar tableScalar = immediateTableBase(tableInstruction);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(finalCopy, "movl", "XAR7", "ACC") ||
			!isAr6ScaledAdd(indexAdd) ||
			!isRegisterMove(baseCopy, "movl", "ACC", "XAR7") ||
			!isSetSxmOnly(setSxm) || tableScalar == null) {
			return null;
		}

		Address table = tableAddress(tableInstruction, tableScalar);
		IndexExpression expression =
			new IndexExpression(indexAdd, "AR6", TABLE_ENTRY_WORDS, 0);
		return new DispatchCandidate(tableInstruction, branch, table, expression,
			DispatchVariant.NATIVE_AR6_ZERO);
	}

	private static DispatchCandidate recoverNativeDirectDispatch(Instruction branch) {
		Instruction load = contiguousPrevious(branch);
		Instruction add = contiguousPrevious(load);
		if (!isNativeLongwordLoad(load) ||
			!isRegisterMove(add, "addl", "XAR7", "ACC")) {
			return null;
		}

		DirectIndexAndTable direct = recoverDirectIndexAndTable(contiguousPrevious(add), 3);
		if (direct == null) {
			direct = recoverDirectIndexAndTable(contiguousPrevious(add), 2);
		}
		if (direct == null) {
			return null;
		}

		Address table = tableAddress(direct.tableInstruction, direct.tableScalar);
		IndexExpression expression =
			new IndexExpression(direct.indexInstruction, direct.indexSource, TABLE_ENTRY_WORDS,
				direct.adjustment);
		return new DispatchCandidate(direct.entryInstruction, branch, table, expression,
			DispatchVariant.NATIVE_DIRECT);
	}

	private static DirectIndexAndTable recoverDirectIndexAndTable(Instruction last, int length) {
		if (last == null || (length != 2 && length != 3)) {
			return null;
		}
		List<Instruction> instructions = new ArrayList<>(length);
		Instruction current = last;
		for (int i = 0; i < length; i++) {
			if (current == null) {
				return null;
			}
			instructions.add(0, current);
			current = contiguousPrevious(current);
		}

		Instruction tableInstruction = null;
		Scalar tableScalar = null;
		Instruction indexInstruction = null;
		String indexSource = null;
		Instruction adjustmentInstruction = null;
		int indexPosition = -1;
		int adjustmentPosition = -1;
		for (int i = 0; i < instructions.size(); i++) {
			Instruction instruction = instructions.get(i);
			Scalar scalar = immediateTableBase(instruction);
			String source = indexSource(instruction);
			if (scalar != null) {
				if (tableInstruction != null) {
					return null;
				}
				tableInstruction = instruction;
				tableScalar = scalar;
			}
			else if (source != null) {
				if (indexInstruction != null) {
					return null;
				}
				indexInstruction = instruction;
				indexSource = source;
				indexPosition = i;
			}
			else if (isAccImmediateSubtraction(instruction)) {
				if (adjustmentInstruction != null) {
					return null;
				}
				adjustmentInstruction = instruction;
				adjustmentPosition = i;
			}
			else {
				return null;
			}
		}

		if (tableInstruction == null || indexInstruction == null ||
			(length == 3) != (adjustmentInstruction != null) ||
			(adjustmentInstruction != null && adjustmentPosition <= indexPosition)) {
			return null;
		}
		long adjustment = adjustmentInstruction == null
				? 0
				: -recoverAccImmediateSubtraction(adjustmentInstruction).longValue();
		return new DirectIndexAndTable(instructions.get(0), tableInstruction, tableScalar,
			indexInstruction, indexSource, adjustment);
	}

	private static IndexAndTable recoverAdjacentIndexAndTable(Instruction last) {
		Instruction first = contiguousPrevious(last);
		if (first == null || last == null) {
			return null;
		}

		Scalar firstTable = immediateTableBase(first);
		Scalar lastTable = immediateTableBase(last);
		String firstIndex = indexSource(first);
		String lastIndex = indexSource(last);
		if (firstIndex != null && lastTable != null) {
			return new IndexAndTable(first, first, firstIndex, last, lastTable);
		}
		if (firstTable != null && lastIndex != null) {
			return new IndexAndTable(first, last, lastIndex, first, firstTable);
		}
		return null;
	}

	private static Guard recoverSoleUnsignedGuard(Program program, DispatchCandidate dispatch,
			TaskMonitor monitor) throws CancelledException {
		ReferenceIterator references =
			program.getReferenceManager().getReferencesTo(dispatch.entryInstruction.getMinAddress());
		Guard match = null;
		while (references.hasNext()) {
			monitor.checkCancelled();
			Reference reference = references.next();
			if (!reference.getReferenceType().isJump() ||
				!reference.getReferenceType().isConditional()) {
				continue;
			}
			Instruction guardInstruction =
				program.getListing().getInstructionAt(reference.getFromAddress());
			Guard guard = recoverUnsignedRange(guardInstruction, dispatch);
			if (guard == null) {
				continue;
			}
			if (match != null) {
				return null;
			}
			match = guard;
		}

		// Some TI schedules invert the usual layout: HI branches to the default
		// while the bounded LOS path falls through directly into the dispatch.
		Guard fallthroughGuard =
			recoverUnsignedRange(contiguousPrevious(dispatch.entryInstruction), dispatch);
		if (fallthroughGuard != null) {
			if (match != null) {
				return null;
			}
			match = fallthroughGuard;
		}
		return match;
	}

	private static Guard recoverUnsignedRange(Instruction guard, DispatchCandidate dispatch) {
		Address defaultPath = unsignedGuardDefaultPath(guard, dispatch);
		if (defaultPath == null) {
			return null;
		}
		if (dispatch.variant == DispatchVariant.NATIVE_AR6_ZERO) {
			return recoverAr6ZeroBasedRange(guard, defaultPath);
		}

		Instruction compare = contiguousPrevious(guard);
		Instruction subtract = contiguousPrevious(compare);
		if (subtract == null) {
			return null;
		}
		if (isMnemonic(compare, "cmpl")) {
			return recoverUnsignedLongRange(guard, dispatch, defaultPath, compare, subtract);
		}
		if (!isMnemonic(compare, "cmpb") || !isRegisterOperand(compare, 0, "AL")) {
			return null;
		}

		Long lowValue = recoverGuardLow(subtract);
		Scalar highScalar = scalarOperand(compare, 1);
		if (lowValue == null || highScalar == null) {
			return null;
		}
		long low = lowValue.longValue();
		long count = highScalar.getUnsignedValue() + 1;
		long high = low + count - 1;
		if (low < 0 || count < 2 || count > MAX_ENTRIES || high > 0x7fff) {
			return null;
		}

		Instruction possibleCopy = contiguousPrevious(subtract);
		Instruction guardStart = subtract;
		boolean copiedSelector = isSelectorCopy(possibleCopy);
		if (copiedSelector) {
			guardStart = possibleCopy;
		}
		if (dispatch.indexExpression.sourceRegister.equals("AH") && !copiedSelector) {
			return null;
		}
		if (!hasExclusiveStraightLineGuard(guardStart, subtract, compare, guard)) {
			return null;
		}
		return new Guard(guard, guardStart, null, low, (int) count, defaultPath);
	}

	private static Guard recoverAr6ZeroBasedRange(Instruction guard, Address defaultPath) {
		Instruction compare = contiguousPrevious(guard);
		Instruction copy = contiguousPrevious(compare);
		Instruction producer = contiguousPrevious(copy);
		if (!isMnemonic(compare, "cmpb") || !isRegisterOperand(compare, 0, "AL") ||
			!isRegisterMove(copy, "mov", "AL", "AR6") ||
			!isMovzMemoryToAr6(producer)) {
			return null;
		}
		Scalar highScalar = scalarOperand(compare, 1);
		if (highScalar == null) {
			return null;
		}
		long count = highScalar.getUnsignedValue() + 1;
		if (count < 2 || count > MAX_ENTRIES || highScalar.getUnsignedValue() > 0x7fff ||
			!hasExclusiveStraightLineGuard(producer, copy, compare, guard)) {
			return null;
		}
		return new Guard(guard, producer, null, 0, (int) count, defaultPath);
	}

	private static Guard recoverUnsignedLongRange(Instruction guard, DispatchCandidate dispatch,
			Address defaultPath, Instruction compare, Instruction subtract) {
		String savedRegister = dispatch.indexExpression.sourceRegister;
		String boundRegister;
		boolean selectorRelated;
		if (savedRegister.equals("XAR7")) {
			boundRegister = "XAR6";
			Instruction selectorRelation = contiguousPrevious(subtract);
			selectorRelated = isRegisterMove(selectorRelation, "movl", "XAR7", "ACC") ||
				isRegisterMove(selectorRelation, "movl", "ACC", "XAR7");
		}
		else if (savedRegister.equals("P")) {
			boundRegister = "XAR7";
			selectorRelated =
				isRegisterMove(contiguousPrevious(subtract), "movl", "P", "ACC");
		}
		else {
			return null;
		}

		Long lowValue = recoverAccImmediateSubtraction(subtract);
		if (lowValue == null || !selectorRelated ||
			!isRegisterOperand(compare, 0, "ACC") ||
			!isRegisterOperand(compare, 1, boundRegister)) {
			return null;
		}

		RegisterBound bound = recoverImmediateRegisterBound(subtract, boundRegister);
		if (bound == null) {
			return null;
		}
		long low = lowValue.longValue();
		long count = bound.highInclusive + 1;
		long high = low + count - 1;
		if (count < 2 || count > MAX_ENTRIES || high > Integer.MAX_VALUE / 2 ||
			!hasExclusiveStraightLineGuard(bound.instruction, subtract, compare, guard)) {
			return null;
		}
		return new Guard(guard, bound.instruction, subtract, low, (int) count, defaultPath);
	}

	private static RegisterBound recoverImmediateRegisterBound(Instruction subtract,
			String registerName) {
		Instruction next = subtract;
		Instruction current = contiguousPrevious(next);
		for (int count = 0; count < 10 && current != null; count++) {
			if (!fallsThroughTo(current, next.getMinAddress())) {
				return null;
			}
			if (writesRegister(current, registerName)) {
				Scalar scalar = scalarOperand(current, 1);
				if (!isMnemonic(current, "movb") ||
					!isRegisterOperand(current, 0, registerName) || scalar == null) {
					return null;
				}
				return new RegisterBound(current, scalar.getUnsignedValue());
			}
			next = current;
			current = contiguousPrevious(current);
		}
		return null;
	}

	private static boolean hasConsistentIndexArithmetic(IndexExpression expression, long low) {
		if (expression.scaleWords != TABLE_ENTRY_WORDS) {
			return false;
		}
		long expectedAdjustment;
		if (expression.sourceRegister.equals("AH") ||
			expression.sourceRegister.equals("XAR7") ||
			expression.sourceRegister.equals("P")) {
			expectedAdjustment = -TABLE_ENTRY_WORDS * low;
		}
		else if (expression.sourceRegister.equals("AL") ||
			expression.sourceRegister.equals("AR6")) {
			expectedAdjustment = 0;
		}
		else {
			return false;
		}
		return expression.adjustmentWords == expectedAdjustment;
	}

	private static boolean hasExclusiveStraightLineGuard(Instruction start, Instruction subtract,
			Instruction compare, Instruction guard) {
		List<Instruction> sequence = new ArrayList<>();
		Instruction current = start;
		while (current != null && sequence.size() < 12) {
			sequence.add(current);
			if (current.equals(guard)) {
				break;
			}
			current = contiguousNext(current);
		}
		if (sequence.isEmpty() || !sequence.get(sequence.size() - 1).equals(guard) ||
			!sequence.contains(subtract) || !sequence.contains(compare)) {
			return false;
		}
		for (int i = 0; i < sequence.size() - 1; i++) {
			if (!fallsThroughTo(sequence.get(i), sequence.get(i + 1).getMinAddress())) {
				return false;
			}
		}
		for (int i = 1; i < sequence.size(); i++) {
			if (hasExplicitFlowReferenceTo(sequence.get(i))) {
				return false;
			}
		}
		return true;
	}

	private static boolean hasExclusiveStraightLineDispatch(Program program, Guard guard,
			DispatchCandidate dispatch) {
		Instruction entry = dispatch.entryInstruction;
		Instruction previous = entry.getPrevious();
		if (previous != null && fallsThroughTo(previous, entry.getMinAddress()) &&
			!previous.equals(guard.instruction)) {
			return false;
		}

		Instruction current = entry;
		Instruction prior = null;
		for (int count = 0; count < MAX_DISPATCH_INSTRUCTIONS && current != null; count++) {
			ReferenceIterator references =
				program.getReferenceManager().getReferencesTo(current.getMinAddress());
			while (references.hasNext()) {
				Reference reference = references.next();
				if (!reference.getReferenceType().isFlow()) {
					continue;
				}
				if (!current.equals(entry) ||
					!reference.getFromAddress().equals(guard.instruction.getMinAddress())) {
					return false;
				}
			}

			if (current.equals(dispatch.branchInstruction)) {
				return prior != null;
			}
			Instruction next = contiguousNext(current);
			if (next == null || !fallsThroughTo(current, next.getMinAddress())) {
				return false;
			}
			prior = current;
			current = next;
		}
		return false;
	}

	private static List<Address> validateTable(Program program, Address table, int count,
			Instruction branch) {
		Memory memory = program.getMemory();
		MemoryBlock tableBlock = memory.getBlock(table);
		MemoryBlock branchBlock = memory.getBlock(branch.getMinAddress());
		if (tableBlock == null || !tableBlock.isInitialized() || !tableBlock.isLoaded() ||
			!tableBlock.isRead() || tableBlock.isWrite() || branchBlock == null ||
			!branchBlock.isExecute()) {
			return null;
		}

		try {
			int wordSize = table.getAddressSpace().getAddressableUnitSize();
			Address tableEnd = table.add((long) count * TABLE_ENTRY_WORDS * wordSize - 1);
			if (!tableBlock.contains(tableEnd)) {
				return null;
			}

			Function branchFunction =
				program.getFunctionManager().getFunctionContaining(branch.getMinAddress());
			Set<Long> distinctTargets = new HashSet<>();
			List<Address> targets = new ArrayList<>(count);
			for (int index = 0; index < count; index++) {
				Address entry = table.add((long) index * TABLE_ENTRY_WORDS * wordSize);
				long low = memory.getShort(entry, false) & 0xffffL;
				long high = memory.getShort(entry.add(wordSize), false) & 0xffffL;
				long rawTarget = (high << 16) | low;
				if ((rawTarget & ~CODE_ADDRESS_MASK) != 0) {
					return null;
				}
				long targetOffset = rawTarget & CODE_ADDRESS_MASK;
				Address target = wordAddress(table, targetOffset);
				MemoryBlock targetBlock = memory.getBlock(target);
				if (targetBlock == null || targetBlock != branchBlock ||
					!targetBlock.isInitialized() || !targetBlock.isLoaded() ||
					!targetBlock.isExecute()) {
					return null;
				}
				Function targetFunction = program.getFunctionManager().getFunctionAt(target);
				if (hasCallReferenceTo(program, target) ||
					(targetFunction != null && targetFunction != branchFunction)) {
					// Function creation can run after this analyzer. Reject explicit
					// call destinations as well as already-established function entries.
					return null;
				}
				distinctTargets.add(targetOffset);
				targets.add(target);
			}
			return distinctTargets.size() >= Math.min(3, count) ? List.copyOf(targets) : null;
		}
		catch (MemoryAccessException | RuntimeException exception) {
			return null;
		}
	}

	private static boolean hasCallReferenceTo(Program program, Address target) {
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(target);
		while (references.hasNext()) {
			if (references.next().getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}

	private static boolean isComputedXar7Branch(Instruction instruction) {
		// "LB *XAR7" (opcode 0x7620) renders *XAR7 as a print literal in this module's
		// SLEIGH, so the instruction carries zero operands -- distinct from the
		// immediate long branch "LB <target>", which has one. Match the indirect form
		// by mnemonic + operand-count + the "*XAR7" print form, and confirm the
		// resolved computed-jump flow, rather than looking for XAR7 as operand 0
		// (upstream's shape, which is absent here).
		return isMnemonic(instruction, "lb") && instruction.getNumOperands() == 0 &&
			instruction.toString().toUpperCase().endsWith("*XAR7") &&
			instruction.getFlowType().isJump() && instruction.getFlowType().isComputed();
	}

	private static boolean isNativeLongwordLoad(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || !isRegisterOperand(instruction, 0, "XAR7") ||
			instruction.getNumOperands() != 2 ||
			!OperandType.isDynamic(instruction.getOperandType(1))) {
			return false;
		}
		Object[] objects = instruction.getOpObjects(1);
		if (objects.length != 2 || !(objects[0] instanceof Register register) ||
			!(objects[1] instanceof Scalar offset)) {
			return false;
		}
		return register.getName().equalsIgnoreCase("XAR7") && offset.getSignedValue() == 0;
	}

	private static Scalar immediateTableBase(Instruction instruction) {
		if (!isMnemonic(instruction, "movl") || !isRegisterOperand(instruction, 0, "XAR7")) {
			return null;
		}
		return scalarOperand(instruction, 1);
	}

	private static Address tableAddress(Instruction tableInstruction, Scalar scalar) {
		long tableOffset = scalar.getUnsignedValue() & CODE_ADDRESS_MASK;
		return wordAddress(tableInstruction.getAddress(), tableOffset);
	}

	private static String indexSource(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 2);
		if (!isMnemonic(instruction, "mov") || !isRegisterOperand(instruction, 0, "ACC") ||
			shift == null || shift.getUnsignedValue() != 1) {
			return null;
		}
		if (isRegisterOperand(instruction, 1, "AH")) {
			return "AH";
		}
		return isRegisterOperand(instruction, 1, "AL") ? "AL" : null;
	}

	private static boolean isAccImmediateSubtraction(Instruction instruction) {
		return recoverAccImmediateSubtraction(instruction) != null;
	}

	private static Long recoverAccImmediateSubtraction(Instruction instruction) {
		if (!isMnemonic(instruction, "sub") || !isRegisterOperand(instruction, 0, "ACC")) {
			return null;
		}
		Scalar value = scalarOperand(instruction, 1);
		Scalar shift = scalarOperand(instruction, 2);
		if (value == null || value.getUnsignedValue() > 0x7fff) {
			// Keeping bit 15 clear makes the operand independent of SXM.
			return null;
		}
		long shiftValue = shift == null ? 0 : shift.getUnsignedValue();
		if (shiftValue > 15) {
			return null;
		}
		long shifted = value.getUnsignedValue() << shiftValue;
		return shifted <= Integer.MAX_VALUE ? shifted : null;
	}

	private static Long recoverRegisterImmediateAdjustment(Instruction instruction,
			String destination) {
		if (instruction == null || !isRegisterOperand(instruction, 0, destination)) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		if (scalar == null) {
			return null;
		}
		if (isMnemonic(instruction, "add")) {
			return scalar.getSignedValue();
		}
		if (isMnemonic(instruction, "sub") && scalar.getUnsignedValue() <= 0x7fff) {
			return -scalar.getUnsignedValue();
		}
		return null;
	}

	private static Long recoverGuardLow(Instruction instruction) {
		if (instruction == null || !isRegisterOperand(instruction, 0, "AL")) {
			return null;
		}
		Scalar scalar = scalarOperand(instruction, 1);
		if (scalar == null) {
			return null;
		}
		if (isMnemonic(instruction, "add") && scalar.getSignedValue() < 0) {
			return -scalar.getSignedValue();
		}
		if (isMnemonic(instruction, "sub") && scalar.getUnsignedValue() <= 0x7fff) {
			return scalar.getUnsignedValue();
		}
		return null;
	}

	private static boolean isMovzMemoryToAr6(Instruction instruction) {
		if (!isMnemonic(instruction, "movz") ||
			!isRegisterOperand(instruction, 0, "AR6") ||
			instruction.getNumOperands() != 2) {
			return false;
		}
		int type = instruction.getOperandType(1);
		return !OperandType.isRegister(type) &&
			(OperandType.isAddress(type) || OperandType.isIndirect(type) ||
				OperandType.isDynamic(type));
	}

	private static boolean isSetSxmOnly(Instruction instruction) {
		Scalar mask = scalarOperand(instruction, 0);
		return isMnemonic(instruction, "setc") && instruction.getNumOperands() == 1 &&
			mask != null && mask.getUnsignedValue() == 1;
	}

	private static boolean isAr6ScaledAdd(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 2);
		return isMnemonic(instruction, "add") &&
			isRegisterOperand(instruction, 0, "ACC") &&
			isRegisterOperand(instruction, 1, "AR6") && shift != null &&
			shift.getUnsignedValue() == 1;
	}

	private static boolean isImmediateAdd(Instruction instruction, String mnemonic,
			String destination, long value) {
		Scalar scalar = scalarOperand(instruction, 1);
		return isMnemonic(instruction, mnemonic) &&
			isRegisterOperand(instruction, 0, destination) && scalar != null &&
			scalar.getUnsignedValue() == value;
	}

	private static boolean isLslAccByOne(Instruction instruction) {
		Scalar shift = scalarOperand(instruction, 1);
		return isMnemonic(instruction, "lsl") &&
			isRegisterOperand(instruction, 0, "ACC") && shift != null &&
			shift.getUnsignedValue() == 1;
	}

	private static boolean isUnsignedConditionalBranch(Instruction instruction,
			String condition) {
		if (instruction == null || !instruction.getFlowType().isJump() ||
			!instruction.getFlowType().isConditional() ||
			!(isMnemonic(instruction, "sb") || isMnemonic(instruction, "b") ||
				isMnemonic(instruction, "bf"))) {
			return false;
		}
		return operandText(instruction, 1).equalsIgnoreCase(condition);
	}

	private static Address unsignedGuardDefaultPath(Instruction guard,
			DispatchCandidate dispatch) {
		Address entry = dispatch.entryInstruction.getMinAddress();
		Address defaultPath;
		if (dispatch.variant != DispatchVariant.NATIVE_SAVED_P &&
			isUnsignedConditionalBranch(guard, "LOS") && flowsTo(guard, entry)) {
			defaultPath = guard.getFallThrough();
		}
		else if ((dispatch.variant == DispatchVariant.PROGRAM_READ_SAVED_LONG ||
			dispatch.variant == DispatchVariant.NATIVE_SAVED_LONG ||
			dispatch.variant == DispatchVariant.NATIVE_SAVED_P ||
			dispatch.variant == DispatchVariant.NATIVE_AR6_ZERO) &&
			isUnsignedConditionalBranch(guard, "HI") &&
			fallsThroughTo(guard, entry)) {
			Address[] flows = guard.getFlows();
			if (flows.length != 1) {
				return null;
			}
			defaultPath = flows[0];
		}
		else {
			return null;
		}
		return defaultPath != null && !isWithinDispatch(defaultPath, dispatch)
				? defaultPath
				: null;
	}

	private static boolean isSelectorCopy(Instruction instruction) {
		return isRegisterMove(instruction, "mov", "AH", "AL") ||
			isRegisterMove(instruction, "mov", "AL", "AH");
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

	private static boolean isRegisterOperand(Instruction instruction, int operand,
			String registerName) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		Register register = instruction.getRegister(operand);
		if (register != null) {
			return register.getName().equalsIgnoreCase(registerName);
		}
		// Register-valued loc32 subtables may expose the operand as dynamic even
		// though the rendered operand and its sole object are the register itself.
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
		// This module's SLEIGH renders "*XAR7"-style indirect operands with the
		// register baked into the print form rather than exposed as an operand
		// object; fall back to matching the rendered operand text so callers that
		// upstream matched via getRegister continue to work here.
		return instruction.getDefaultOperandRepresentation(operand)
			.equalsIgnoreCase("*" + registerName);
	}

	private static Scalar scalarOperand(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? null
				: instruction.getScalar(operand);
	}

	private static boolean writesRegister(Instruction instruction, String registerName) {
		if (instruction == null) {
			return false;
		}
		Register expected = instruction.getProgram().getLanguage().getRegister(registerName);
		if (expected != null) {
			for (Object object : instruction.getResultObjects()) {
				if (object instanceof Register result &&
					(expected.contains(result) || result.contains(expected))) {
					return true;
				}
			}
		}
		// Result objects are decoder-dependent; operand zero is a conservative
		// fallback for the XAR-writing instructions admitted by this recognizer.
		return isRegisterOperand(instruction, 0, registerName);
	}

	private static String operandText(Instruction instruction, int operand) {
		return instruction == null || operand >= instruction.getNumOperands()
				? ""
				: instruction.getDefaultOperandRepresentation(operand);
	}

	private static boolean flowsTo(Instruction instruction, Address destination) {
		if (instruction == null) {
			return false;
		}
		for (Address flow : instruction.getFlows()) {
			if (flow.equals(destination)) {
				return true;
			}
		}
		return false;
	}

	private static boolean fallsThroughTo(Instruction instruction, Address destination) {
		Address fallThrough = instruction == null ? null : instruction.getFallThrough();
		return fallThrough != null && fallThrough.equals(destination);
	}

	private static boolean hasExplicitFlowReferenceTo(Instruction instruction) {
		ReferenceIterator references = instruction.getProgram().getReferenceManager()
				.getReferencesTo(instruction.getMinAddress());
		while (references.hasNext()) {
			Reference reference = references.next();
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	private static boolean isWithinDispatch(Address address, DispatchCandidate dispatch) {
		return address.compareTo(dispatch.entryInstruction.getMinAddress()) >= 0 &&
			address.compareTo(dispatch.branchInstruction.getMaxAddress()) <= 0;
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

	private static Instruction contiguousNext(Instruction instruction) {
		if (instruction == null) {
			return null;
		}
		Instruction next = instruction.getNext();
		return next != null && instruction.getMaxAddress().next().equals(next.getMinAddress())
				? next
				: null;
	}

	/** Convert an architectural C28 word address to Ghidra's byte-offset Address. */
	private static Address wordAddress(Address basis, long wordOffset) {
		int wordSize = basis.getAddressSpace().getAddressableUnitSize();
		return basis.getAddressSpace().getAddress(Math.multiplyExact(wordOffset, wordSize));
	}

	private enum DispatchVariant {
		PROGRAM_READ("program-read PREAD"),
		PROGRAM_READ_SAVED_LONG("saved-selector program-read PREAD"),
		NATIVE_PL("unified-memory native-load"),
		NATIVE_SAVED_LONG("saved-selector native-load"),
		NATIVE_SAVED_P("P-saved fall-through native-load"),
		NATIVE_AR6_ZERO("zero-based AR6-indexed native-load"),
		NATIVE_DIRECT("compact native-load");

		private final String description;

		DispatchVariant(String description) {
			this.description = description;
		}
	}

	private static final class IndexExpression {
		private final Instruction instruction;
		private final String sourceRegister;
		private final long scaleWords;
		private final long adjustmentWords;

		private IndexExpression(Instruction instruction, String sourceRegister, long scaleWords,
				long adjustmentWords) {
			this.instruction = instruction;
			this.sourceRegister = sourceRegister;
			this.scaleWords = scaleWords;
			this.adjustmentWords = adjustmentWords;
		}
	}

	private static final class DispatchCandidate {
		private final Instruction entryInstruction;
		private final Instruction branchInstruction;
		private final Address tableBase;
		private final IndexExpression indexExpression;
		private final DispatchVariant variant;

		private DispatchCandidate(Instruction entryInstruction, Instruction branchInstruction,
				Address tableBase, IndexExpression indexExpression, DispatchVariant variant) {
			this.entryInstruction = entryInstruction;
			this.branchInstruction = branchInstruction;
			this.tableBase = tableBase;
			this.indexExpression = indexExpression;
			this.variant = variant;
		}
	}

	private static final class Guard {
		private final Instruction instruction;
		@SuppressWarnings("unused")
		private final Instruction startInstruction;
		private final Instruction canonicalInstruction;
		private final long low;
		private final int count;
		private final Address defaultPath;

		private Guard(Instruction instruction, Instruction startInstruction,
				Instruction canonicalInstruction, long low, int count, Address defaultPath) {
			this.instruction = instruction;
			this.startInstruction = startInstruction;
			this.canonicalInstruction = canonicalInstruction;
			this.low = low;
			this.count = count;
			this.defaultPath = defaultPath;
		}
	}

	/** Fully recovered and validated switch facts shared by all dispatch variants. */
	private static final class SwitchDescriptor {
		private final Address branchAddress;
		private final Address tableBase;
		private final int count;
		private final long lowestCase;
		private final Address defaultPath;
		private final Instruction guardCanonicalInstruction;
		private final IndexExpression indexExpression;
		@SuppressWarnings("unused")
		private final List<Address> validatedTargets;
		private final DispatchVariant variant;

		private SwitchDescriptor(Address branchAddress, Address tableBase, int count,
				long lowestCase, Address defaultPath, Instruction guardCanonicalInstruction,
				IndexExpression indexExpression, List<Address> validatedTargets,
				DispatchVariant variant) {
			this.branchAddress = branchAddress;
			this.tableBase = tableBase;
			this.count = count;
			this.lowestCase = lowestCase;
			this.defaultPath = defaultPath;
			this.guardCanonicalInstruction = guardCanonicalInstruction;
			this.indexExpression = indexExpression;
			this.validatedTargets = validatedTargets;
			this.variant = variant;
		}
	}

	private static final class IndexAndTable {
		private final Instruction entryInstruction;
		private final Instruction indexInstruction;
		private final String indexSource;
		private final Instruction tableInstruction;
		private final Scalar tableScalar;

		private IndexAndTable(Instruction entryInstruction, Instruction indexInstruction,
				String indexSource, Instruction tableInstruction, Scalar tableScalar) {
			this.entryInstruction = entryInstruction;
			this.indexInstruction = indexInstruction;
			this.indexSource = indexSource;
			this.tableInstruction = tableInstruction;
			this.tableScalar = tableScalar;
		}
	}

	private static final class DirectIndexAndTable {
		private final Instruction entryInstruction;
		private final Instruction tableInstruction;
		private final Scalar tableScalar;
		private final Instruction indexInstruction;
		private final String indexSource;
		private final long adjustment;

		private DirectIndexAndTable(Instruction entryInstruction, Instruction tableInstruction,
				Scalar tableScalar, Instruction indexInstruction, String indexSource,
				long adjustment) {
			this.entryInstruction = entryInstruction;
			this.tableInstruction = tableInstruction;
			this.tableScalar = tableScalar;
			this.indexInstruction = indexInstruction;
			this.indexSource = indexSource;
			this.adjustment = adjustment;
		}
	}

	private static final class RegisterBound {
		private final Instruction instruction;
		private final long highInclusive;

		private RegisterBound(Instruction instruction, long highInclusive) {
			this.instruction = instruction;
			this.highInclusive = highInclusive;
		}
	}
}
