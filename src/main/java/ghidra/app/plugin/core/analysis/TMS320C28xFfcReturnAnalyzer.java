// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Copyright the mwdmwd/ghidra-c28x contributors (https://github.com/mwdmwd/ghidra-c28x)
//
// Ported from mwdmwd/ghidra-c28x (Apache-2.0). Local changes: the processor-name
// string ("TMS320C28x" here vs "TMS320C28" upstream), the class rename, and the
// FFC/LB detection in ffcTarget() / isXar7Branch(). Upstream matches XAR7 as
// operand 0, but this module's SLEIGH renders "FFC XAR7,#t" and "LB *XAR7" with
// XAR7 as a mnemonic-attached print literal (the FFC's operand 0 is the target;
// "LB *XAR7" has no operand at all), so detection is by mnemonic + resolved call
// flow and the *XAR7 print form instead. See THIRD-PARTY.md.
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Reclassifies the terminal {@code LB *XAR7} of a narrowly proven fast-function
 * helper as a return.
 * <p>
 * The C28x {@code FFC XAR7,dest} instruction stores its return address in XAR7;
 * TI documents {@code LB *XAR7} as the corresponding return sequence.  The
 * opcode is nevertheless also the ordinary computed branch used by switch
 * tables.  This analyzer therefore changes no global calling convention and
 * does not match an untagged branch.  It requires all of the following finite
 * evidence:
 * <ul>
 *   <li>one or more decoded FFC calls target the helper entry,</li>
 *   <li>every incoming flow reference to the entry is one of those FFC calls,</li>
 *   <li>there is no fall-through into the entry or external ingress into its body,</li>
 *   <li>the bounded body is contiguous and straight-line through a terminal
 *       {@code LB *XAR7}, and</li>
 *   <li>no intervening instruction writes any part of XAR7.</li>
 * </ul>
 * Only the proven terminal instruction receives local SLEIGH context selecting
 * RETURN P-Code. Ordinary indirect branches and switch-canonicalized LBs
 * retain their existing semantics.
 */
public class TMS320C28xFfcReturnAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x FFC Return Analyzer";
	private static final String DESCRIPTION =
		"Recognizes exclusive FFC helpers returning through an untouched XAR7";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String RETURN_CONTEXT_NAME = "ffc_return";
	private static final String SWITCH_CONTEXT_NAME = "switch_canonical";
	private static final int MAX_HELPER_INSTRUCTIONS = 128;

	public TMS320C28xFfcReturnAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
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
		Register returnContext = context.getRegister(RETURN_CONTEXT_NAME);
		Register switchContext = context.getRegister(SWITCH_CONTEXT_NAME);
		if (returnContext == null || switchContext == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " +
				(returnContext == null ? RETURN_CONTEXT_NAME : SWITCH_CONTEXT_NAME));
			return false;
		}

		Listing listing = program.getListing();
		Map<Address, List<Instruction>> callersByTarget = recoverFfcCallers(listing, monitor);
		List<FfcHelper> matches = new ArrayList<>();
		Set<Address> validReturns = new HashSet<>();
		for (Map.Entry<Address, List<Instruction>> entry : callersByTarget.entrySet()) {
			monitor.checkCancelled();
			FfcHelper helper = recoverHelper(program, entry.getKey(), entry.getValue(),
				switchContext, monitor);
			if (helper != null) {
				matches.add(helper);
				validReturns.add(helper.returnAddress);
			}
		}

		List<Instruction> revocations = new ArrayList<>();
		InstructionIterator taggedInstructions = listing.getInstructions(true);
		while (taggedInstructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = taggedInstructions.next();
			if (BigInteger.ONE.equals(context.getValue(returnContext,
				instruction.getMinAddress(), false)) && !validReturns.contains(instruction.getMinAddress())) {
				revocations.add(instruction);
			}
		}

		AddressSet redisassemble = new AddressSet();
		for (FfcHelper helper : matches) {
			Instruction terminal = listing.getInstructionAt(helper.returnAddress);
			if (terminal == null || BigInteger.ONE.equals(context.getValue(returnContext,
				terminal.getMinAddress(), false))) {
				continue;
			}
			try {
				listing.clearCodeUnits(terminal.getMinAddress(), terminal.getMaxAddress(), false);
				context.setValue(returnContext, terminal.getMinAddress(), terminal.getMaxAddress(),
					BigInteger.ONE);
				redisassemble.add(terminal.getMinAddress());
				Msg.info(this,
					"recognized FFC helper return at " + helper.returnAddress + " entry=" +
						helper.entryAddress + " callers=" + helper.callerCount + " instructions=" +
						helper.instructionCount);
			}
			catch (ContextChangeException exception) {
				log.appendException(exception);
			}
		}
		for (Instruction terminal : revocations) {
			try {
				Address address = terminal.getMinAddress();
				listing.clearCodeUnits(terminal.getMinAddress(), terminal.getMaxAddress(), false);
				context.setValue(returnContext, terminal.getMinAddress(), terminal.getMaxAddress(),
					BigInteger.ZERO);
				redisassemble.add(address);
				Msg.info(this, "revoked unproven FFC helper return at " + address);
			}
			catch (ContextChangeException exception) {
				log.appendException(exception);
			}
		}

		if (!redisassemble.isEmpty()) {
			AutoAnalysisManager.getAnalysisManager(program)
				.disassemble(redisassemble, AnalysisPriority.DISASSEMBLY);
		}
		return true;
	}

	private static Map<Address, List<Instruction>> recoverFfcCallers(Listing listing,
			TaskMonitor monitor) throws CancelledException {
		Map<Address, List<Instruction>> callersByTarget = new LinkedHashMap<>();
		InstructionIterator instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			Address target = ffcTarget(instruction);
			if (target != null) {
				callersByTarget.computeIfAbsent(target, ignored -> new ArrayList<>())
					.add(instruction);
			}
		}
		return callersByTarget;
	}

	private static FfcHelper recoverHelper(Program program, Address entry,
			List<Instruction> callers, Register switchContext,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Instruction first = listing.getInstructionAt(entry);
		if (first == null || callers.isEmpty() || hasFallthroughInto(first)) {
			return null;
		}
		if (!hasExclusiveFfcEntry(program, entry, callers)) {
			return null;
		}

		List<Instruction> body = new ArrayList<>();
		Instruction current = first;
		for (int count = 0; count < MAX_HELPER_INSTRUCTIONS; count++) {
			monitor.checkCancelled();
			if (current == null) {
				return null;
			}
			body.add(current);
			if (isXar7Branch(current)) {
				if (BigInteger.ONE.equals(program.getProgramContext().getValue(switchContext,
					current.getMinAddress(), false))) {
					return null;
				}
				if (!hasExclusiveBodyIngress(program, body)) {
					return null;
				}
				return new FfcHelper(entry, current.getMinAddress(), callers.size(), body.size());
			}
			if (writesRegister(current, "XAR7") || hasNonFallthroughFlow(current)) {
				return null;
			}

			Instruction next = contiguousNext(current);
			if (next == null || !next.getMinAddress().equals(current.getFallThrough())) {
				return null;
			}
			current = next;
		}
		return null;
	}

	private static boolean hasExclusiveFfcEntry(Program program, Address entry,
			List<Instruction> callers) {
		Set<Address> expectedCallers = new HashSet<>();
		for (Instruction caller : callers) {
			if (!entry.equals(ffcTarget(caller))) {
				return false;
			}
			expectedCallers.add(caller.getMinAddress());
		}

		Set<Address> observedCallers = new HashSet<>();
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(entry);
		while (references.hasNext()) {
			Reference reference = references.next();
			if (!reference.getReferenceType().isFlow()) {
				continue;
			}
			Instruction source = program.getListing().getInstructionAt(reference.getFromAddress());
			if (source == null || !entry.equals(ffcTarget(source)) ||
				!expectedCallers.contains(source.getMinAddress())) {
				return false;
			}
			observedCallers.add(source.getMinAddress());
		}
		return !observedCallers.isEmpty() && observedCallers.equals(expectedCallers);
	}

	private static boolean hasExclusiveBodyIngress(Program program, List<Instruction> body) {
		Set<Address> bodyAddresses = new HashSet<>();
		for (Instruction instruction : body) {
			bodyAddresses.add(instruction.getMinAddress());
		}
		for (int i = 1; i < body.size(); i++) {
			Instruction instruction = body.get(i);
			ReferenceIterator references = program.getReferenceManager()
				.getReferencesTo(instruction.getMinAddress());
			while (references.hasNext()) {
				Reference reference = references.next();
				if (reference.getReferenceType().isFlow() &&
					!bodyAddresses.contains(reference.getFromAddress())) {
					return false;
				}
			}
		}
		return true;
	}

	private static Address ffcTarget(Instruction instruction) {
		// This module's SLEIGH renders "FFC XAR7,#target" with XAR7 as a mnemonic-
		// attached print literal, so operand 0 is the target (not the XAR7 register)
		// and the instruction carries exactly one resolved call flow. FFC is the sole
		// user of this mnemonic, so mnemonic + call-flow uniquely identifies it; take
		// the target from the resolved flow rather than an XAR7 operand (which upstream
		// assumed and which does not exist in this module's operand model).
		if (!isMnemonic(instruction, "ffc") || !instruction.getFlowType().isCall()) {
			return null;
		}
		Address[] flows = instruction.getFlows();
		return flows.length == 1 ? flows[0] : null;
	}

	private static boolean isXar7Branch(Instruction instruction) {
		// "LB *XAR7" (opcode 0x7620) renders *XAR7 as a print literal, so it carries
		// zero operands -- distinct from the immediate long branch "LB <target>", which
		// has one. Match the indirect form on that shape rather than an XAR7 operand.
		return isMnemonic(instruction, "lb") && instruction.getNumOperands() == 0 &&
			instruction.toString().toUpperCase().endsWith("*XAR7");
	}

	private static boolean hasNonFallthroughFlow(Instruction instruction) {
		return instruction.getFlowType().isCall() || instruction.getFlowType().isJump() ||
			instruction.getFlowType().isTerminal() || instruction.getFlows().length != 0;
	}

	private static boolean hasFallthroughInto(Instruction instruction) {
		Instruction previous = instruction.getPrevious();
		return previous != null && instruction.getMinAddress().equals(previous.getFallThrough());
	}

	private static boolean writesRegister(Instruction instruction, String registerName) {
		Register expected = instruction.getProgram().getLanguage().getRegister(registerName);
		if (expected != null) {
			for (Object object : instruction.getResultObjects()) {
				if (object instanceof Register result &&
					(expected.contains(result) || result.contains(expected))) {
					return true;
				}
			}
		}
		// Decoder result objects are not guaranteed for every instruction.  Since
		// C28x syntax puts register destinations first, treating an XAR7 operand 0
		// as a write is a conservative fallback (and intentionally rejects PUSH).
		return isRegisterOperand(instruction, 0, registerName);
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
		Object[] objects = instruction.getOpObjects(operand);
		for (Object object : objects) {
			if (object instanceof Register objectRegister &&
				objectRegister.getName().equalsIgnoreCase(registerName)) {
				return true;
			}
		}
		return instruction.getDefaultOperandRepresentation(operand)
			.equalsIgnoreCase("*" + registerName);
	}

	private static Instruction contiguousNext(Instruction instruction) {
		Instruction next = instruction.getNext();
		return next != null && instruction.getMaxAddress().next().equals(next.getMinAddress())
				? next
				: null;
	}

	private static final class FfcHelper {
		private final Address entryAddress;
		private final Address returnAddress;
		private final int callerCount;
		private final int instructionCount;

		private FfcHelper(Address entryAddress, Address returnAddress, int callerCount,
				int instructionCount) {
			this.entryAddress = entryAddress;
			this.returnAddress = returnAddress;
			this.callerCount = callerCount;
			this.instructionCount = instructionCount;
		}
	}
}
