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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
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
import ghidra.program.model.symbol.FlowType;
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
 *   <li>the body closes under its own control flow within a bounded instruction
 *       count, every path ending at an {@code LB *XAR7}, and</li>
 *   <li>no instruction in that region writes any part of XAR7, calls out (XAR7 is
 *       killed by call), or transfers anywhere the closure cannot enumerate.</li>
 * </ul>
 * The body need not be one basic block: a helper that returns early is still
 * proven, because the guarantee comes from XAR7 being unwritten across the whole
 * region and the region being enterable only at its entry, not from the shape of
 * the control flow between them.
 * <p>
 * Every proven {@code LB *XAR7} receives local SLEIGH context selecting RETURN
 * P-Code. Ordinary indirect branches and switch-canonicalized LBs retain their
 * existing semantics.
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
				validReturns.addAll(helper.returnAddresses);
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
			for (Address returnAddress : helper.returnAddresses) {
				Instruction terminal = listing.getInstructionAt(returnAddress);
				if (terminal == null || BigInteger.ONE.equals(context.getValue(returnContext,
					terminal.getMinAddress(), false))) {
					continue;
				}
				try {
					listing.clearCodeUnits(terminal.getMinAddress(), terminal.getMaxAddress(),
						false);
					context.setValue(returnContext, terminal.getMinAddress(),
						terminal.getMaxAddress(), BigInteger.ONE);
					redisassemble.add(terminal.getMinAddress());
					Msg.info(this,
						"recognized FFC helper return at " + returnAddress + " entry=" +
							helper.entryAddress + " callers=" + helper.callerCount +
							" instructions=" + helper.instructionCount + " returns=" +
							helper.returnAddresses.size());
				}
				catch (ContextChangeException exception) {
					log.appendException(exception);
				}
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

		// Bounded closure over the helper's OWN control flow, not a straight line.
		//
		// The proof never needed the body to be a single basic block. What it needs is
		// that XAR7 is unwritten everywhere in the region and that the region can only
		// be entered at `entry` (checked below); under those two conditions every
		// `LB *XAR7` inside it necessarily branches to the address the FFC stored,
		// whatever the internal control flow looks like.
		//
		// Requiring one straight-line exit rejected an entire shape TI emits freely:
		// the compare/shift helpers that return early. Measured on a production PMR
		// image, one of the two real FFC helpers is exactly that -- a 64-bit compare
		// with an `SB ...,NEQ` over a second `LB *XAR7`.
		Map<Address, Instruction> body = new LinkedHashMap<>();
		List<Address> returns = new ArrayList<>();
		Deque<Instruction> pending = new ArrayDeque<>();
		pending.add(first);
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			Instruction current = pending.poll();
			if (body.containsKey(current.getMinAddress())) {
				continue;
			}
			if (body.size() >= MAX_HELPER_INSTRUCTIONS) {
				return null;
			}
			body.put(current.getMinAddress(), current);

			if (isXar7Branch(current)) {
				// The switch canonicalizer owns this opcode when it has claimed it,
				// and its context bit outranks this analyzer.
				if (BigInteger.ONE.equals(program.getProgramContext().getValue(switchContext,
					current.getMinAddress(), false))) {
					return null;
				}
				returns.add(current.getMinAddress());
				continue;   // an exit: nothing flows past it
			}
			if (writesRegister(current, "XAR7")) {
				return null;
			}
			// A call may clobber XAR7 (it is killedbycall), and a computed transfer has
			// no enumerable successor, so neither can be carried across. A terminal that
			// is not one of our exits ends a path we cannot account for. All three
			// simply fail the proof, exactly as the straight-line walk failed them.
			FlowType flow = current.getFlowType();
			if (flow.isCall() || flow.isTerminal() || flow.isComputed()) {
				return null;
			}

			for (Address target : current.getFlows()) {
				Instruction next = listing.getInstructionAt(target);
				if (next == null) {
					return null;
				}
				pending.add(next);
			}
			Address fallThrough = current.getFallThrough();
			if (fallThrough != null) {
				Instruction next = listing.getInstructionAt(fallThrough);
				if (next == null) {
					return null;
				}
				pending.add(next);
			}
			else if (current.getFlows().length == 0) {
				return null;   // no successor at all, and not an exit
			}
		}

		if (returns.isEmpty() || !hasExclusiveBodyIngress(program, entry, body.keySet())) {
			return null;
		}
		return new FfcHelper(entry, returns, callers.size(), body.size());
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

	/**
	 * True when nothing outside {@code bodyAddresses} can reach any of it except at
	 * {@code entry} (whose ingress is proven against the FFC callers separately).
	 * <p>
	 * Both ways in have to be closed. A recorded flow reference covers branches and
	 * calls; plain FALL-THROUGH is not a reference, so it is checked directly against
	 * the preceding instruction. The straight-line walk this replaced got the second
	 * one for free, by being contiguous from the entry and testing only the entry.
	 */
	private static boolean hasExclusiveBodyIngress(Program program, Address entry,
			Set<Address> bodyAddresses) {
		Listing listing = program.getListing();
		for (Address address : bodyAddresses) {
			if (address.equals(entry)) {
				continue;
			}
			Instruction instruction = listing.getInstructionAt(address);
			Instruction previous = instruction == null ? null : instruction.getPrevious();
			if (previous != null && !bodyAddresses.contains(previous.getMinAddress()) &&
				address.equals(previous.getFallThrough())) {
				return false;
			}
			ReferenceIterator references = program.getReferenceManager()
				.getReferencesTo(address);
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

	private static final class FfcHelper {
		private final Address entryAddress;
		/** Every proven {@code LB *XAR7} in the body; a helper may return early. */
		private final List<Address> returnAddresses;
		private final int callerCount;
		private final int instructionCount;

		private FfcHelper(Address entryAddress, List<Address> returnAddresses, int callerCount,
				int instructionCount) {
			this.entryAddress = entryAddress;
			this.returnAddresses = returnAddresses;
			this.callerCount = callerCount;
			this.instructionCount = instructionCount;
		}
	}
}
