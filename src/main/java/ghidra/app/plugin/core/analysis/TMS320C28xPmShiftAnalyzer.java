// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Copyright the mwdmwd/ghidra-c28x contributors (https://github.com/mwdmwd/ghidra-c28x)
//
// Marks the instructions where the C28x product shift mode actually shifts.
//
// Every instruction that reads P applies the decoded ST0.PM product shift (-6..+1).
// This module has always modelled P unshifted, documented as an approximation in
// tms320c28x_mac.sinc, and that approximation is right far more often than not: the TI C
// runtime establishes PM=0 at function entry (SPRU514 Table 7-4), so a function containing
// no SPM at all runs at PM=0. Measured over two production images, of 924 product-consuming
// instructions in a DIR image, 868 sit in such a function and only 32 are reached with a
// non-zero PM; in a PMR image it is 1 of 409.
//
// So the shift is the exception, and this analyzer marks the exceptions: where it can prove
// PM is non-zero on every path into a P-consuming instruction, it sets the pm_shift context
// bit and SLEIGH selects a variant that applies the real shift.
//
// This INVERTS mwdmwd's TMS320C28PmProductStoreAnalyzer (375fa7f), which proves the opposite
// -- their default applies the shift and their analyzer proves PM=0 to remove it. Their
// polarity follows from their spec modelling PM everywhere; ours follows from this one not
// modelling it at all. Adopting theirs unchanged would have put a shift term on ~900 product
// paths in order to fix 32, and the 868 with no SPM in the function are exactly the ones no
// prover can discharge, so they would carry it permanently. Same mechanism, opposite sign.
// See issue #74 and THIRD-PARTY.md.
package ghidra.app.plugin.core.analysis;

import static ghidra.app.plugin.core.analysis.TMS320C28xSwitchShapes.contiguousPrevious;
import static ghidra.app.plugin.core.analysis.TMS320C28xSwitchShapes.isMnemonic;
import static ghidra.app.plugin.core.analysis.TMS320C28xSwitchShapes.isPrintedRegister;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

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
 * Sets the {@code pm_shift} SLEIGH context bit on P-consuming instructions proved to run
 * under a non-zero product shift mode. See the file header for why the proof runs in this
 * direction rather than upstream's.
 */
public class TMS320C28xPmShiftAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x PM Product Shift";
	private static final String DESCRIPTION =
		"Applies the PM product shift where an SPM proves it non-zero";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String CONTEXT_NAME = "pm_shift";
	// How far back of a consumer the governing SPM may sit. The proof requires an unbroken
	// straight-line run, so this only bounds the work, not the soundness.
	private static final int MAX_SCAN = 64;

	public TMS320C28xPmShiftAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Same slot as the switch canonicalizer: after instructions exist, before
		// CODE_ANALYSIS builds the P-Code the decompiler will read.
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
		Register pmShift = context.getRegister(CONTEXT_NAME);
		if (pmShift == null) {
			log.appendMsg(NAME, "missing SLEIGH context register " + CONTEXT_NAME);
			return false;
		}

		Listing listing = program.getListing();
		List<Proof> proofs = new ArrayList<>();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (!isProductConsumer(instruction) ||
				BigInteger.ONE.equals(
					context.getValue(pmShift, instruction.getMinAddress(), false))) {
				continue;
			}
			Integer mode = recoverProvenShiftMode(instruction);
			if (mode != null && mode != 0) {
				proofs.add(new Proof(instruction.getMinAddress(), mode));
			}
		}

		AddressSet redisassemble = new AddressSet();
		for (Proof proof : proofs) {
			Instruction instruction = listing.getInstructionAt(proof.address);
			if (instruction == null) {
				continue;
			}
			try {
				listing.clearCodeUnits(instruction.getMinAddress(), instruction.getMaxAddress(),
					false);
				context.setValue(pmShift, instruction.getMinAddress(), instruction.getMaxAddress(),
					BigInteger.ONE);
				redisassemble.add(instruction.getMinAddress());
				Msg.info(this, "PM product shift " + proof.mode + " proved at " + proof.address);
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

	/**
	 * The decoded product shift mode governing {@code consumer}, or null when no SPM proves
	 * one.
	 *
	 * <p>The proof is a straight-line run: walk back from the consumer while each step is the
	 * fall-through of the one before it, and require that nothing in the run is the target of
	 * a flow reference. That second half is what makes it a proof rather than a guess -- an
	 * instruction that can be jumped to may be reached from somewhere the SPM never executed,
	 * so the mode it sets would not hold on every path in.
	 */
	private static Integer recoverProvenShiftMode(Instruction consumer) {
		Instruction next = consumer;
		Instruction current = contiguousPrevious(consumer);
		for (int steps = 0; steps < MAX_SCAN && current != null; steps++) {
			Address fallThrough = current.getFallThrough();
			if (fallThrough == null || !fallThrough.equals(next.getMinAddress()) ||
				hasIncomingFlow(next)) {
				return null;
			}
			if (isMnemonic(current, "spm")) {
				return decodeShiftMode(current);
			}
			// A write to PM this analyzer cannot read (POP ST0 restores the whole word)
			// ends the proof rather than being walked past.
			if (writesProductShiftMode(current)) {
				return null;
			}
			next = current;
			current = contiguousPrevious(current);
		}
		return null;
	}

	private static boolean hasIncomingFlow(Instruction instruction) {
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

	/**
	 * {@code SPM} renders its mode as a display literal ("SPM -2", "SPM +1", "SPM 0"), so the
	 * value is read from the printed text rather than from an operand.
	 */
	private static Integer decodeShiftMode(Instruction spm) {
		String text = spm.toString().trim();
		int space = text.indexOf(' ');
		if (space < 0) {
			return null;
		}
		String mode = text.substring(space + 1).trim();
		if (mode.startsWith("+")) {
			mode = mode.substring(1);
		}
		try {
			return Integer.valueOf(mode);
		}
		catch (NumberFormatException exception) {
			return null;
		}
	}

	/** Anything other than SPM that redefines PM, after which the mode is unknown again. */
	private static boolean writesProductShiftMode(Instruction instruction) {
		if (isMnemonic(instruction, "pop") || isMnemonic(instruction, "setflg") ||
			isMnemonic(instruction, "movst0")) {
			return true;
		}
		Register pm = instruction.getProgram().getLanguage().getRegister("PM");
		if (pm == null) {
			return false;
		}
		for (Object object : instruction.getResultObjects()) {
			if (object instanceof Register result && (pm.contains(result) || result.contains(pm))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The instructions whose value depends on the product shift. Exactly the set that has a
	 * {@code pm_shift=1} variant, so a proof here always changes something.
	 *
	 * <pre>
	 * ADDL|SUBL|CMPL ACC,P &lt;&lt; PM   TI writes the shift into the syntax
	 * MOVL ACC,P                    "ACC = P &lt;&lt; PM"      (SPRU430F)
	 * MOV  loc16,P                  "[loc16] = low(P &lt;&lt; PM)"
	 * MOVH loc16,P                  "[loc16] = high(P &lt;&lt; PM)"
	 * </pre>
	 *
	 * <p>{@code MOVL loc32,P} is deliberately NOT here: SPRU430F defines it as
	 * {@code [loc32] = P}, plain, and titles it "Store the P Register" against
	 * "Store Lower Half of <i>Shifted</i> P Register" for the loc16 form. It reads P without
	 * the shift, so marking it would claim a correction that its constructor cannot make.
	 * Telling the two apart needs the RAW printed text, not a field comparison: the shifted
	 * form prints {@code MOVL ACC,P} and the store prints {@code MOVL @ACC,P} when its loc32
	 * happens to be ACC, and the usual field helpers strip the {@code @} that separates them.
	 *
	 * <p>The MAC family shifts too, but no site in either surveyed image reaches one with a
	 * non-zero PM, so those stay on the plain model rather than being paired on speculation.
	 */
	private static boolean isProductConsumer(Instruction instruction) {
		String text = instruction.toString().toUpperCase().replaceAll("\\s+", " ").trim();
		if (isMnemonic(instruction, "addl") || isMnemonic(instruction, "subl") ||
			isMnemonic(instruction, "cmpl")) {
			return text.endsWith(",P << PM");
		}
		if (isMnemonic(instruction, "movl")) {
			return text.equals("MOVL ACC,P");
		}
		return (isMnemonic(instruction, "mov") || isMnemonic(instruction, "movh")) &&
			isPrintedRegister(instruction, 1, "P");
	}

	private record Proof(Address address, int mode) {
	}
}
