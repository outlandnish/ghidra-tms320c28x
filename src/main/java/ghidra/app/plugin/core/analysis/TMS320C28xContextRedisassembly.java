// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Copyright the mwdmwd/ghidra-c28x contributors (https://github.com/mwdmwd/ghidra-c28x)
//
// Re-disassembling one instruction under a new SLEIGH context value without losing what
// was attached to it.
//
// The FFC-return, PM-shift and switch analyzers each select a constructor variant by
// setting a context bit on an already-decoded instruction. Ghidra binds context at decode
// time, so the instruction has to be cleared and decoded again. Clearing it also deletes
// every reference from it and every override on it, and re-disassembly restores only the
// DEFAULT references the new decode implies. Anything else was lost:
//   - references a user or a script added. ResolveComputedPointerXrefs writes data
//     references onto exactly the deref instructions the PM-shift analyzer re-decodes,
//     e.g. `MOV *+XAR4[2],P`.
//   - flow, fall-through and length overrides a user set.
// Re-analysis ran these analyzers again and quietly undid that work.
//
// This saves the non-DEFAULT memory references and the overrides, clears and re-contexts
// the instruction, and puts them back. Without overrides the instruction is left to the
// caller's batched AutoAnalysisManager.disassemble. An override needs an instruction to
// sit on, so with one present this decodes it at once and restores the override before
// any queued analyzer can see the replacement without it.
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;

/** Clears and re-contexts one instruction, keeping its non-DEFAULT references and overrides. */
public final class TMS320C28xContextRedisassembly {

	private TMS320C28xContextRedisassembly() {
	}

	private record SavedReference(Address target, RefType type, SourceType source,
			int operand, boolean primary) {
	}

	/**
	 * Set {@code register} to {@code value} over {@code instruction} and queue it for
	 * re-disassembly in {@code redisassemble}, carrying its references and overrides across.
	 *
	 * @return true if the context was changed; false (with the reason in {@code log}) if not
	 */
	public static boolean recontext(Program program, Instruction instruction, Register register,
			BigInteger value, AddressSet redisassemble, TaskMonitor monitor, MessageLog log,
			String owner) {
		Address start = instruction.getMinAddress();
		Address end = instruction.getMaxAddress();
		FlowOverride flowOverride = instruction.getFlowOverride();
		boolean fallOverridden = instruction.isFallThroughOverridden();
		Address fallThrough = instruction.getFallThrough();
		int lengthOverride = instruction.isLengthOverridden() ? instruction.getLength() : 0;
		boolean overridden =
			flowOverride != FlowOverride.NONE || fallOverridden || lengthOverride != 0;

		ReferenceManager refs = program.getReferenceManager();
		List<SavedReference> saved = new ArrayList<>();
		for (Reference ref : refs.getReferencesFrom(start)) {
			if (ref.isMemoryReference() && ref.getSource() != SourceType.DEFAULT) {
				saved.add(new SavedReference(ref.getToAddress(), ref.getReferenceType(),
					ref.getSource(), ref.getOperandIndex(), ref.isPrimary()));
			}
		}

		try {
			program.getListing().clearCodeUnits(start, end, false);
			program.getProgramContext().setValue(register, start, end, value);
			if (overridden) {
				if (!new DisassembleCommand(start, null, false).applyTo(program, monitor)) {
					log.appendMsg(owner, "could not re-disassemble overridden instruction at " +
						start);
					return false;
				}
				Instruction restored = program.getListing().getInstructionAt(start);
				if (restored == null) {
					log.appendMsg(owner, "no instruction after re-disassembly at " + start);
					return false;
				}
				if (flowOverride != FlowOverride.NONE) {
					restored.setFlowOverride(flowOverride);
				}
				if (fallOverridden) {
					restored.setFallThrough(fallThrough);
				}
				if (lengthOverride != 0) {
					restored.setLengthOverride(lengthOverride);
				}
			}
			redisassemble.add(start);
			return true;
		}
		catch (ContextChangeException | CodeUnitInsertionException exception) {
			log.appendException(exception);
			return false;
		}
		finally {
			// Unconditionally: a failed re-context must not cost the references either.
			for (SavedReference ref : saved) {
				Reference back =
					refs.addMemoryReference(start, ref.target, ref.type, ref.source, ref.operand);
				if (ref.primary) {
					refs.setPrimary(back, true);
				}
			}
		}
	}
}
