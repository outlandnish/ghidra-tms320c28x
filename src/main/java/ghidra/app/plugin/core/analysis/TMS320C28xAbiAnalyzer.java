// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
package ghidra.app.plugin.core.analysis;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Re-lays out parameter storage per SPRU514 §7.3.1 class-priority rules on
 * functions whose signatures have known types.
 *
 * <p>The C28x cspec's pentry model assigns storage in declaration order, so
 * for {@code f(int a, int b, long c)} it picks {@code [AL, AH, XAR4]} —
 * whereas the TI EABI compiler emits {@code [AR4, AR5, AH:AL]} because
 * {@code long c} pre-reserves ACC and evicts the {@code int}s from AL/AH.
 * Ghidra has no in-cspec hook to inject a custom {@code PrototypeModel}
 * subclass, so this analyzer post-processes function signatures instead.
 *
 * <p>See {@link TMS320C28xAbiAllocator} for the allocation algorithm. This
 * class only handles when-to-run and how-to-install the corrected storage
 * via {@link Function#updateFunction} with
 * {@link Function.FunctionUpdateType#CUSTOM_STORAGE}. It is a no-op on
 * functions without user-supplied signatures (default-typed parameters
 * would just get spilled to stack, which is worse than the cspec's guess).
 */
public class TMS320C28xAbiAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x ABI (SPRU) Storage";
	private static final String DESCRIPTION =
		"Re-lays out parameter storage per SPRU514 §7.3.1 class-priority rules " +
		"(fixes cross-class reservation cases like f(int,int,long) that the " +
		"cspec's declaration-order pentry model cannot express).";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String DEFAULT_CONVENTION = "__c28x";

	public TMS320C28xAbiAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_SIGNATURES_ANALYZER);
		// Run after the function analyzer so signature information from other
		// sources (DWARF importer, user edits, function-signature-changed events)
		// is already in place before we recompute storage.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) {
			return false;
		}
		// Only touch programs where the default convention is our SPRU-oriented one.
		// If a project has switched to a different prototype, honor that choice.
		CompilerSpec cs = program.getCompilerSpec();
		if (cs == null || cs.getDefaultCallingConvention() == null) {
			return false;
		}
		return DEFAULT_CONVENTION.equals(cs.getDefaultCallingConvention().getName());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		Iterator<Function> functions = fm.getFunctions(set, true);
		int updated = 0;
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function fn = functions.next();
			if (fn.isThunk() || fn.isExternal()) {
				continue;
			}
			if (!isEligibleConvention(fn)) {
				continue;
			}
			try {
				if (applySpruStorage(program, fn)) {
					updated++;
				}
			}
			catch (Exception e) {
				log.appendMsg(NAME, "failed to re-lay " + fn.getName() + " @ " +
					fn.getEntryPoint() + ": " + e.getMessage());
			}
		}
		if (updated > 0) {
			Msg.info(this, "re-laid " + updated + " function signature(s) per SPRU §7.3.1");
		}
		return true;
	}

	private static boolean isEligibleConvention(Function fn) {
		String cc = fn.getCallingConventionName();
		if (cc == null || Function.DEFAULT_CALLING_CONVENTION_STRING.equals(cc) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(cc)) {
			// Default → our SPRU model applies (the cspec's default_proto is __c28x).
			return true;
		}
		return DEFAULT_CONVENTION.equals(cc);
	}

	/**
	 * @return true iff we changed any parameter's storage on {@code fn}
	 */
	private static boolean applySpruStorage(Program program, Function fn)
			throws InvalidInputException, DuplicateNameException {
		Parameter[] existing = fn.getParameters();
		if (existing.length == 0) {
			return false;
		}
		// Skip auto params (hidden struct-return ptr / this) — the cspec places
		// them and our allocator doesn't model them. We compute storage only for
		// the user-declared params in declaration order.
		List<Parameter> user = new ArrayList<>(existing.length);
		for (Parameter p : existing) {
			if (!p.isAutoParameter()) {
				user.add(p);
			}
		}
		if (user.isEmpty()) {
			return false;
		}

		// Bail if any user param has no meaningful declared type — running the
		// allocator on defaulted params would spill everything to stack.
		DataType[] paramTypes = new DataType[user.size()];
		for (int i = 0; i < user.size(); i++) {
			DataType dt = user.get(i).getDataType();
			if (dt == null) {
				return false;
			}
			paramTypes[i] = dt;
		}

		VariableStorage[] want = TMS320C28xAbiAllocator.computeParamStorage(program, paramTypes);
		if (matchesExisting(user, want)) {
			return false;
		}

		List<Variable> newParams = new ArrayList<>(user.size());
		for (int i = 0; i < user.size(); i++) {
			Parameter src = user.get(i);
			newParams.add(new ParameterImpl(src.getName(), paramTypes[i], want[i], program));
		}
		// CUSTOM_STORAGE tells Ghidra to honor our per-param VariableStorage and not
		// re-derive it from the cspec on the next signature change.
		fn.updateFunction(fn.getCallingConventionName(), fn.getReturn(), newParams,
			Function.FunctionUpdateType.CUSTOM_STORAGE, /*force*/ false, SourceType.ANALYSIS);
		return true;
	}

	private static boolean matchesExisting(List<Parameter> existing, VariableStorage[] want) {
		if (existing.size() != want.length) {
			return false;
		}
		for (int i = 0; i < want.length; i++) {
			if (!Objects.equals(existing.get(i).getVariableStorage(), want[i])) {
				return false;
			}
		}
		return true;
	}
}
