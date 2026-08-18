// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Attaches memory references to {@code @6bit} operands in post-call
 * fall-throughs whose callee is provably DP-preserving.
 *
 * <p>Scope, plainly. Ghidra's stock constant-propagation resolves the
 * dominant majority of {@code @6bit} operands directly from the live DP
 * register (measured on a large F28377D image: 96% recall from stock CP
 * alone). This analyzer's marginal value is exclusively the post-call
 * fall-through range: TI's C ABI does not preserve DP across calls, so the
 * SLA invalidates {@code ctx_DP_valid} at {@code inst_next} for every call.
 * When we can prove the callee never touches DP, the caller's DP is still
 * live in the fall-through — and we attach the references the SLA's
 * conservative invalidation would otherwise cost. Measured recall from this
 * analyzer alone: ~2.5% (~324 sites out of ~12k on a large image).
 *
 * <p>Two phases:
 * <ol>
 *   <li><b>Fixed-point over the callgraph.</b> A function is DP-preserving
 *       iff (a) no instruction in its body writes DP (any of {@code MOVW DP},
 *       {@code MOVZ DP}, {@code POP DP} — detected as any instruction whose
 *       {@code getResultObjects()} contains the DP register), and (b) every
 *       call it makes targets a resolved, non-external, DP-preserving
 *       function. Indirect calls, external / thunk calls, and calls to
 *       functions with no entry-point body all disqualify the caller. The
 *       predicate is computed by seeding the "not preserving" set with every
 *       function containing a DP writer or a non-direct call, then
 *       propagating not-preserving through reverse callers until stable.</li>
 *   <li><b>Walk-and-attach from a deduplicated seed queue.</b> Seeded from
 *       every direct call whose target is DP-preserving and whose caller
 *       carries {@code ctx_DP_valid=1} at the call address ({@code start =
 *       inst_next}, {@code dpAtCall} = caller's DP). Each walk goes forward
 *       via fall-through — stopping at the first (i) non-fall-through flow
 *       (jump / terminal), (ii) DP writer, (iii) nested call whose callee
 *       is not provably DP-preserving, or (iv) join point where the
 *       incoming flows do not all agree on the DP value — and attaches a
 *       memory reference on every {@code @6bit} operand in that range
 *       using {@code target = (dpAtCall<<6) | off6}.
 *
 *       <p>Two ways a walk contributes reachability past a DP-preserving
 *       nested call: (a) it continues past — {@code dpAtCall} is provably
 *       still live across such a callee, so extending the walk is sound;
 *       and (b) it also queues a fresh seed at that call's fall-through
 *       with the same {@code dpAtCall}. The fresh seed's walk starts with
 *       an empty {@code visited} set and clean join state, so joins that
 *       block the extended walk from the outer call may not block the
 *       fresh walk. This recovers sites where the extended walk gets
 *       blocked -- what the old multi-round context-store design was
 *       computing across rounds via seeded context. Dedup on
 *       {@code (start, dpAtCall)} keeps termination: the same seed yields
 *       the same walk, so it is processed at most once.
 *
 *       <p>The pass is idempotent: a matching reference already present
 *       is skipped, so re-running is a no-op.</li>
 * </ol>
 *
 * <p>Why direct reference attachment, not context re-seeding:
 * {@code ProgramContext.setValue} throws {@link ContextChangeException} over
 * a range that already holds defined instructions (measured on a real image:
 * ~4k exceptions per invocation, no sites re-seeded). Ghidra's context-write
 * guard is what {@code clearCodeUnits(..., false)} used to sidestep, but
 * clearing + re-disassembling was only there to make the *old* two-constructor
 * SLA re-pick the resolved variant. With the collapsed single-constructor SLA
 * (see {@code tms320c28x_addr.sinc}, this branch), the p-code prototype is
 * context-neutral and there's nothing for a re-disassembly to change — so we
 * skip the context store entirely and add the reference in the walk loop
 * using the {@code dpAtCall} we already have in hand.
 *
 * <p>Discriminator for {@code @6bit} operands: the collapsed loc16/loc32
 * constructor's semantic body uses DP register plus the {@code loc_off6}
 * field, but Ghidra's operand-object list carries only the printed operand
 * ({@code @0xNN} — a single {@link Scalar} in {@code [0..63]}); DP lives in
 * the constructor's semantics, not the operand display. So the operand-level
 * discriminator is "single Scalar in [0,63] whose SLA-declared ref type is a
 * memory read/write". Every other loc16/loc32 mode is a register-direct or
 * indirect form and either has no scalar or a register in its operand
 * objects, so this uniquely matches {@code @6bit} within the addressing
 * sub-table. Immediates ({@code #22bit} in {@code MOVL XARn,#22bit},
 * {@code LC #22bit}, etc.) also have a lone scalar but their ref type is
 * not memory read/write, so the type filter excludes them.
 *
 * <p>Runs after {@code TMS320C28xFfcReturnAnalyzer} and after auto-analysis
 * has established the call graph. No listing mutation beyond adding
 * references; comments, labels, and existing user overrides are untouched.
 */
public class TMS320C28xDpPropagationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x DP Context Propagation";
	private static final String DESCRIPTION =
		"Attaches memory references to @6bit operands in the post-call fall-through " +
		"of every direct call whose callee provably doesn't write DP, recovering the " +
		"~2.5% of operands the SLA's conservative post-call ctx_DP invalidation costs " +
		"stock constant-propagation.";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String CTX_DP_NAME = "ctx_DP";
	private static final String CTX_DP_VALID_NAME = "ctx_DP_valid";
	private static final String DP_REGISTER_NAME = "DP";
	// Hard cap on the forward walk to bound work in the presence of unstructured
	// flow. Real fall-through blocks between calls in TI-compiler output are
	// short (dozens of insns); 256 is a safety net, not a design target.
	private static final int MAX_WALK_INSTRUCTIONS = 256;

	// Per-program cache of the DP-preserving predicate. `added()` fires each time
	// some other analyzer adds instructions, and this analyzer no longer drives
	// re-disassembly of its own (references-only design), so the round count is
	// bounded by upstream churn -- typically 1-3 rounds after auto-analysis
	// settles. Cache still worthwhile: the callgraph fixed point is O(functions
	// + call-edges) and small in absolute terms but pointless to recompute if
	// nothing changed.
	//
	// Stamp is a compound (functionCount, instructionCount). functionCount alone
	// would miss a body change at constant count -- e.g. a later analyzer
	// extending a function's fall-through into an instruction that turns out to
	// be a DP writer, silently flipping the callee from "preserving" to "not".
	// The theoretical failure mode is optimistic staleness (a callee marked
	// preserving when it isn't), which would attach a wrong-address reference
	// in a fall-through the callee actually clobbered DP for -- a precision
	// bug. The compound stamp closes the hole: any instruction added or removed
	// anywhere in the program forces a recompute.
	private static final Map<Program, CachedPreserving> CACHE =
		Collections.synchronizedMap(new WeakHashMap<>());

	private static final class CachedPreserving {
		final Set<Function> preserving;
		final int functionCountStamp;
		final long instructionCountStamp;

		CachedPreserving(Set<Function> preserving, int functionCountStamp,
				long instructionCountStamp) {
			this.preserving = preserving;
			this.functionCountStamp = functionCountStamp;
			this.instructionCountStamp = instructionCountStamp;
		}

		boolean matches(int currentFunctionCount, long currentInstructionCount) {
			return functionCountStamp == currentFunctionCount &&
				instructionCountStamp == currentInstructionCount;
		}
	}

	public TMS320C28xDpPropagationAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// FUNCTION_ANALYSIS.after() puts us after functions have been created and
		// their bodies established — we need Function.getBody() to reason about
		// per-function DP writes. The FFC return analyzer runs at DISASSEMBLY.after()
		// and its re-disassembly finishes before we start, so we see a stable graph.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) {
			return false;
		}
		// Guard against being loaded on a language build that predates the DP
		// context work — canAnalyze runs before added() so this is the right
		// place to no-op cleanly instead of crashing at first getRegister call.
		ProgramContext context = program.getProgramContext();
		return context.getRegister(CTX_DP_NAME) != null &&
			context.getRegister(CTX_DP_VALID_NAME) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ProgramContext context = program.getProgramContext();
		Register ctxDp = context.getRegister(CTX_DP_NAME);
		Register ctxDpValid = context.getRegister(CTX_DP_VALID_NAME);
		Register dpRegister = program.getLanguage().getRegister(DP_REGISTER_NAME);
		if (ctxDp == null || ctxDpValid == null || dpRegister == null) {
			log.appendMsg(NAME, "missing context or DP register — no-op");
			return false;
		}

		FunctionManager functionManager = program.getFunctionManager();
		Set<Function> dpPreserving = getOrComputeDpPreserving(program, dpRegister, monitor);
		Memory memory = program.getMemory();
		ReferenceManager refs = program.getReferenceManager();

		int outerSites = 0;
		int freshSites = 0;
		int addedReferences = 0;
		int truncatedWalks = 0;

		// A walk is seeded either from the fall-through of an outer direct call
		// (initial population) or from the fall-through of a DP-preserving nested
		// call the walk chose to cross (added dynamically -- see #51). The fresh
		// seeds get a clean `visited` set and a clean join state, so joins that
		// blocked the extended chained walk from the outer call may not block the
		// fresh walk. Dedup by (start, dpAtCall): the same (address, DP) seed
		// yields the same walk, so processing it twice is pure waste; different
		// dpAtCall values at the same address are two legitimately different
		// paths and both must be walked (each attaches its own resolved refs).
		Deque<Seed> seedQueue = new ArrayDeque<>();
		Set<Seed> enqueued = new HashSet<>();

		// Initial population: every direct call whose callee is DP-preserving and
		// whose caller's ctx_DP_valid at the call is 1. Working from calls (rather
		// than from functions) keeps this O(calls) and side-steps having to
		// enumerate returns from callees.
		Listing listing = program.getListing();
		Iterator<Instruction> instructions = listing.getInstructions(true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction call = instructions.next();
			FlowType flow = call.getFlowType();
			if (!flow.isCall() || flow.isComputed()) {
				continue;
			}
			Address[] flows = call.getFlows();
			if (flows.length != 1) {
				continue;
			}
			Function callee = functionManager.getFunctionAt(flows[0]);
			if (callee == null || !dpPreserving.contains(callee)) {
				continue;
			}

			BigInteger validAtCall = context.getValue(ctxDpValid, call.getMinAddress(), false);
			if (validAtCall == null || !BigInteger.ONE.equals(validAtCall)) {
				continue;
			}
			BigInteger dpAtCall = context.getValue(ctxDp, call.getMinAddress(), false);
			if (dpAtCall == null) {
				continue;
			}

			Address instNext = call.getFallThrough();
			if (instNext == null) {
				continue;
			}
			enqueueSeed(seedQueue, enqueued, new Seed(instNext, dpAtCall, false));
		}

		// Drain the queue. Each walk may spawn fresh seeds for the fall-throughs
		// of DP-preserving nested calls it crossed; dedup keeps termination.
		while (!seedQueue.isEmpty()) {
			monitor.checkCancelled();
			Seed seed = seedQueue.pop();
			WalkResult walk = walkFallThrough(program, seed.start, dpRegister,
				ctxDp, ctxDpValid, seed.dpAtCall, functionManager, dpPreserving,
				monitor);
			if (walk.instructionCount == 0) {
				continue;
			}
			if (seed.fresh) {
				freshSites++;
			}
			else {
				outerSites++;
			}
			if (walk.truncatedAtCap) {
				truncatedWalks++;
			}
			addedReferences += attachReferencesInRange(listing, refs, memory,
				walk.range, seed.dpAtCall, monitor);
			for (Address fresh : walk.freshSeedFallthroughs) {
				enqueueSeed(seedQueue, enqueued, new Seed(fresh, seed.dpAtCall, true));
			}
		}

		int totalSites = outerSites + freshSites;
		if (totalSites > 0 || addedReferences > 0) {
			Msg.info(this, "attached " + addedReferences +
				" memory reference(s) across " + totalSites +
				" walked fall-through(s) (" + outerSites + " outer post-call, " +
				freshSites + " fresh-seeded at crossed nested calls)");
		}
		if (truncatedWalks > 0) {
			// Non-zero truncations mean some qualifying fall-throughs were longer than
			// MAX_WALK_INSTRUCTIONS and the tail was skipped. Chaining past DP-preserving
			// calls extends walks materially past the pre-chaining design, so this cap
			// is more likely to bind here than it was in the context-store era. Raise the
			// cap or scope the walk if this fires in real work.
			Msg.warn(this, truncatedWalks + " walk(s) truncated at the " +
				MAX_WALK_INSTRUCTIONS + "-instruction cap; some post-call " +
				"@6bit operands may be unresolved");
		}
		return true;
	}

	private static void enqueueSeed(Deque<Seed> queue, Set<Seed> enqueued, Seed seed) {
		if (enqueued.add(seed)) {
			queue.add(seed);
		}
	}

	/**
	 * A walk-fall-through starting point. {@code start} is the address to walk
	 * forward from; {@code dpAtCall} is the DP value provably live at that
	 * address (either the caller's DP at the outer call, or -- for fresh seeds
	 * spawned by chaining -- the same DP carried across a DP-preserving nested
	 * call). Dedup is by both fields: the same address reached with a different
	 * DP is two legitimately different paths.
	 */
	private static final class Seed {
		final Address start;
		final BigInteger dpAtCall;
		/** True iff this seed was spawned by chaining past a nested call
		 *  (rather than being an outer per-direct-call seed). Bookkeeping only;
		 *  not part of identity for dedup -- an outer seed and a fresh seed at
		 *  the same (start, dpAtCall) do the same walk and only one should run. */
		final boolean fresh;

		Seed(Address start, BigInteger dpAtCall, boolean fresh) {
			this.start = start;
			this.dpAtCall = dpAtCall;
			this.fresh = fresh;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (!(o instanceof Seed other)) return false;
			return start.equals(other.start) && dpAtCall.equals(other.dpAtCall);
		}

		@Override
		public int hashCode() {
			return start.hashCode() * 31 + dpAtCall.hashCode();
		}
	}

	// --- reference attachment (per-walked-range) ---------------------------------

	private static int attachReferencesInRange(Listing listing, ReferenceManager refs,
			Memory memory, AddressSetView range, BigInteger dpAtCall,
			TaskMonitor monitor) throws CancelledException {
		int added = 0;
		Iterator<Instruction> insns = listing.getInstructions(range, true);
		while (insns.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = insns.next();
			int operandCount = insn.getNumOperands();
			for (int i = 0; i < operandCount; i++) {
				Long off6 = extractDpOff6(insn, i);
				if (off6 == null) {
					continue;
				}
				// SLA-declared ref type filters out immediates (e.g. #22bit in
				// MOVL XARn,#22bit) that happen to render as a lone Scalar but
				// aren't memory accesses. Also picks the correct RefType
				// (READ/WRITE/READ_WRITE) from the instruction's p-code.
				RefType refType = insn.getOperandRefType(i);
				if (refType == null || (!refType.isRead() && !refType.isWrite())) {
					continue;
				}
				long word = (dpAtCall.longValue() << 6) | off6.longValue();
				Address target;
				try {
					target = wordAddress(insn.getMinAddress(), word);
				}
				catch (ArithmeticException | IllegalArgumentException e) {
					continue;
				}
				// Only attach if the resolved address falls in a real memory block.
				// A stray reference to an unmapped page is worse noise than the
				// unresolved raw offset it would replace.
				if (!memory.contains(target)) {
					continue;
				}
				if (hasEquivalentReference(refs, insn.getMinAddress(), i, target)) {
					continue;
				}
				refs.addMemoryReference(insn.getMinAddress(), target, refType,
					SourceType.ANALYSIS, i);
				added++;
			}
		}
		return added;
	}

	/**
	 * Identifies a {@code @6bit} operand and returns its {@code loc_off6} value
	 * (0..63), or {@code null} if the operand isn't a DP-direct access.
	 *
	 * <p>The collapsed loc16/loc32 {@code @6bit} constructor renders as
	 * {@code @0xNN} — a single {@link Scalar}. DP lives in the constructor's
	 * semantic body, not in the operand's object list. But so does SP in the
	 * stack-relative form {@code *-SP[off6]}, which reuses the same
	 * {@code loc_off6} field and also produces a lone-Scalar operand with a
	 * memory read/write ref type. To distinguish them we require the operand
	 * text to start with {@code @}: every other {@code @}-prefixed loc16/loc32
	 * form is register-direct ({@code @AL}, {@code @AR0}, {@code @SP}, ...) and
	 * those are already excluded by the lone-Scalar test, so leading-{@code @}
	 * uniquely picks {@code @6bit}.
	 *
	 * <p>The caller pairs this with an {@link Instruction#getOperandRefType}
	 * check to filter non-memory scalar operands (e.g. {@code #22bit}
	 * immediates).
	 */
	private static Long extractDpOff6(Instruction insn, int operand) {
		Object[] opObjects = insn.getOpObjects(operand);
		if (opObjects.length != 1 || !(opObjects[0] instanceof Scalar scalar)) {
			return null;
		}
		long value = scalar.getUnsignedValue();
		if (value < 0 || value >= 64) {
			return null;
		}
		// Distinguish @6bit from *-SP[6bit] -- both are lone Scalar[0..63] with a
		// memory ref type. See javadoc.
		String representation = insn.getDefaultOperandRepresentation(operand);
		if (representation == null || !representation.startsWith("@")) {
			return null;
		}
		return value;
	}

	private static boolean hasEquivalentReference(ReferenceManager refs, Address from,
			int operand, Address target) {
		for (Reference reference : refs.getReferencesFrom(from)) {
			if (reference.getOperandIndex() == operand &&
				reference.isMemoryReference() &&
				target.equals(reference.getToAddress())) {
				return true;
			}
		}
		return false;
	}

	/** Convert an architectural C28 word address to Ghidra's byte-offset Address. */
	private static Address wordAddress(Address basis, long wordOffset) {
		int wordSize = basis.getAddressSpace().getAddressableUnitSize();
		return basis.getAddressSpace().getAddress(Math.multiplyExact(wordOffset, wordSize));
	}

	// --- phase 1: DP-preserving predicate over the callgraph ---------------------

	private static Set<Function> getOrComputeDpPreserving(Program program,
			Register dpRegister, TaskMonitor monitor) throws CancelledException {
		int functionCount = program.getFunctionManager().getFunctionCount();
		long instructionCount = program.getListing().getNumInstructions();
		CachedPreserving cached = CACHE.get(program);
		if (cached != null && cached.matches(functionCount, instructionCount)) {
			return cached.preserving;
		}
		Set<Function> preserving = computeDpPreservingFunctions(program, dpRegister, monitor);
		CACHE.put(program, new CachedPreserving(preserving, functionCount, instructionCount));
		String prior = cached == null
			? "absent"
			: "functions=" + cached.functionCountStamp + " instructions=" +
				cached.instructionCountStamp;
		Msg.info(TMS320C28xDpPropagationAnalyzer.class,
			"DP-preserving functions: " + preserving.size() + " / " + functionCount +
			" (recomputed; cache stamp was " + prior + ")");
		return preserving;
	}

	private static Set<Function> computeDpPreservingFunctions(Program program,
			Register dpRegister, TaskMonitor monitor) throws CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		// Seed "unsafe" (= not DP-preserving) with any function that writes DP
		// directly or contains a call we can't reason about (indirect/external).
		// Also build the reverse-call map for propagation.
		Set<Function> unsafe = new HashSet<>();
		Map<Function, Set<Function>> callers = new HashMap<>();
		Iterator<Function> functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function fn = functions.next();
			if (fn.isExternal()) {
				unsafe.add(fn);
				continue;
			}
			if (fn.isThunk()) {
				// A thunk to an unresolved external is unsafe; a thunk to a resolved
				// function will be tied to that target's safety by the propagation below.
				Function thunked = fn.getThunkedFunction(true);
				if (thunked == null || thunked.isExternal()) {
					unsafe.add(fn);
					continue;
				}
				// Treat the thunk as calling its target so a change in the target's
				// state flows back to the thunk.
				callers.computeIfAbsent(thunked, k -> new HashSet<>()).add(fn);
				continue;
			}

			boolean fnUnsafe = false;
			AddressSetView body = fn.getBody();
			if (body != null && !body.isEmpty()) {
				Iterator<Instruction> insns = program.getListing().getInstructions(body, true);
				while (insns.hasNext()) {
					monitor.checkCancelled();
					Instruction insn = insns.next();
					if (writesRegister(insn, dpRegister)) {
						fnUnsafe = true;
						break;
					}
					FlowType flow = insn.getFlowType();
					if (!flow.isCall()) {
						continue;
					}
					if (flow.isComputed()) {
						// Indirect call — target unknown, must assume it writes DP.
						fnUnsafe = true;
						break;
					}
					Address[] flows = insn.getFlows();
					if (flows.length != 1) {
						fnUnsafe = true;
						break;
					}
					Function target = functionManager.getFunctionAt(flows[0]);
					if (target == null) {
						// Direct call to an address with no function object — the callee
						// body is unknown to us, so we can't prove it doesn't write DP.
						fnUnsafe = true;
						break;
					}
					// Record the caller edge so propagation can revisit `fn` if the
					// target later turns out to be unsafe.
					callers.computeIfAbsent(target, k -> new HashSet<>()).add(fn);
				}
			}
			else {
				// No body means we can't inspect anything — treat as unsafe rather
				// than optimistically preserving.
				fnUnsafe = true;
			}

			if (fnUnsafe) {
				unsafe.add(fn);
			}
		}

		// Workset propagation: any function that calls an unsafe target becomes
		// unsafe, in turn. Converges quickly because each function is added to
		// `unsafe` at most once.
		Deque<Function> worklist = new ArrayDeque<>(unsafe);
		while (!worklist.isEmpty()) {
			monitor.checkCancelled();
			Function unsafeFn = worklist.pop();
			Set<Function> reverseCallers = callers.get(unsafeFn);
			if (reverseCallers == null) {
				continue;
			}
			for (Function caller : reverseCallers) {
				if (unsafe.add(caller)) {
					worklist.push(caller);
				}
			}
		}

		Set<Function> preserving = new HashSet<>();
		Iterator<Function> allFunctions = functionManager.getFunctions(true);
		while (allFunctions.hasNext()) {
			monitor.checkCancelled();
			Function fn = allFunctions.next();
			if (!unsafe.contains(fn)) {
				preserving.add(fn);
			}
		}
		return preserving;
	}

	// --- phase 2: forward walk to compute the propagation range ------------------

	private static final class WalkResult {
		final AddressSet range;
		final int instructionCount;
		final boolean truncatedAtCap;
		/** Fall-through addresses of DP-preserving nested calls the walk chose
		 *  to cross. The caller enqueues each as a fresh Seed with the same
		 *  dpAtCall (issue #51): a long extended chained walk accumulates more
		 *  join-blocking opportunities than several short walks would, so
		 *  re-entering from each crossed call's fall-through with a clean
		 *  visited/join state recovers sites the extended walk lost. */
		final List<Address> freshSeedFallthroughs;

		WalkResult(AddressSet range, int instructionCount, boolean truncatedAtCap,
				List<Address> freshSeedFallthroughs) {
			this.range = range;
			this.instructionCount = instructionCount;
			this.truncatedAtCap = truncatedAtCap;
			this.freshSeedFallthroughs = freshSeedFallthroughs;
		}
	}

	private static WalkResult walkFallThrough(Program program, Address start,
			Register dpRegister, Register ctxDp, Register ctxDpValid,
			BigInteger dpAtCall, FunctionManager functionManager,
			Set<Function> dpPreserving, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		AddressSet range = new AddressSet();
		Set<Address> visited = new HashSet<>();
		List<Address> freshSeedFallthroughs = new ArrayList<>();
		Instruction current = listing.getInstructionAt(start);
		int count = 0;
		while (current != null && count < MAX_WALK_INSTRUCTIONS) {
			monitor.checkCancelled();
			Address addr = current.getMinAddress();
			if (!visited.add(addr)) {
				break;
			}
			// At a join point (address reached from outside our walk), require every
			// external predecessor to flow the same (valid=1, ctx_DP=dpAtCall) into
			// this address. If they all agree, crossing is sound (loop-head joins in
			// tight compiler code often satisfy this: the body reloads DP to the same
			// page the caller had, and the back-edge source carries the matching
			// context). If any disagrees or is unresolvable, stop -- the SLA's
			// last-write-wins storage at the join means we can't rely on the raw
			// context value at joinAddr; each predecessor's outgoing edge context
			// must be computed independently.
			if (count > 0 && !allExternalPredecessorsAgree(program, addr, visited,
					dpRegister, ctxDp, ctxDpValid, dpAtCall)) {
				break;
			}
			range.add(addr, current.getMaxAddress());
			count++;

			// Stop conditions past this instruction: we don't want to attach a
			// reference on a subsequent instruction whose DP is provably different.
			if (writesRegister(current, dpRegister)) {
				// This instruction writes DP; downstream operands are governed by
				// its new value (or the SLA's own snapshot when it's MOVW/MOVZ DP).
				// Include this insn in the range so a @6bit source operand of it
				// -- if any -- is still resolvable against dpAtCall, but stop.
				break;
			}
			FlowType flow = current.getFlowType();
			// Continue past a call only when its callee is a resolved direct target
			// AND provably DP-preserving. This is the chaining fix: without it, the
			// walk stops at the first nested call and every @6bit operand beyond it
			// stays unresolved until (never, in the reference-only design) the outer
			// per-call loop reaches that nested call in a separate iteration -- but
			// the outer loop needs the nested call's own validAtCall=1, which the
			// SLA invalidates. Recovering those was what the old multi-round
			// context-write design did the expensive way. Doing it here in one pass
			// captures the same reachability directly. Indirect / external / unknown
			// callees still stop the walk -- the callee body isn't provable so we
			// can't carry dpAtCall past them.
			if (flow.isCall()) {
				if (!continuesPastCall(current, functionManager, dpPreserving)) {
					break;
				}
				// Also queue a fresh-walk seed at this call's fall-through
				// (issue #51). The extended walk keeps going here, but a fresh
				// walk from the same address may cross joins the extended walk
				// gets blocked by -- see WalkResult.freshSeedFallthroughs.
				Address callFall = current.getFallThrough();
				if (callFall != null) {
					freshSeedFallthroughs.add(callFall);
				}
			}
			else if (flow.isTerminal()) {
				break;
			}
			Address fall = current.getFallThrough();
			if (fall == null) {
				// Unconditional branch / return / computed jump -- no linear
				// successor to attach references to.
				break;
			}
			current = listing.getInstructionAt(fall);
		}
		// Truncation at the cap is when we exited the loop because count reached
		// MAX_WALK_INSTRUCTIONS AND there was more to walk (current != null). Any
		// natural stop (flow break, DP writer, join disagreement, exhausted
		// fall-through) leaves either current==null or triggered a break before
		// the count check. Chaining past DP-preserving calls makes the walk
		// materially longer than the pre-chaining design, so surface this so a
		// silent recall miss at the cap is measurable rather than invisible.
		boolean truncated = count >= MAX_WALK_INSTRUCTIONS && current != null;
		return new WalkResult(range, count, truncated, freshSeedFallthroughs);
	}

	private static boolean continuesPastCall(Instruction call,
			FunctionManager functionManager, Set<Function> dpPreserving) {
		FlowType flow = call.getFlowType();
		if (flow.isComputed()) {
			return false;
		}
		Address[] flows = call.getFlows();
		if (flows.length != 1) {
			return false;
		}
		Function callee = functionManager.getFunctionAt(flows[0]);
		return callee != null && dpPreserving.contains(callee);
	}

	/**
	 * Returns true iff every incoming flow reference into {@code joinAddr} from
	 * outside the current walk flows the same ({@code ctx_DP_valid=1},
	 * {@code ctx_DP=dpAtCall}) into this address. Returns true trivially when no
	 * external predecessor exists (not actually a join).
	 *
	 * <p>Per-predecessor edge context is computed from the source instruction,
	 * because {@link ProgramContext#getValue} at the join address stores only the
	 * last write during disassembly and hides disagreement. The rule:
	 * <ul>
	 *   <li>Source is a call: outgoing context on the return edge is the SLA's
	 *       invalidation {@code (0, ?)}, so it never matches. Rejected.</li>
	 *   <li>Source writes DP (any {@code getResultObjects()} contains DP): for
	 *       {@code MOVW/MOVZ DP,#imm} the outgoing value is the immediate
	 *       operand -- read via {@link Instruction#getScalar}. {@code POP DP}
	 *       has no immediate; treat as {@code (0, ?)} and reject.</li>
	 *   <li>Otherwise: outgoing context equals incoming context (no globalset on
	 *       plain instructions or on branches), which is what's stored at the
	 *       source's own address.</li>
	 * </ul>
	 * References from data addresses or non-instruction sources are rejected.
	 */
	private static boolean allExternalPredecessorsAgree(Program program, Address joinAddr,
			Set<Address> insideWalk, Register dpRegister, Register ctxDp,
			Register ctxDpValid, BigInteger dpAtCall) {
		ProgramContext context = program.getProgramContext();
		Listing listing = program.getListing();
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(joinAddr);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (!ref.getReferenceType().isFlow()) {
				continue;
			}
			Address src = ref.getFromAddress();
			if (insideWalk.contains(src)) {
				continue;
			}
			Instruction pred = listing.getInstructionAt(src);
			if (pred == null) {
				return false;
			}
			if (pred.getFlowType().isCall()) {
				// Return edge from a call: SLA invalidates ctx_DP_valid at inst_next.
				return false;
			}

			BigInteger outgoingValid;
			BigInteger outgoingDp;
			if (writesRegister(pred, dpRegister)) {
				// MOVW DP,#imm16 and MOVZ DP,#10bit render "DP" as a print literal,
				// so the immediate sits at operand 0 (not 1 -- there is no operand
				// 1). POP DP has no operand at all; getScalar returns null and we
				// reject. The audit measured 0 POP DP predecessors of join points
				// across ~18k program-wide flow refs, so the POP DP rejection has
				// no measurable recall cost; recovering the popped value would
				// require stack-effect matching (see git history for design).
				Scalar imm = pred.getScalar(0);
				if (imm == null) {
					return false;
				}
				outgoingValid = BigInteger.ONE;
				outgoingDp = BigInteger.valueOf(imm.getUnsignedValue());
			}
			else {
				outgoingValid = context.getValue(ctxDpValid, src, false);
				outgoingDp = context.getValue(ctxDp, src, false);
			}
			if (outgoingValid == null || !BigInteger.ONE.equals(outgoingValid)) {
				return false;
			}
			if (outgoingDp == null || !outgoingDp.equals(dpAtCall)) {
				return false;
			}
		}
		return true;
	}

	// --- helpers -----------------------------------------------------------------

	private static boolean writesRegister(Instruction instruction, Register expected) {
		for (Object object : instruction.getResultObjects()) {
			if (object instanceof Register result &&
				(expected.contains(result) || result.contains(expected))) {
				return true;
			}
		}
		return false;
	}
}
