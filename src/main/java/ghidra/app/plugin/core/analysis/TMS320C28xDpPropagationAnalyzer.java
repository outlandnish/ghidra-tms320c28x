// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
 * Re-propagates the caller's {@code ctx_DP} snapshot into the fall-through of
 * every direct call whose target is provably DP-preserving, then attaches a
 * memory reference to every {@code @6bit} operand whose {@code ctx_DP} is known.
 *
 * <p>Background — the SLEIGH spec snapshots {@code MOVW DP,#imm} /
 * {@code MOVZ DP,#imm} into a {@code ctx_DP} context register and flows it
 * forward. Every {@code @6bit} loc16/loc32 access resolves at runtime to
 * {@code (DP<<6)|off6}; when {@code ctx_DP_valid=1} the analyzer knows the
 * DP value at that instruction and can attach a memory reference to the full
 * absolute address so Ghidra draws the XREF, renders the resolved symbol in
 * the operand, and the decompiler promotes the load to a global-variable
 * access.
 *
 * <p>Because TI's C ABI doesn't preserve DP across calls, every call
 * constructor invalidates {@code ctx_DP_valid} at {@code inst_next}. That's
 * the correct default: without knowing the callee, the caller's DP might be
 * stale by the time we return. On a real F28377D image the invalidation cost
 * 14 of ~364 resolvable {@code @6bit} operands (~3.8%), all sitting in a
 * fall-through of a call whose callee happens never to write DP.
 *
 * <p>Three phases:
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
 *   <li><b>Re-seed at qualifying return sites.</b> For every direct call
 *       whose target is DP-preserving and whose caller's {@code ctx_DP_valid}
 *       is 1 at the call address, walk forward from {@code inst_next} via
 *       fall-through — stopping at the first (i) call, (ii) non-fall-through
 *       flow (jump / terminal), (iii) DP writer, or (iv) join point (an
 *       instruction with an incoming flow reference from outside the walked
 *       range) — and set {@code ctx_DP_valid=1} plus the caller's
 *       {@code ctx_DP} value across the range in the persistent program
 *       context. No re-disassembly is required: the {@code @6bit} constructor
 *       emits the same runtime-expression p-code regardless of context; the
 *       reference pass below reads context via
 *       {@link ProgramContext#getValue}, which sees the updated values.</li>
 *   <li><b>Attach memory references at {@code @6bit} sites.</b> Sweep every
 *       instruction; for each {@code @6bit} operand ({@code opObjects = {DP,
 *       Scalar[0..63]}}) where {@code ctx_DP_valid=1} at the instruction,
 *       resolve to {@code word = (ctx_DP<<6) | off6}, convert to Ghidra's
 *       byte-offset address, and attach a memory reference on that operand
 *       (skipping if a matching reference already exists — the pass is
 *       idempotent). Reference type is taken from the operand's SLA-declared
 *       {@link Instruction#getOperandRefType} so read/write/read-write is
 *       preserved.</li>
 * </ol>
 *
 * <p>Runs after {@code TMS320C28xFfcReturnAnalyzer} and after auto-analysis
 * has established the call graph. Phase 2 preserves comments/labels
 * (context-only mutation, no code-unit clear). Phase 3 is idempotent and
 * safe to re-run after a manual disassembly change.
 */
public class TMS320C28xDpPropagationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C28x DP Context Propagation";
	private static final String DESCRIPTION =
		"Re-seeds the caller's ctx_DP snapshot at the return of every call whose " +
		"callee provably doesn't write DP, recovering @6bit operand resolution " +
		"that the SLA's conservative post-call invalidation loses.";
	private static final String PROCESSOR_NAME = "TMS320C28x";
	private static final String CTX_DP_NAME = "ctx_DP";
	private static final String CTX_DP_VALID_NAME = "ctx_DP_valid";
	private static final String DP_REGISTER_NAME = "DP";
	// Hard cap on the forward walk to bound work in the presence of unstructured
	// flow. Real fall-through blocks between calls in TI-compiler output are
	// short (dozens of insns); 256 is a safety net, not a design target.
	private static final int MAX_WALK_INSTRUCTIONS = 256;

	// Per-program cache of the DP-preserving predicate. `added()` fires once per
	// re-disassembly round, and our own re-seed loop can drive up to ~10 rounds on
	// a typical F28377D image (chained calls to DP-preserving callees each need one
	// round to bubble up). Measured effect on runtime is modest -- ~350 ms of a
	// ~3 s total on a 12k-instruction image -- because the bottleneck is actually
	// the phase-2 program-wide instruction sweep, not the callgraph fixed point;
	// scoping that sweep to the AddressSetView `added()` receives is a separate
	// follow-up.  Still worth keeping the cache: the fixed point is measurably
	// slow enough to matter, and avoiding pointless recomputation is cheap.
	//
	// Stamp is a compound (functionCount, instructionCount). functionCount
	// alone would miss a body change at constant count -- e.g. our own
	// re-disassembly extending a function's fall-through into an instruction
	// that turns out to be a DP writer, silently flipping the callee from
	// "preserving" to "not". The theoretical failure mode is optimistic
	// staleness (a callee marked preserving when it isn't), which would
	// re-seed the caller's DP into a fall-through where the callee actually
	// clobbered DP -- a wrong-XREF class bug.  The compound stamp closes the
	// hole: any instruction added or removed anywhere in the program forces
	// a recompute. In our loop, clear-then-re-disassemble preserves count
	// (N cleared, N added back) so the cache still holds across rounds.
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

		int propagatedSites = 0;
		int propagatedInstructions = 0;

		// Iterate every direct call in the program; for each whose callee is DP-
		// preserving and whose caller's ctx_DP_valid at the call is 1, re-seed the
		// fall-through range. Working from calls (rather than from functions) keeps
		// this O(calls) and side-steps having to enumerate returns from callees.
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

			WalkResult walk = walkFallThrough(program, instNext, dpRegister,
				ctxDp, ctxDpValid, dpAtCall, monitor);
			if (walk.instructionCount == 0) {
				continue;
			}
			// Skip if the fall-through already carries valid=1 and matching DP —
			// no work to do. The @6bit constructor no longer depends on this
			// context for its p-code prototype, so unlike the earlier design we
			// never need to clear + re-disassemble; ProgramContext.setValue is
			// enough for the phase-3 reference pass to see the updated values.
			BigInteger validAtNext = context.getValue(ctxDpValid, instNext, false);
			if (validAtNext != null && BigInteger.ONE.equals(validAtNext)) {
				BigInteger dpAtNext = context.getValue(ctxDp, instNext, false);
				if (dpAtCall.equals(dpAtNext)) {
					continue;
				}
			}

			try {
				context.setValue(ctxDpValid, walk.range.getMinAddress(),
					walk.range.getMaxAddress(), BigInteger.ONE);
				context.setValue(ctxDp, walk.range.getMinAddress(),
					walk.range.getMaxAddress(), dpAtCall);
				propagatedSites++;
				propagatedInstructions += walk.instructionCount;
			}
			catch (ContextChangeException e) {
				log.appendException(e);
			}
		}

		if (propagatedSites > 0) {
			Msg.info(this, "re-seeded ctx_DP across " + propagatedSites +
				" post-call site(s), " + propagatedInstructions + " instruction(s)");
		}

		// Phase 3: attach memory references at every @6bit operand whose ctx_DP
		// is known. Program-wide sweep -- not scoped to `set` -- because a
		// context re-seed in one region can newly resolve a @6bit operand in
		// another, and the pass is idempotent (skips operands with matching
		// references already present).
		int addedRefs = attachDpReferences(program, dpRegister, ctxDp, ctxDpValid, monitor);
		if (addedRefs > 0) {
			Msg.info(this, "attached " + addedRefs +
				" memory reference(s) at resolved @6bit operand(s)");
		}
		return true;
	}

	// --- phase 3: attach memory references at resolved @6bit operands ------------

	private static int attachDpReferences(Program program, Register dpRegister,
			Register ctxDp, Register ctxDpValid, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		ProgramContext context = program.getProgramContext();
		ReferenceManager refs = program.getReferenceManager();
		Memory memory = program.getMemory();
		int added = 0;
		Iterator<Instruction> insns = listing.getInstructions(true);
		while (insns.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = insns.next();
			int operandCount = insn.getNumOperands();
			for (int i = 0; i < operandCount; i++) {
				Long off6 = extractDpOff6(insn, i, dpRegister);
				if (off6 == null) {
					continue;
				}
				// Sanity guard: the {DP, Scalar[0..63]} operand-object pair is
				// unique to the @6bit constructor within loc16/loc32, but the
				// SLA might grow another mode later that shares the shape. The
				// operand's SLA-declared ref type ("this operand is a memory
				// read/write") is the second, decorrelated signal that keeps a
				// future addition from silently producing wrong references.
				RefType refType = insn.getOperandRefType(i);
				if (refType == null || (!refType.isRead() && !refType.isWrite())) {
					continue;
				}
				BigInteger valid = context.getValue(ctxDpValid, insn.getMinAddress(), false);
				if (valid == null || !BigInteger.ONE.equals(valid)) {
					continue;
				}
				BigInteger dp = context.getValue(ctxDp, insn.getMinAddress(), false);
				if (dp == null) {
					continue;
				}
				long word = (dp.longValue() << 6) | off6.longValue();
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
	 * (0..63), or {@code null} if the operand isn't a DP-relative direct access.
	 *
	 * <p>Discriminator: the collapsed loc16/loc32 {@code @6bit} constructor
	 * emits {@code (zext(DP) << 6) | zext(loc_off6:4)}, so its semantic
	 * operand-object list is exactly {@code {DP, Scalar}} with the scalar in
	 * the 6-bit range. No other loc16/loc32 mode in the SLA references DP
	 * (indirect modes go through {@code XARn}; stack modes through {@code SP};
	 * register-direct modes have no scalar), so this pair is a sufficient
	 * discriminator.
	 */
	private static Long extractDpOff6(Instruction insn, int operand, Register dpRegister) {
		Object[] opObjects = insn.getOpObjects(operand);
		if (opObjects.length != 2) {
			return null;
		}
		Register foundRegister = null;
		Scalar foundScalar = null;
		for (Object object : opObjects) {
			if (object instanceof Register register) {
				foundRegister = register;
			}
			else if (object instanceof Scalar scalar) {
				foundScalar = scalar;
			}
		}
		if (foundRegister == null || foundScalar == null) {
			return null;
		}
		if (!dpRegister.equals(foundRegister)) {
			return null;
		}
		long value = foundScalar.getUnsignedValue();
		if (value < 0 || value >= 64) {
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

		WalkResult(AddressSet range, int instructionCount) {
			this.range = range;
			this.instructionCount = instructionCount;
		}
	}

	private static WalkResult walkFallThrough(Program program, Address start,
			Register dpRegister, Register ctxDp, Register ctxDpValid,
			BigInteger dpAtCall, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		AddressSet range = new AddressSet();
		Set<Address> visited = new HashSet<>();
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

			// Stop conditions past this instruction: we don't want to include an
			// instruction that itself would break the propagation invariant.
			if (writesRegister(current, dpRegister)) {
				// This instruction writes DP, so ctx_DP downstream would change
				// anyway (via the SLA's own snapshot). Include this insn in the
				// range so it re-disassembles with our re-seeded context, but stop.
				break;
			}
			FlowType flow = current.getFlowType();
			// Continue past conditional jumps: the fall-through path preserves DP
			// (the branch instruction itself doesn't touch DP; the taken-branch
			// target lives at its own address and isn't in our re-seeded range,
			// so we don't affect the other path). Unconditional jumps and pure
			// terminals have no fall-through -- caught by `fall == null` below.
			// Calls always break: even if the callee is DP-preserving, the SLA's
			// own invalidation at inst_next kicks in and the outer analyzer loop
			// will pick up the fall-through in a subsequent iteration.
			if (flow.isCall() || flow.isTerminal()) {
				break;
			}
			Address fall = current.getFallThrough();
			if (fall == null) {
				// Unconditional branch / return / computed jump -- no linear
				// successor to seed into.
				break;
			}
			current = listing.getInstructionAt(fall);
		}
		return new WalkResult(range, count);
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
