// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Copyright the mwdmwd/ghidra-c28x contributors (https://github.com/mwdmwd/ghidra-c28x)
//
// Ported from mwdmwd/ghidra-c28x's TMS320C28CodePointerAnalyzer (Apache-2.0). Local
// changes: the processor-name string ("TMS320C28x" here vs "TMS320C28" theirs), the
// class rename, and the marker-property rename that follows it. The recovery logic is
// unchanged -- it reads P-code rather than operand text, so unlike the switch and FFC
// ports it needed no adaptation to this module's print forms. See THIRD-PARTY.md.
//
// One behavioural change, at isProvenFunctionEntry below: their only gate is that the
// store's destination is already typed as a pointer to a FunctionDefinition, which a raw
// firmware image can never satisfy. This port also accepts a store whose proved constant
// is exactly an existing function's entry point. MarkComponentRegistry additionally types
// the RAM dispatch slots it proves, so the original gate has something to match as well.
//
// It logs a funnel line at the end of every run ("N stores proved constant, N formed a
// code address, N passed target safety, N accepted"), because a recognizer that reports
// zero is otherwise indistinguishable from an image with nothing to find. On the image
// this was measured against the answer is a legitimate zero: the constants that reach
// 4-byte stores are scaling values that merely fit in 22 bits, and that image installs
// its handlers as .cinit data rather than by storing an immediate. See #61.
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates or reuses function entries only for exact constants stored into
 * destinations already typed as function pointers.
 * <p>
 * This analyzer deliberately does not classify address-looking immediates.  A
 * candidate must be a single full-width memory store to one exact primitive
 * datum whose type is a pointer to a {@link FunctionDefinition}.  The stored
 * value is proved by finite intraprocedural data flow: full-width register
 * copies of constants or other proved registers propagate, all predecessor
 * paths must agree, partial/overlapping writes and dynamic composition clobber
 * the proof, calls invalidate it, and unexpected interior ingress contributes
 * an unknown state.
 * <p>
 * The lower 22-bit C28x code address must be lossless, nonzero, non-default, initialized,
 * executable, decodable at an instruction boundary, and outside incompatible
 * data or the interior of another function.  Ordinary WRITE/DATA references
 * remain untouched and no CALL edge is fabricated.  Functions are discovered
 * monotonically: stale analyzer markers are revoked, but a function created on
 * an earlier valid proof is retained because deleting it safely after later
 * user or analysis edits cannot be established locally.
 */
public class TMS320C28xCodePointerAnalyzer extends AbstractAnalyzer {

    public static final String MARKER_PROPERTY = "TMS320C28x_CODE_POINTER_TARGET";

    private static final String NAME = "TMS320C28x Typed Code-Pointer Analyzer";
    private static final String DESCRIPTION =
        "Seeds executable targets from exact constants stored into typed function-pointer slots";
    private static final String PROCESSOR_NAME = "TMS320C28x";
    private static final long CODE_ADDRESS_MASK = 0x003f_ffffL;
    private static final int STORE_BYTES = 4;
    private static final int MAX_FUNCTION_INSTRUCTIONS = 65_536;

    public TMS320C28xCodePointerAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().equals(
            Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
    }

    @Override
    public void registerOptions(Options options, Program program) {
        // Deliberately finite; there are no address-range or heuristic options.
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        List<Register> tracked = trackedRegisters(program);
        if (tracked.isEmpty()) {
            log.appendMsg(NAME, "no full-width C28x registers available for constant proof");
            return false;
        }

        provedStores.set(0);
        provedCodeAddress.set(0);
        provedSafeTarget.set(0);
        Map<Address, Candidate> candidates = new LinkedHashMap<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            analyzeFunction(program, functions.next(), tracked, candidates, monitor, log);
        }

        Map<Address, String> desiredMarkers = new HashMap<>();
        Map<Address, List<Candidate>> byTarget = new LinkedHashMap<>();
        candidates.values().stream()
                .sorted(Comparator.comparing(c -> c.target))
                .forEach(c -> byTarget.computeIfAbsent(c.target, unused -> new ArrayList<>()).add(c));

        for (Map.Entry<Address, List<Candidate>> entry : byTarget.entrySet()) {
            monitor.checkCancelled();
            Address target = entry.getKey();
            if (!ensureFunction(program, target, monitor, log)) {
                continue;
            }
            long targetWord = byteOffsetToWord(program, target);
            String marker = "0x" + Long.toHexString(targetWord);
            for (Candidate candidate : entry.getValue()) {
                desiredMarkers.put(candidate.instruction.getMinAddress(), marker);
                Msg.info(this, "proved typed code-pointer store " +
                    candidate.instruction.getMinAddress() + " -> " + target +
                    " via " + candidate.destination);
            }
        }

        reconcileMarkers(program.getListing(), desiredMarkers, monitor);
        // A recognizer that reports nothing is indistinguishable from an image with
        // nothing in it, so say how far candidates actually got.
        Msg.info(this, String.format(
            "code-pointer funnel: %d stores proved constant, %d formed a code address, "
            + "%d passed target safety, %d accepted",
            provedStores.get(), provedCodeAddress.get(), provedSafeTarget.get(),
            candidates.size()));
        return true;
    }

    // Funnel counters. Static because the recovery walk is static; reset at the top of
    // added(), which is the only caller.
    private static final java.util.concurrent.atomic.AtomicInteger provedStores =
        new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.concurrent.atomic.AtomicInteger provedCodeAddress =
        new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.concurrent.atomic.AtomicInteger provedSafeTarget =
        new java.util.concurrent.atomic.AtomicInteger();

    private static void analyzeFunction(Program program, Function function,
            List<Register> tracked, Map<Address, Candidate> candidates,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (function == null || function.isExternal()) {
            return;
        }

        Listing listing = program.getListing();
        LinkedHashMap<Address, Node> nodes = new LinkedHashMap<>();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (nodes.size() >= MAX_FUNCTION_INSTRUCTIONS) {
                log.appendMsg(NAME, "skipping oversized function at " + function.getEntryPoint());
                return;
            }
            Instruction instruction = iterator.next();
            nodes.put(instruction.getMinAddress(), new Node(instruction));
        }
        if (nodes.isEmpty()) {
            return;
        }

        for (Node node : nodes.values()) {
            Instruction instruction = node.instruction;
            if (instruction.getFlowType().isCall()) {
                addSuccessor(nodes, node, instruction.getFallThrough());
            }
            else {
                for (Address flow : instruction.getFlows()) {
                    addSuccessor(nodes, node, flow);
                }
                addSuccessor(nodes, node, instruction.getFallThrough());
            }
        }

        Node entry = nodes.get(function.getEntryPoint());
        ReferenceManager references = program.getReferenceManager();
        for (Node node : nodes.values()) {
            monitor.checkCancelled();
            Set<Address> expected = new HashSet<>();
            for (Node predecessor : node.predecessors) {
                expected.add(predecessor.instruction.getMinAddress());
            }
            ReferenceIterator incoming = references.getReferencesTo(
                node.instruction.getMinAddress());
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (reference.getReferenceType().isFlow() &&
                    !expected.contains(reference.getFromAddress())) {
                    node.alternateIngress = true;
                }
            }
            if (node != entry && node.predecessors.isEmpty()) {
                node.alternateIngress = true;
            }
        }

        Deque<Node> work = new ArrayDeque<>(nodes.values());
        Set<Node> queued = new HashSet<>(nodes.values());
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Node node = work.removeFirst();
            queued.remove(node);

            ConstantState incoming = ConstantState.bottom();
            if (node == entry || node.alternateIngress) {
                incoming = merge(incoming, ConstantState.unknown());
            }
            for (Node predecessor : node.predecessors) {
                incoming = merge(incoming, predecessor.outputState);
            }
            ConstantState outgoing = transfer(node.instruction, incoming, tracked);
            if (incoming.equals(node.inputState) && outgoing.equals(node.outputState)) {
                continue;
            }
            node.inputState = incoming;
            node.outputState = outgoing;
            for (Node successor : node.successors) {
                if (queued.add(successor)) {
                    work.addLast(successor);
                }
            }
        }

        for (Node node : nodes.values()) {
            monitor.checkCancelled();
            if (!node.inputState.reachable) {
                continue;
            }
            StoreValue store = exactFullWidthStore(program, node.instruction,
                node.inputState, tracked);
            if (store == null) {
                continue;
            }
            provedStores.incrementAndGet();
            Address target = codeAddress(program, store.value);
            if (target == null) {
                continue;
            }
            provedCodeAddress.incrementAndGet();
            if (!isSafeTarget(program, target)) {
                MemoryBlock block = program.getMemory().getBlock(target);
                Msg.debug(TMS320C28xCodePointerAnalyzer.class, String.format(
                    "code-pointer reject %s -> %s: block=%s exec=%s data=%s fn=%s",
                    node.instruction.getMinAddress(), target,
                    block == null ? "none" : block.getName(),
                    block != null && block.isExecute(),
                    program.getListing().getDefinedDataContaining(target) != null,
                    program.getFunctionManager().getFunctionContaining(target) != null));
                continue;
            }
            provedSafeTarget.incrementAndGet();
            if (!isFunctionPointerDestination(program, store.destination) &&
                !isProvenFunctionEntry(program, target)) {
                continue;
            }
            candidates.put(node.instruction.getMinAddress(),
                new Candidate(node.instruction, store.destination, target));
        }
    }

    private static ConstantState transfer(Instruction instruction, ConstantState input,
            List<Register> tracked) {
        if (!input.reachable) {
            return input;
        }
        if (instruction.getFlowType().isCall()) {
            return ConstantState.unknown();
        }

        Map<Register, Long> values = new HashMap<>(input.values);
        Map<VarnodeKey, PcodeOp> definitions = new HashMap<>();
        for (PcodeOp op : instruction.getPcode()) {
            Varnode output = op.getOutput();
            if (output != null) {
                updateRegisterState(op, output, values, definitions, tracked);
                definitions.put(new VarnodeKey(output), op);
            }
        }
        return ConstantState.known(values);
    }

    private static StoreValue exactFullWidthStore(Program program, Instruction instruction,
            ConstantState input, List<Register> tracked) {
        if (!input.reachable || instruction.getFlowType().isCall()) {
            return null;
        }

        List<Reference> writes = new ArrayList<>();
        for (Reference reference : instruction.getReferencesFrom()) {
            if (reference.isMemoryReference() && reference.getReferenceType().isWrite()) {
                writes.add(reference);
            }
        }
        if (writes.size() != 1) {
            return null;
        }
        Reference write = writes.get(0);
        Address destination = write.getToAddress();
        int operand = write.getOperandIndex();
        if (destination == null || operand < 0 || operand >= instruction.getNumOperands() ||
            !destination.equals(instruction.getAddress(operand)) ||
            !destination.getAddressSpace().equals(
                program.getAddressFactory().getDefaultAddressSpace())) {
            return null;
        }

        Map<Register, Long> values = new HashMap<>(input.values);
        Map<VarnodeKey, PcodeOp> definitions = new HashMap<>();
        Long stored = null;
        int stores = 0;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.STORE) {
                stores++;
                if (op.getNumInputs() != 3 || op.getInput(2).getSize() != STORE_BYTES) {
                    return null;
                }
                stored = resolveExactValue(op.getInput(2), values, definitions,
                    tracked, new HashSet<>());
            }
            Varnode output = op.getOutput();
            if (output != null) {
                updateRegisterState(op, output, values, definitions, tracked);
                definitions.put(new VarnodeKey(output), op);
            }
        }
        if (stores != 1 || stored == null) {
            return null;
        }
        return new StoreValue(destination, stored.longValue() & 0xffff_ffffL);
    }

    private static void updateRegisterState(PcodeOp op, Varnode output,
            Map<Register, Long> values, Map<VarnodeKey, PcodeOp> definitions,
            List<Register> tracked) {
        if (!output.isRegister()) {
            return;
        }
        Register exact = exactTrackedRegister(output, tracked);
        for (Register register : tracked) {
            if (overlaps(output, register)) {
                values.remove(register);
            }
        }
        if (exact == null || op.getOpcode() != PcodeOp.COPY || op.getNumInputs() != 1) {
            return;
        }
        Long value = resolveExactValue(op.getInput(0), values, definitions,
            tracked, new HashSet<>());
        if (value != null) {
            values.put(exact, value.longValue() & 0xffff_ffffL);
        }
    }

    private static Long resolveExactValue(Varnode node, Map<Register, Long> values,
            Map<VarnodeKey, PcodeOp> definitions, List<Register> tracked,
            Set<VarnodeKey> visiting) {
        if (node == null || node.getSize() != STORE_BYTES) {
            return null;
        }
        if (node.isConstant()) {
            return Long.valueOf(node.getOffset() & 0xffff_ffffL);
        }
        if (node.isRegister()) {
            Register register = exactTrackedRegister(node, tracked);
            return register == null ? null : values.get(register);
        }
        if (!node.isUnique()) {
            return null;
        }
        VarnodeKey key = new VarnodeKey(node);
        if (!visiting.add(key)) {
            return null;
        }
        try {
            PcodeOp definition = definitions.get(key);
            if (definition == null || definition.getOpcode() != PcodeOp.COPY ||
                definition.getNumInputs() != 1) {
                return null;
            }
            return resolveExactValue(definition.getInput(0), values, definitions,
                tracked, visiting);
        }
        finally {
            visiting.remove(key);
        }
    }

    /**
     * The target-side alternative to a typed destination.
     *
     * <p>THE LOCAL ADAPTATION. mwdmwd gate candidates purely on the destination: the
     * slot must already be typed as a pointer to a FunctionDefinition. That is a sound
     * rule for a program someone has begun annotating, and it is unsatisfiable on a raw
     * firmware image, where nothing is typed at all -- measured on a production image
     * after this repo's pipeline, 344 defined data items, 0 of them function pointers,
     * so the analyzer recovered nothing whatsoever.
     *
     * <p>Rather than drop the precision, move the proof to the other end: accept the
     * store when the proved constant is EXACTLY the entry point of a function that
     * already exists. That is the same criterion MarkCodePointers.java relies on, and
     * for the same reason -- arbitrary data essentially never equals a function entry,
     * whereas "points somewhere into the code range" matches constantly. Combined with
     * the unchanged upstream requirements (a single full-width store of a value proved
     * constant on every path, landing on an initialized, executable, instruction-aligned
     * address outside any other function's interior) this stays a proof rather than a
     * heuristic.
     *
     * <p>A typed destination still qualifies on its own, so nothing mwdmwd recover is
     * lost; this only adds the cases their gate cannot reach.
     */
    private static boolean isProvenFunctionEntry(Program program, Address target) {
        Function function = program.getFunctionManager().getFunctionAt(target);
        return function != null && !function.isExternal() &&
            function.getEntryPoint().equals(target);
    }

    private static boolean isFunctionPointerDestination(Program program, Address destination) {
        Listing listing = program.getListing();
        Data root = listing.getDefinedDataContaining(destination);
        if (root == null) {
            return false;
        }
        long rawOffset = destination.subtract(root.getMinAddress());
        if (rawOffset < 0 || rawOffset > Integer.MAX_VALUE) {
            return false;
        }
        Data primitive = root.getPrimitiveAt((int) rawOffset);
        if (primitive == null || !primitive.getMinAddress().equals(destination) ||
            primitive.getLength() != STORE_BYTES) {
            return false;
        }
        DataType type = unwrapTypedef(primitive.getDataType());
        if (!(type instanceof Pointer pointer) || type.getLength() != STORE_BYTES) {
            return false;
        }
        DataType referenced = unwrapTypedef(pointer.getDataType());
        return referenced instanceof FunctionDefinition;
    }

    private static DataType unwrapTypedef(DataType type) {
        Set<DataType> seen = new HashSet<>();
        while (type instanceof TypeDef typedef && seen.add(type)) {
            type = typedef.getBaseDataType();
        }
        return type;
    }

    private static Address codeAddress(Program program, long value) {
        long normalized = value & 0xffff_ffffL;
        if (normalized == 0 || normalized == CODE_ADDRESS_MASK ||
                (normalized & ~CODE_ADDRESS_MASK) != 0) {
            return null;
        }
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        if (space.getAddressableUnitSize() != 2) {
            return null;
        }
        try {
            return space.getAddress(Math.multiplyExact(normalized, 2L));
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    private static boolean isSafeTarget(Program program, Address target) {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        if (!target.getAddressSpace().equals(space)) {
            return false;
        }
        MemoryBlock block = program.getMemory().getBlock(target);
        if (block == null || !block.isInitialized() || !block.isExecute()) {
            return false;
        }

        Listing listing = program.getListing();
        if (listing.getDefinedDataContaining(target) != null) {
            return false;
        }
        Instruction containingInstruction = listing.getInstructionContaining(target);
        if (containingInstruction != null &&
            !containingInstruction.getMinAddress().equals(target)) {
            return false;
        }

        FunctionManager functions = program.getFunctionManager();
        Function containingFunction = functions.getFunctionContaining(target);
        if (containingFunction != null &&
            !containingFunction.getEntryPoint().equals(target)) {
            return false;
        }

        if (containingFunction == null) {
            Instruction previous = listing.getInstructionBefore(target);
            if (previous != null && target.equals(previous.getFallThrough())) {
                return false;
            }
            ReferenceIterator incoming = program.getReferenceManager().getReferencesTo(target);
            while (incoming.hasNext()) {
                Reference reference = incoming.next();
                if (reference.getReferenceType().isFlow() &&
                    !reference.getReferenceType().isCall()) {
                    return false;
                }
            }
        }

        if (containingInstruction != null) {
            return true;
        }
        try {
            PseudoDisassembler pseudo = new PseudoDisassembler(program);
            pseudo.setRespectExecuteFlag(true);
            PseudoInstruction instruction = pseudo.disassemble(target);
            return instruction != null && instruction.getMinAddress().equals(target) &&
                instruction.getLength() > 0;
        }
        catch (Exception exception) {
            return false;
        }
    }

    private static boolean ensureFunction(Program program, Address target,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        FunctionManager functions = program.getFunctionManager();
        Function existing = functions.getFunctionAt(target);
        if (existing != null) {
            return true;
        }
        Function containing = functions.getFunctionContaining(target);
        if (containing != null) {
            return false;
        }

        Listing listing = program.getListing();
        if (listing.getInstructionAt(target) == null) {
            MemoryBlock block = program.getMemory().getBlock(target);
            if (block == null) {
                return false;
            }
            AddressSet restricted = new AddressSet(block.getStart(), block.getEnd());
            DisassembleCommand disassemble = new DisassembleCommand(target, restricted, true);
            if (!disassemble.applyTo(program, monitor) ||
                listing.getInstructionAt(target) == null) {
                log.appendMsg(NAME, "failed to disassemble proved target " + target +
                    ": " + disassemble.getStatusMsg());
                return false;
            }
        }

        CreateFunctionCmd create = new CreateFunctionCmd(null, target, null,
            SourceType.ANALYSIS, false, false);
        if (!create.applyTo(program, monitor)) {
            log.appendMsg(NAME, "failed to create proved target function " + target +
                ": " + create.getStatusMsg());
            return false;
        }
        Function function = functions.getFunctionAt(target);
        return function != null && function.getEntryPoint().equals(target);
    }

    private static void reconcileMarkers(Listing listing, Map<Address, String> desired,
            TaskMonitor monitor) throws CancelledException {
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            String current = instruction.getStringProperty(MARKER_PROPERTY);
            String wanted = desired.get(instruction.getMinAddress());
            if (wanted == null) {
                if (current != null) {
                    instruction.removeProperty(MARKER_PROPERTY);
                }
            }
            else if (!wanted.equals(current)) {
                instruction.setProperty(MARKER_PROPERTY, wanted);
            }
        }
    }

    private static List<Register> trackedRegisters(Program program) {
        List<Register> result = new ArrayList<>();
        for (Register register : program.getLanguage().getRegisters()) {
            if (register.isBaseRegister() && register.getMinimumByteSize() == STORE_BYTES &&
                !register.isProcessorContext() && !register.isProgramCounter() &&
                !register.isHidden()) {
                result.add(register);
            }
        }
        result.sort(Comparator.comparing(Register::getName));
        return result;
    }

    private static Register exactTrackedRegister(Varnode node, List<Register> tracked) {
        if (node == null || !node.isRegister() || node.getSize() != STORE_BYTES) {
            return null;
        }
        for (Register register : tracked) {
            if (node.getAddress().equals(register.getAddress()) &&
                node.getSize() == register.getMinimumByteSize()) {
                return register;
            }
        }
        return null;
    }

    private static boolean overlaps(Varnode node, Register register) {
        if (node == null || !node.isRegister()) {
            return false;
        }
        long nodeStart = node.getAddress().getOffset();
        long nodeEnd = nodeStart + node.getSize();
        long registerStart = register.getAddress().getOffset();
        long registerEnd = registerStart + register.getMinimumByteSize();
        return nodeStart < registerEnd && registerStart < nodeEnd;
    }

    private static ConstantState merge(ConstantState left, ConstantState right) {
        if (!left.reachable) {
            return right;
        }
        if (!right.reachable) {
            return left;
        }
        Map<Register, Long> agreed = new HashMap<>();
        for (Map.Entry<Register, Long> entry : left.values.entrySet()) {
            Long other = right.values.get(entry.getKey());
            if (entry.getValue().equals(other)) {
                agreed.put(entry.getKey(), entry.getValue());
            }
        }
        return ConstantState.known(agreed);
    }

    private static void addSuccessor(Map<Address, Node> nodes, Node source,
            Address address) {
        if (address == null) {
            return;
        }
        Node target = nodes.get(address);
        if (target == null) {
            return;
        }
        source.successors.add(target);
        target.predecessors.add(source);
    }

    private static long byteOffsetToWord(Program program, Address address) {
        int unit = program.getAddressFactory().getDefaultAddressSpace().getAddressableUnitSize();
        return address.getOffset() / unit;
    }

    private record Candidate(Instruction instruction, Address destination, Address target) {
    }

    private record StoreValue(Address destination, long value) {
    }

    private record VarnodeKey(Address address, int size) {
        VarnodeKey(Varnode node) {
            this(node.getAddress(), node.getSize());
        }
    }

    private static final class ConstantState {
        private static final ConstantState BOTTOM =
            new ConstantState(false, Map.of());
        private static final ConstantState UNKNOWN =
            new ConstantState(true, Map.of());

        final boolean reachable;
        final Map<Register, Long> values;

        private ConstantState(boolean reachable, Map<Register, Long> values) {
            this.reachable = reachable;
            this.values = Map.copyOf(values);
        }

        static ConstantState bottom() {
            return BOTTOM;
        }

        static ConstantState unknown() {
            return UNKNOWN;
        }

        static ConstantState known(Map<Register, Long> values) {
            return values.isEmpty() ? UNKNOWN : new ConstantState(true, values);
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (!(object instanceof ConstantState other)) {
                return false;
            }
            return reachable == other.reachable && values.equals(other.values);
        }

        @Override
        public int hashCode() {
            return Boolean.hashCode(reachable) * 31 + values.hashCode();
        }
    }

    private static final class Node {
        final Instruction instruction;
        final Set<Node> predecessors = new LinkedHashSet<>();
        final Set<Node> successors = new LinkedHashSet<>();
        boolean alternateIngress;
        ConstantState inputState = ConstantState.bottom();
        ConstantState outputState = ConstantState.bottom();

        Node(Instruction instruction) {
            this.instruction = instruction;
        }
    }
}
