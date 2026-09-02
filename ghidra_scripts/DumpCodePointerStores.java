// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Coverage report for TMS320C28xCodePointerAnalyzer.
//
// That analyzer proves, by intraprocedural constant propagation, which exact function
// address a store writes into a code-pointer slot. The interesting question is not how
// many it finds but how many it finds that NOTHING ELSE in the pipeline knows about:
// a handler installed by `g_handler = &fn;` at runtime is invisible to materialization
// (the value never exists in flash) and invisible to the registry pass (the slot is
// only written on a path startup never took).
//
// So this snapshots what is already known -- which targets have incoming references,
// which are already functions -- runs the analyzer, and reports the delta. A target
// that gains its FIRST reference here is one the rest of the pipeline missed.
//
// Run after the usual pipeline (Setup -> Seed -> Materialize* -> MarkComponentRegistry):
//   analyzeHeadless <proj> t -process <prog> -postScript DumpCodePointerStores.java
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.plugin.core.analysis.TMS320C28xCodePointerAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class DumpCodePointerStores extends GhidraScript {

    /**
     * Where candidates are lost, stage by stage.
     *
     * A recognizer that reports zero is indistinguishable from an image with nothing to
     * find, so mirror the analyzer's own preconditions and count survivors at each one.
     * The stages are, in order: the instruction carries exactly one memory-WRITE
     * reference; that reference's operand index resolves back to the same address
     * (upstream's `destination.equals(instruction.getAddress(operand))`); and the
     * instruction emits exactly one 4-byte STORE in its p-code.
     */
    private void funnel() {
        int withWrite = 0, exactlyOneWrite = 0, operandAgrees = 0, fourByteStore = 0;
        int constantValue = 0, registerValue = 0, uniqueValue = 0, otherValue = 0;
        Map<String, Integer> definers = new LinkedHashMap<>();
        Map<String, Integer> copySources = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            int writes = 0;
            ghidra.program.model.symbol.Reference write = null;
            for (ghidra.program.model.symbol.Reference r : insn.getReferencesFrom()) {
                if (r.isMemoryReference() && r.getReferenceType().isWrite()) {
                    writes++;
                    write = r;
                }
            }
            if (writes > 0) withWrite++;
            if (writes != 1) continue;
            exactlyOneWrite++;

            int operand = write.getOperandIndex();
            Address destination = write.getToAddress();
            boolean agrees = destination != null && operand >= 0 &&
                operand < insn.getNumOperands() &&
                destination.equals(insn.getAddress(operand));
            if (agrees) operandAgrees++;

            int stores = 0;
            for (ghidra.program.model.pcode.PcodeOp op : insn.getPcode()) {
                if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.STORE &&
                    op.getNumInputs() == 3 && op.getInput(2).getSize() == 4) {
                    stores++;
                }
            }
            if (stores != 1) continue;
            fourByteStore++;

            // What the stored value looks like decides whether the constant proof can
            // ever reach it: a constant varnode is immediate, a full-width register
            // varnode is propagatable, and anything else (a sub-register piece, a
            // temporary built by concatenation) is not.
            for (ghidra.program.model.pcode.PcodeOp op : insn.getPcode()) {
                if (op.getOpcode() != ghidra.program.model.pcode.PcodeOp.STORE ||
                    op.getNumInputs() != 3 || op.getInput(2).getSize() != 4) {
                    continue;
                }
                ghidra.program.model.pcode.Varnode value = op.getInput(2);
                if (value.isConstant()) constantValue++;
                else if (value.isRegister()) registerValue++;
                else if (value.isUnique()) {
                    uniqueValue++;
                    // Which op produced that temp? The resolver only walks back through
                    // COPY, so anything else here is a dead end for the constant proof.
                    String producer = "<undefined in this instruction>";
                    for (ghidra.program.model.pcode.PcodeOp d : insn.getPcode()) {
                        ghidra.program.model.pcode.Varnode out = d.getOutput();
                        if (out != null && out.isUnique() &&
                            out.getOffset() == value.getOffset() &&
                            out.getSize() == value.getSize()) {
                            producer = d.getMnemonic();
                        }
                    }
                    definers.merge(producer, 1, Integer::sum);
                    // And what does that COPY read? This is the last link in the
                    // resolver's chain: a constant or a full-width register can be
                    // proved, anything else cannot.
                    for (ghidra.program.model.pcode.PcodeOp d : insn.getPcode()) {
                        ghidra.program.model.pcode.Varnode out = d.getOutput();
                        if (out == null || !out.isUnique() ||
                            out.getOffset() != value.getOffset() ||
                            out.getSize() != value.getSize() ||
                            d.getOpcode() != ghidra.program.model.pcode.PcodeOp.COPY ||
                            d.getNumInputs() != 1) {
                            continue;
                        }
                        ghidra.program.model.pcode.Varnode src = d.getInput(0);
                        String kind = src.isConstant() ? "constant"
                            : src.isRegister()
                                ? "register size=" + src.getSize() + " "
                                    + describeRegister(src)
                                : src.isUnique() ? "unique" : "other";
                        copySources.merge(kind, 1, Integer::sum);
                    }
                }
                else otherValue++;
            }
        }
        println("funnel:");
        println("  instructions with a memory WRITE ref  : " + withWrite);
        println("  ...exactly one                        : " + exactlyOneWrite);
        println("  ...whose operand index agrees         : " + operandAgrees);
        println("  ...emitting one 4-byte STORE          : " + fourByteStore);
        println("  stored value is a constant            : " + constantValue);
        println("  stored value is a full register       : " + registerValue);
        println("  stored value is a unique (temp)       : " + uniqueValue);
        println("  stored value is something else        : " + otherValue);
        // The other end of the proof: unless something loads a constant into a
        // full-width register, no store can ever resolve to one.
        int constIntoReg = 0, constIntoRegViaTemp = 0;
        InstructionIterator all = currentProgram.getListing().getInstructions(true);
        while (all.hasNext()) {
            Instruction insn = all.next();
            Map<Long, ghidra.program.model.pcode.Varnode> tempSrc = new LinkedHashMap<>();
            for (ghidra.program.model.pcode.PcodeOp op : insn.getPcode()) {
                ghidra.program.model.pcode.Varnode out = op.getOutput();
                if (out == null) continue;
                if (out.isUnique() && op.getOpcode() == ghidra.program.model.pcode.PcodeOp.COPY
                    && op.getNumInputs() == 1) {
                    tempSrc.put(out.getOffset(), op.getInput(0));
                }
                if (!out.isRegister() || out.getSize() != 4) continue;
                if (op.getOpcode() != ghidra.program.model.pcode.PcodeOp.COPY ||
                    op.getNumInputs() != 1) continue;
                ghidra.program.model.pcode.Varnode in = op.getInput(0);
                if (in.isConstant()) constIntoReg++;
                else if (in.isUnique() && tempSrc.containsKey(in.getOffset())
                    && tempSrc.get(in.getOffset()).isConstant()) constIntoRegViaTemp++;
            }
        }
        println("  COPY constant -> 4-byte register      : " + constIntoReg);
        println("  ...via a COPY temp                    : " + constIntoRegViaTemp);
        println("  what defines the stored temp:");
        definers.entrySet().stream()
            .sorted((a, b) -> b.getValue() - a.getValue())
            .forEach(e -> println("      " + e.getValue() + "  " + e.getKey()));
        println("  what that COPY reads:");
        copySources.entrySet().stream()
            .sorted((a, b) -> b.getValue() - a.getValue())
            .limit(10)
            .forEach(e -> println("      " + e.getValue() + "  " + e.getKey()));
    }

    private String describeRegister(ghidra.program.model.pcode.Varnode node) {
        ghidra.program.model.lang.Register r = currentProgram.getRegister(node.getAddress());
        return r == null ? "<unnamed>"
            : r.getName() + (r.isBaseRegister() ? " (base)" : " (child of "
                + r.getBaseRegister().getName() + ")");
    }

    @Override
    protected void run() throws Exception {
        // Snapshot BEFORE: every address that already has something pointing at it, and
        // every address that is already a function entry.
        Set<Address> referencedBefore = new HashSet<>();
        for (Address a : currentProgram.getReferenceManager().getReferenceDestinationIterator(
                currentProgram.getMemory(), true)) {
            referencedBefore.add(a);
        }
        Set<Address> functionsBefore = new HashSet<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            functionsBefore.add(f.getEntryPoint());
        }

        TMS320C28xCodePointerAnalyzer analyzer = new TMS320C28xCodePointerAnalyzer();
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());

        // The analyzer records each proved store as a property on the storing
        // instruction, whose value is the target word address.
        Map<Address, String> proved = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            String marker = insn.getStringProperty(TMS320C28xCodePointerAnalyzer.MARKER_PROPERTY);
            if (marker != null) proved.put(insn.getMinAddress(), marker);
        }

        println("=== CODEPTRPROBE ===");
        println("proved code-pointer stores : " + proved.size());
        Set<String> targets = new HashSet<>(proved.values());
        println("distinct targets           : " + targets.size());

        int newlyReferenced = 0, newlyFunction = 0;
        for (Map.Entry<Address, String> e : proved.entrySet()) {
            long word = Long.decode(e.getValue());
            Address target = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(word * 2);
            boolean wasReferenced = referencedBefore.contains(target);
            boolean wasFunction = functionsBefore.contains(target);
            if (!wasReferenced) newlyReferenced++;
            if (!wasFunction) newlyFunction++;
            println(String.format("  store word %05x -> %05x%s%s",
                e.getKey().getOffset() / 2, word,
                wasReferenced ? "" : "   [FIRST reference to this target]",
                wasFunction ? "" : "   [target was not a function]"));
        }
        println("targets gaining a first reference : " + newlyReferenced);
        println("targets that were not functions   : " + newlyFunction);
        funnel();
        println("=== END ===");
    }
}
