// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Switch-dispatch coverage report against a real image.
//
// TMS320C28xSwitchAnalyzer recognizes a fixed set of TI-compiler dispatch schedules by
// exact instruction sequence. That makes it precise and also makes it silent: a shape it
// has never seen simply does not match, and nothing says so. On a stripped image there is
// no way to tell "no switches here" from "switches the matchers miss" without reading the
// listing by hand.
//
// This script closes that gap. It finds every computed `LB *XAR7` in the program, runs the
// analyzer, and reports each branch under TWO independent facts, because they answer
// different questions:
//
//   CANONICALIZED  the analyzer claimed this schedule (switch_canonical is set)
//   RESOLVED       the branch has computed-jump references, i.e. the switch IS recovered
//
// They come apart in both directions and neither alone is the coverage number. Stock
// Decompiler Switch Analysis resolves some native dispatches unaided, so a branch can be
// RESOLVED without ever being CANONICALIZED -- and once DSA has done that, its case blocks
// become functions, which is exactly what the analyzer's table validation refuses, so it
// will never claim that branch afterwards. That is benign: the switch is recovered.
// Conversely TMS320C28xProgramReadSwitchAnalyzer resolves the PREAD forms by installing a
// jump-table override without canonicalizing anything. The dispatch that needs work is the
// one that is NEITHER -- for those the preceding instructions are printed, which is the
// shape a new matcher would have to accept, so it arrives as a written-out schedule rather
// than as an address to go and look up.
//
// Args (optional): WORD addresses to disassemble from before analyzing. Useful when the
// image has not been through the full SeedFunctions pipeline and only a few windows are
// decoded -- disassembly must start from a known instruction boundary, since walking
// backwards from the branch cannot find one reliably.
//
//   analyzeHeadless <proj> t -process <prog> \
//       -postScript DumpSwitchDispatches.java 0xWORD 0xWORD
//
// An arg of the form ctx:<n> sets how many leading instructions to print. Not `ctx=<n>`:
// cmd.exe treats `=` as an argument delimiter, so analyzeHeadless.bat would deliver `ctx`
// and `<n>` as two separate args and the count would be read as an address.
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.plugin.core.analysis.TMS320C28xSwitchAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Reference;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DumpSwitchDispatches extends GhidraScript {

    // How much of the schedule leading into an unrecovered branch to print. The
    // longest shape any current matcher walks back is eight instructions; twelve
    // leaves room to see the range guard that precedes it. Override with ctx:<n>.
    private static final int DEFAULT_CONTEXT_INSTRUCTIONS = 12;

    // How much of the guard to print at each edge into the dispatch block. A range
    // guard is at most a bound load, a subtract, a compare and the branch.
    private static final int EDGE_INSTRUCTIONS = 5;

    private int contextInstructions = DEFAULT_CONTEXT_INSTRUCTIONS;

    @Override
    protected void run() throws Exception {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();

        for (var block : currentProgram.getMemory().getBlocks()) {
            println(String.format("block %s words 0x%x..0x%x", block.getName(),
                block.getStart().getOffset() / 2, block.getEnd().getOffset() / 2));
        }

        for (String arg : getScriptArgs()) {
            if (arg.startsWith("ctx:")) {
                contextInstructions = Integer.parseInt(arg.substring(4));
                continue;
            }
            Address at = space.getAddress(Long.decode(arg) * 2);
            disassemble(at);
            println(String.format("seeded disassembly at word 0x%x", Long.decode(arg)));
        }

        List<Address> branches = new ArrayList<>();
        InstructionIterator all = listing.getInstructions(true);
        while (all.hasNext()) {
            Instruction instruction = all.next();
            if (isComputedXar7Branch(instruction)) {
                branches.add(instruction.getMinAddress());
            }
        }
        println("=== DUMPSWITCH ===");
        println(String.format("computed LB *XAR7 branches found: %d", branches.size()));

        TMS320C28xSwitchAnalyzer analyzer = new TMS320C28xSwitchAnalyzer();
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());

        ProgramContext context = currentProgram.getProgramContext();
        Register canonical = context.getRegister("switch_canonical");
        int canonicalized = 0;
        int resolved = 0;
        for (Address branch : branches) {
            boolean claimed = canonical != null &&
                BigInteger.ONE.equals(context.getValue(canonical, branch, false));
            int cases = computedJumpCount(branch);
            if (claimed) {
                canonicalized++;
            }
            if (cases >= 2) {
                resolved++;
            }
            println(String.format("word 0x%x  %-14s %-11s cases=%d", branch.getOffset() / 2,
                claimed ? "CANONICALIZED" : "not-claimed", cases >= 2 ? "RESOLVED" : "UNRESOLVED",
                cases));
            if (claimed || cases >= 2) {
                continue;
            }
            println("  -- schedule leading in:");
            List<Instruction> window = leadingInstructions(branch);
            for (Instruction instruction : window) {
                println(String.format("    %08x  %-28s %s",
                    instruction.getMinAddress().getOffset() / 2, instruction.toString(),
                    operandShape(instruction)));
            }
            printIncomingEdges(window);
        }
        println(String.format("canonicalized %d of %d; resolved %d of %d", canonicalized,
            branches.size(), resolved, branches.size()));
        println("=== END ===");
    }

    /** Computed-jump references out of a branch -- i.e. the recovered case count. */
    private int computedJumpCount(Address branch) {
        int computed = 0;
        for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(branch)) {
            if (reference.getReferenceType().isJump() && reference.getReferenceType().isComputed()) {
                computed++;
            }
        }
        return computed;
    }

    /**
     * How the matchers actually see an instruction: operand count, and per operand the
     * objects SLEIGH exposes. A matcher predicate is written against this, not against
     * the printed text, and the two diverge whenever a constructor bakes a register or
     * a mode name into the mnemonic as a print literal -- which shows up here as an
     * operand that simply is not there.
     */
    private static String operandShape(Instruction instruction) {
        StringBuilder shape = new StringBuilder();
        shape.append("mn='").append(instruction.getMnemonicString()).append('\'');
        shape.append(" nops=").append(instruction.getNumOperands());
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            shape.append(" [").append(i).append(']');
            for (Object object : instruction.getOpObjects(i)) {
                shape.append(object instanceof ghidra.program.model.lang.Register register
                        ? "reg:" + register.getName()
                        : object instanceof ghidra.program.model.scalar.Scalar scalar
                                ? "scalar:0x" + Long.toHexString(scalar.getUnsignedValue())
                                : object.getClass().getSimpleName())
                    .append(' ');
            }
        }
        return shape.toString();
    }

    /**
     * The instructions immediately before {@code branch}, oldest first. Walks back
     * by following each instruction's own fall-through, so a window that lands
     * mid-instruction is skipped rather than being decoded at a false boundary.
     */
    private List<Instruction> leadingInstructions(Address branch) {
        Listing listing = currentProgram.getListing();
        List<Instruction> chain = new ArrayList<>();
        Instruction current = listing.getInstructionAt(branch);
        for (int i = 0; i < contextInstructions && current != null; i++) {
            Instruction previous = listing.getInstructionBefore(current.getMinAddress());
            if (previous == null || !previous.getMaxAddress().next().equals(current.getMinAddress())) {
                break;
            }
            chain.add(0, previous);
            current = previous;
        }
        return chain;
    }

    /**
     * The guard, when it is not in the fall-through window. A dispatch block is often
     * jumped into rather than fallen into, which puts the range check proving the
     * selector bounded in another block entirely -- invisible to a backwards walk, and
     * exactly what a matcher has to see. So for every instruction in the printed window,
     * print each flow edge arriving from outside it, with the instructions ending there.
     */
    private void printIncomingEdges(List<Instruction> window) {
        Listing listing = currentProgram.getListing();
        AddressSet inWindow = new AddressSet();
        for (Instruction instruction : window) {
            inWindow.add(instruction.getMinAddress(), instruction.getMaxAddress());
        }
        for (Instruction instruction : window) {
            for (Reference reference : currentProgram.getReferenceManager()
                    .getReferencesTo(instruction.getMinAddress())) {
                Address from = reference.getFromAddress();
                if (!reference.getReferenceType().isFlow() || inWindow.contains(from)) {
                    continue;
                }
                println(String.format("  edge -> %08x from %08x (%s):",
                    instruction.getMinAddress().getOffset() / 2, from.getOffset() / 2,
                    reference.getReferenceType().getName()));
                for (Instruction leading : trailingChain(listing.getInstructionAt(from))) {
                    println(String.format("    %08x  %-28s %s",
                        leading.getMinAddress().getOffset() / 2, leading.toString(),
                        operandShape(leading)));
                }
            }
        }
    }

    /** {@code source} and the instructions it falls through from, oldest first. */
    private List<Instruction> trailingChain(Instruction source) {
        Listing listing = currentProgram.getListing();
        List<Instruction> chain = new ArrayList<>();
        Instruction current = source;
        for (int i = 0; i < EDGE_INSTRUCTIONS && current != null; i++) {
            chain.add(0, current);
            Instruction previous = listing.getInstructionBefore(current.getMinAddress());
            if (previous == null ||
                !previous.getMaxAddress().next().equals(current.getMinAddress())) {
                break;
            }
            current = previous;
        }
        return chain;
    }

    // Mirrors the analyzer's own terminal-branch test: this module's SLEIGH bakes
    // XAR7 into the mnemonic literal, so `LB *XAR7` carries no operands at all.
    private static boolean isComputedXar7Branch(Instruction instruction) {
        if (instruction == null || !instruction.getFlowType().isJump() ||
            !instruction.getFlowType().isComputed()) {
            return false;
        }
        return "LB".equalsIgnoreCase(instruction.getMnemonicString()) &&
            instruction.toString().contains("*XAR7");
    }
}
