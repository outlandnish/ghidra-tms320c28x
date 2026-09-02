// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Coverage report for TMS320C28xSwitchAnalyzer against a real image.
//
// The analyzer recognizes a fixed set of TI-compiler dispatch schedules by exact
// instruction sequence. That makes it precise and also makes it silent: a shape it
// has never seen simply does not match, and nothing says so. On a stripped image
// there is no way to tell "no switches here" from "switches the matchers miss"
// without reading the listing by hand.
//
// This script closes that gap. It finds every computed `LB *XAR7` in the program,
// runs the analyzer, and reports which ones it claimed. For each one it did NOT
// claim it prints the preceding instructions, which is the shape a new matcher
// would have to accept -- so an unmatched dispatch arrives as a written-out
// schedule rather than as an address to go and look up.
//
// Args (optional): WORD addresses to disassemble from before analyzing. Useful when
// the image has not been through the full SeedFunctions pipeline and only a few
// windows are decoded -- disassembly must start from a known instruction boundary,
// since walking backwards from the branch cannot find one reliably.
//
//   analyzeHeadless <proj> t -process <prog> \
//       -postScript DumpSwitchDispatches.java 0xWORD 0xWORD
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.plugin.core.analysis.TMS320C28xSwitchAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DumpSwitchDispatches extends GhidraScript {

    // How much of the schedule leading into an unmatched branch to print. The
    // longest shape any current matcher walks back is eight instructions; twelve
    // leaves room to see the range guard that precedes it.
    private static final int CONTEXT_INSTRUCTIONS = 12;

    @Override
    protected void run() throws Exception {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();

        for (var block : currentProgram.getMemory().getBlocks()) {
            println(String.format("block %s words 0x%x..0x%x", block.getName(),
                block.getStart().getOffset() / 2, block.getEnd().getOffset() / 2));
        }

        for (String arg : getScriptArgs()) {
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
        int matched = 0;
        for (Address branch : branches) {
            boolean claimed = canonical != null &&
                BigInteger.ONE.equals(context.getValue(canonical, branch, false));
            if (claimed) {
                matched++;
                println(String.format("MATCHED   word 0x%x", branch.getOffset() / 2));
            }
            else {
                println(String.format("UNMATCHED word 0x%x  -- schedule leading in:",
                    branch.getOffset() / 2));
                for (Instruction instruction : leadingInstructions(branch)) {
                    println(String.format("    %08x  %-28s %s",
                        instruction.getMinAddress().getOffset() / 2, instruction.toString(),
                        operandShape(instruction)));
                }
            }
        }
        println(String.format("matched %d of %d", matched, branches.size()));
        println("=== END ===");
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
        for (int i = 0; i < CONTEXT_INSTRUCTIONS && current != null; i++) {
            Instruction previous = listing.getInstructionBefore(current.getMinAddress());
            if (previous == null || !previous.getMaxAddress().next().equals(current.getMinAddress())) {
                break;
            }
            chain.add(0, previous);
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
