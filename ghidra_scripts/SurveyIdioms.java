// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Does an idiom-recovery analyzer have anything to recover on THIS image?
//
// mwdmwd/ghidra-c28x carries a family of analyzers that each prove one compiler idiom and
// canonicalize it so the decompiler stops rendering it as shift-and-mask salad: unrolled
// SUBCUL division, adjacent ASR64 sign-extension pairs, constant-T LSRL shifts, no-shift PM
// product stores, OVM-zero return data flow. Each is several hundred lines, and whether it
// earns them is entirely a property of the image -- a firmware that calls the runtime
// division helper has no unrolled SUBCUL to find, and one that never sets OVM has no
// saturation to model.
//
// Porting one to find out costs a week. This counts the evidence in minutes, so the decision
// is made on what is actually in the image rather than on the plausibility of the commit
// message. Run it before adopting an idiom analyzer, and again on a second image before
// declining one -- the counts differ sharply between an inverter and a gateway.
//
// It also audits ARTIFICIAL CFG: SLEIGH constructors whose p-code contains an internal
// branch split one instruction into several basic blocks, which the decompiler then has to
// re-merge. That is measured here rather than by reading the .sinc, because what matters is
// the count weighted by how often the instruction actually occurs.
//
// Read the output as: a target with a count of zero is a decline with evidence behind it.
//
//   analyzeHeadless <proj> t -process <prog> -noanalysis -postScript SurveyIdioms.java
//
// CHECK THE INSTRUCTION COUNT FIRST. A byte-swapped image imported without the swap
// disassembles to a few dozen instructions instead of a hundred thousand, and every count
// below is then a zero that means nothing. See docs/C28X_IMAGE_SETUP.md "The byte-swap":
// an image whose count is implausibly low for its size has not been swapped.
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class SurveyIdioms extends GhidraScript {

    // How many of the most common mnemonics to list, and to audit for artificial CFG.
    private static final int TOP_MNEMONICS = 40;

    // A run of this many identical conditional-subtract steps is an unrolled division; TI
    // emits 16 for SUBCU and 32 for SUBCUL, so anything at or above this is the idiom and
    // a scattered handful is not.
    private static final int DIVISION_RUN = 4;

    private final Map<String, Integer> mnemonics = new TreeMap<>();
    private final Map<String, Integer> modeSelects = new TreeMap<>();
    private final Map<String, Integer> internalBranches = new TreeMap<>();
    private final Map<String, Integer> runs = new TreeMap<>();
    private int instructionCount;
    private int adjacentAsr64;
    private int productStores;

    @Override
    protected void run() throws Exception {
        survey();
        println("=== SURVEY " + currentProgram.getName() + " ===");
        println("instructions: " + instructionCount);

        println("");
        println("-- idiom-analyzer targets (upstream mwdmwd/ghidra-c28x) --");
        line("SUBCUL", "unrolled 32-bit division (d0f8b83)",
            "runs>=" + DIVISION_RUN + ": " + runs.getOrDefault("SUBCUL", 0));
        line("SUBCU", "unrolled 16-bit division (d0f8b83)",
            "runs>=" + DIVISION_RUN + ": " + runs.getOrDefault("SUBCU", 0));
        line("ASR64", "sign-extension pairs (f33d2b8)", "adjacent pairs: " + adjacentAsr64);
        line("LSRL", "constant-T shift (679d5eb)", "");
        line("ZALR", "full-width ACC write (5878e9c)", "");
        line("SPM", "product-shift mode changes -- the PM product store (375fa7f) is only", "");
        println(String.format("  %-10s %6d   worth proving where products are stored without one",
            "stores->P", productStores));
        for (String mnemonic : new String[] { "QMPYL", "IMPYL", "QMPYAL", "QMPYUL", "LSL64" }) {
            line(mnemonic, "fixed-point product feeding those stores", "");
        }

        println("");
        println("-- mode selects (the SETC/CLRC an analyzer would key on) --");
        if (modeSelects.isEmpty()) {
            println("  (none)");
        }
        modeSelects.entrySet().stream()
            .sorted((a, b) -> b.getValue() - a.getValue())
            .forEach(e -> println(String.format("  %-24s %6d", e.getKey(), e.getValue())));
        println("  SXM bears on the MOV low-half exposure (cb3f290);");
        println("  OVM on the return-data-flow / ADDCL / shifted-P ADDL cluster (8c639a6).");

        List<Map.Entry<String, Integer>> top = new ArrayList<>(mnemonics.entrySet());
        top.sort((a, b) -> b.getValue() - a.getValue());

        println("");
        println("-- artificial CFG: p-code internal branches in the " + TOP_MNEMONICS +
            " most common instructions --");
        int flagged = 0;
        for (int i = 0; i < Math.min(TOP_MNEMONICS, top.size()); i++) {
            String mnemonic = top.get(i).getKey();
            Integer branchy = internalBranches.get(mnemonic);
            if (branchy != null) {
                flagged++;
                println(String.format("  %-10s %6d of %d instances branch internally", mnemonic,
                    branchy, top.get(i).getValue()));
            }
        }
        if (flagged == 0) {
            println("  (none -- no common instruction splits into extra basic blocks)");
        }

        println("");
        println("-- top " + TOP_MNEMONICS + " mnemonics --");
        for (int i = 0; i < Math.min(TOP_MNEMONICS, top.size()); i++) {
            println(String.format("  %-10s %6d", top.get(i).getKey(), top.get(i).getValue()));
        }
        println("=== END SURVEY ===");
    }

    private void line(String mnemonic, String note, String extra) {
        println(String.format("  %-10s %6d   %s%s", mnemonic, mnemonics.getOrDefault(mnemonic, 0),
            note, extra.isEmpty() ? "" : "   [" + extra + "]"));
    }

    private void survey() throws Exception {
        Map<String, Integer> openRuns = new LinkedHashMap<>();
        Instruction previous = null;
        InstructionIterator all = currentProgram.getListing().getInstructions(true);
        while (all.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = all.next();
            instructionCount++;
            String mnemonic = instruction.getMnemonicString().toUpperCase();
            mnemonics.merge(mnemonic, 1, Integer::sum);

            if (mnemonic.equals("SETC") || mnemonic.equals("CLRC")) {
                modeSelects.merge(instruction.toString().toUpperCase().replaceAll("\\s+", " "), 1,
                    Integer::sum);
            }
            if (mnemonic.equals("ASR64") && previous != null &&
                previous.getMnemonicString().equalsIgnoreCase("ASR64")) {
                adjacentAsr64++;
            }
            if (isProductStore(instruction, mnemonic)) {
                productStores++;
            }
            countRun(openRuns, "SUBCUL", mnemonic);
            countRun(openRuns, "SUBCU", mnemonic);
            if (hasInternalBranch(instruction)) {
                internalBranches.merge(mnemonic, 1, Integer::sum);
            }
            previous = instruction;
        }
        // A run that reaches the end of the listing still counts.
        openRuns.forEach((mnemonic, length) -> {
            if (length >= DIVISION_RUN) {
                runs.merge(mnemonic, 1, Integer::sum);
            }
        });
    }

    /** Track consecutive occurrences of {@code watch}, banking each run that gets long enough. */
    private void countRun(Map<String, Integer> openRuns, String watch, String mnemonic) {
        if (mnemonic.equals(watch)) {
            openRuns.merge(watch, 1, Integer::sum);
            return;
        }
        Integer length = openRuns.remove(watch);
        if (length != null && length >= DIVISION_RUN) {
            runs.merge(watch, 1, Integer::sum);
        }
    }

    /** A store OUT of the P register -- what the PM product-store idiom writes. */
    private static boolean isProductStore(Instruction instruction, String mnemonic) {
        if (!mnemonic.equals("MOVL") && !mnemonic.equals("MOV")) {
            return false;
        }
        String text = instruction.toString().toUpperCase();
        return text.endsWith(",P") || text.endsWith(",@P") || text.endsWith(",PH") ||
            text.endsWith(",PL");
    }

    /**
     * Whether an instruction's p-code branches WITHIN itself. Such a branch targets a
     * constant-space varnode (a relative p-code index) rather than a code address, and splits
     * the single instruction into several basic blocks for the decompiler to re-merge.
     */
    private static boolean hasInternalBranch(Instruction instruction) {
        for (PcodeOp op : instruction.getPcode()) {
            int opcode = op.getOpcode();
            if (opcode != PcodeOp.BRANCH && opcode != PcodeOp.CBRANCH) {
                continue;
            }
            Varnode target = op.getInput(0);
            if (target != null && target.isConstant()) {
                return true;
            }
        }
        return false;
    }
}
