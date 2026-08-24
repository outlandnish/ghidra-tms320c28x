// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Step 7 of the image-setup pipeline (docs/C28X_IMAGE_SETUP.md): classify the Error
// bookmarks the pipeline leaves behind and delete only the ones that are provably
// cosmetic, leaving anything that could be a real gap visible.
//
// The bulk of post-pipeline marks are phantom decodes: the disassembler speculatively
// decoded a const pool, a flash load image, or inter-function padding before
// MarkDataTables/MaterializeSections claimed those bytes as data. Once the byte is a
// data (or undefined) code unit, the mark on it describes an instruction that no longer
// exists. Those are safe to drop wholesale.
//
// What is NOT dropped, because each can be a genuine finding:
//   - a mark on a real instruction inside a function  -> possible missing opcode
//   - a mark on a loose instruction outside any function -> code/data boundary or a
//     committed-state artifact; wants a human look
//   - a "flow into uninitialized / non-existing memory" mark whose target is still
//     unmapped -> an un-materialized section (back to pipeline step 4/4b)
//
// Default is a DRY RUN: it prints the classification and changes nothing. Pass "apply"
// as the script argument to actually delete the cosmetic marks.
//
//   run_ghidra_script SweepResidualMarks.java            # report only
//   run_ghidra_script SweepResidualMarks.java  apply     # delete the cosmetic class
//
//@category C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SweepResidualMarks extends GhidraScript {

    /** "…memory at 00180048 (flow from …)" — the address the dangling flow targets. */
    private static final Pattern FLOW_TARGET =
            Pattern.compile("memory at ([0-9a-fA-F]+)");

    @Override
    public void run() throws Exception {
        boolean apply = false;
        for (String a : getScriptArgs()) {
            if (a.equalsIgnoreCase("apply")) {
                apply = true;
            }
        }

        BookmarkManager bm = currentProgram.getBookmarkManager();

        List<Bookmark> cosmetic = new ArrayList<>();   // mark sits on data/undefined
        List<Bookmark> inFunction = new ArrayList<>(); // real instruction, in a function
        List<Bookmark> loose = new ArrayList<>();      // real instruction, no function
        List<Bookmark> deadFlow = new ArrayList<>();   // flow target still unmapped

        Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
        while (it.hasNext()) {
            Bookmark b = it.next();
            Address addr = b.getAddress();
            String comment = b.getComment() == null ? "" : b.getComment();

            Address flowTarget = danglingFlowTarget(comment, addr);
            if (flowTarget != null) {
                deadFlow.add(b);
                continue;
            }

            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
            boolean isInsn = cu instanceof Instruction;
            boolean inFn = getFunctionContaining(addr) != null;

            if (inFn) {
                // Inside a function body. An address here that did NOT decode is the most
                // interesting case there is: SeedFunctions bound a function whose very
                // first word the disassembler could not resolve, which is the signature of
                // a missing opcode. Never treat that as cosmetic just because the failed
                // decode left an undefined code unit behind.
                inFunction.add(b);
            }
            else if (!isInsn) {
                cosmetic.add(b);          // data / undefined / nothing, outside any function
            }
            else {
                loose.add(b);
            }
        }

        println("=== residual Error marks: " + (cosmetic.size() + inFunction.size()
                + loose.size() + deadFlow.size()) + " ===");
        report("cosmetic (mark on data/undefined -- deletable)", cosmetic);
        report("KEEP: on an instruction inside a function (possible missing opcode)", inFunction);
        report("KEEP: on a loose instruction (code/data boundary -- review)", loose);
        report("KEEP: flow into unmapped memory (un-materialized section?)", deadFlow);

        if (!apply) {
            println("");
            println("DRY RUN -- nothing changed. Re-run with the 'apply' argument to delete "
                    + cosmetic.size() + " cosmetic mark(s).");
            return;
        }

        int removed = 0;
        for (Bookmark b : cosmetic) {
            bm.removeBookmark(b);
            removed++;
        }
        println("");
        println("applied: deleted " + removed + " cosmetic mark(s); "
                + (inFunction.size() + loose.size() + deadFlow.size()) + " kept for review.");
    }

    /**
     * For a "could not follow disassembly flow into …" mark, return the target address when
     * it is still unmapped or uninitialized (a real gap), else null. A target that is now
     * backed by initialized bytes means the mark is stale, and FinalizeRamfuncs pass 1b
     * already clears those — anything left here is worth keeping.
     */
    private Address danglingFlowTarget(String comment, Address markAddr) {
        if (!comment.contains("follow disassembly flow")
                && !comment.contains("not permitted within uninitialized")) {
            return null;
        }
        Matcher m = FLOW_TARGET.matcher(comment);
        if (!m.find()) {
            // "Disassembly not permitted within uninitialized memory block" names no
            // address. It still means a flow ran into memory nothing has filled, so keep
            // it: report it against the mark's own address.
            return comment.contains("not permitted within uninitialized") ? markAddr : null;
        }
        try {
            Address t = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseLong(m.group(1), 16));
            MemoryBlock blk = currentProgram.getMemory().getBlock(t);
            return (blk == null || !blk.isInitialized()) ? t : null;
        }
        catch (Exception e) {
            return null;
        }
    }

    private void report(String label, List<Bookmark> list) {
        println("  " + label + ": " + list.size());
        int shown = 0;
        for (Bookmark b : list) {
            if (shown++ >= 12) {
                println("      … and " + (list.size() - 12) + " more");
                break;
            }
            Function f = getFunctionContaining(b.getAddress());
            println("      " + b.getAddress() + (f == null ? "" : "  in " + f.getName())
                    + "  -- " + b.getComment());
        }
    }

    /** Ghidra's bookmark type constant, spelled out so the import stays minimal. */
    private static final class BookmarkType {
        static final String ERROR = ghidra.program.model.listing.BookmarkType.ERROR;
    }
}
