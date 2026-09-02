// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Find and mark CODE-ADDRESS (jump/switch) tables in a C28x firmware image.
//
// THE PROBLEM. The C28x stores a 32-bit code pointer as two 16-bit words: the LOW half at
// the even word, the HIGH half (a small page number) at the next word. A switch/case
// dispatch compiles to a table of these pointers, usually placed right after a function
// (after its LRETR). A linear or prologue-driven disassembler that falls through the
// inter-function padding into such a table decodes the pointer words as bogus instructions
// (e.g. the constant high word 0x0008 reads as BANZ), producing garbage code and the red
// "conflicting data/instruction" error blocks Ghidra shows. This is DATA misread as code —
// not a missing/buggy opcode — so the fix is markup, not a SLEIGH change.
//
// THE PATTERN. A run of >= MIN_ENTRIES consecutive word-pairs where:
//   - the HIGH word (odd offset) is a small constant page number that places the pointer
//     INSIDE the loaded image (typically 0x0008 for a 0x8xxxx image), and
//   - the assembled address (high<<16 | low) lands in the image's code range.
// Real jump tables are dense runs of these; isolated coincidences are filtered by MIN_ENTRIES.
//
// WHAT IT DOES. For each detected table: clear any (bogus) code units over it, define each
// entry as a `pointer`, add a DATA reference entry->target, and label the table
// `jmptbl_<addr>`. By default it only marks tables that are NOT already correctly defined as
// pointers. It then RECOVERS the targets (see below).
//
// TARGET RECOVERY. Marking the table alone leaves its targets undefined: a DATA reference
// does not make Ghidra disassemble anything, so a handler reached ONLY through the table
// stays invisible -- no function, no body, and its own callees never get discovered either.
// SeedFunctions' fn-ptr-table pass (C) is the general version of this, but it has to guard a
// whole-image scan for lone 2-word pointer-like values with a CODE-DENSITY test, and that
// test rejects exactly the interesting case: a handler sitting in a region nothing else has
// seeded yet. Here the evidence is much stronger -- a dense run of >= MIN_ENTRIES consecutive
// in-image code pointers is already a confirmed table -- so its targets can be recovered with
// weaker guards than a blind scan could justify.
//
// SWITCH vs DISPATCH -- the distinction that matters. The detector finds both, and they want
// opposite treatment:
//   - a SWITCH/case table's targets are basic blocks INSIDE one function. Turning each into
//     its own function would shred the containing function into fragments.
//   - a DISPATCH/handler table's targets ARE function entries (ISR vectors, service tables,
//     state handlers), and those are the ones worth recovering.
// Each table is classified before anything is created:
//   1. any target already INSIDE a function body is left alone and reported as interior --
//      that is a case block, or a function that already owns it;
//   2. the remaining targets are scored by whether they open with a C28x push PROLOGUE
//      (the same test SeedFunctions pass B uses). A table where most unowned targets carry a
//      prologue is a DISPATCH table -- create a function at each. Below that threshold the
//      table is treated as a SWITCH and only the individually prologue-bearing targets are
//      promoted, so a case block never becomes a function.
// Creation guards, after classification: the target must sit in an initialized executable
// block, must disassemble, and must yield a body of at least minLeafWords -- rejecting the
// 1-2 word padding/stranded-LRETR "functions" that a naive seed produces.
//
// This is the structured-data counterpart to SeedFunctions.java's entropy filter: an entropy
// gate won't catch a pointer table (it's low-entropy and the page byte is in the opcode
// vocabulary), so jump tables need their own pattern detector — this script.
//
// Properties (optional, -Dname=value):
//   c28x.jmptbl.minEntries   (int, default 4)     minimum run length to treat as a table
//   c28x.jmptbl.dryRun       (bool,default false) report only; make no changes
//   c28x.jmptbl.noRecover    (bool,default false) mark tables only; do not recover targets
//   c28x.jmptbl.minLeafWords (int, default 3)     reject recovered functions smaller than this
//   c28x.jmptbl.prologFrac   (dbl, default 0.5)   unowned-target prologue fraction above which
//                                                 a table counts as DISPATCH rather than SWITCH
//
// @category TMS320C28x
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class MarkJumpTables extends GhidraScript {
    long base, lo, hi;
    byte[] mem;
    ghidra.program.model.address.AddressSpace space;

    int wordAt(long byteOff) {
        if (byteOff < 0 || byteOff + 1 >= mem.length) return -1;
        return (mem[(int)byteOff] & 0xff) | ((mem[(int)(byteOff+1)] & 0xff) << 8);
    }
    Address addr(long word) { return space.getAddress(word * 2); }

    // Read the assembled 32-bit pointer at table word `w` (low @ w, high @ w+1).
    // Returns -1 unless this looks like a real code pointer: the HIGH word must be a small
    // page number (these images live in page 0x08, i.e. 0x8xxxx — random data's high words
    // scatter across 0..0xffff, so bounding the page is the key discriminator), and the
    // assembled address must land inside the loaded image.
    static final int MAX_PAGE = 0x000F;   // 22-bit addr -> high 6 bits; image code is page 8
    long pointerAt(long w) {
        long sb = (w - base) * 2;
        int loW = wordAt(sb), hiW = wordAt(sb + 2);
        if (loW < 0 || hiW < 0) return -1;
        if (hiW > MAX_PAGE) return -1;           // high word must be a small page number
        long tgt = (((long) hiW) << 16) | (loW & 0xffff);
        if (tgt < lo || tgt > hi) return -1;     // must point inside the loaded image
        return tgt;
    }

    @Override
    public void run() throws Exception {
        int minEntries = Integer.getInteger("c28x.jmptbl.minEntries", 4);
        boolean dryRun = Boolean.getBoolean("c28x.jmptbl.dryRun");

        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        // Flash image = the LARGEST INITIALIZED block. A naive getBlocks()[0] grabs whatever
        // block sorts first by address (M0_RAM @0x0, or an uninitialized flash-gap / MMIO block
        // once SetupF28377D has added them), and getBytes() throws MemoryAccessException on an
        // uninitialized block. Mirror SeedFunctions / MaterializeSections: pick the largest
        // initialized block instead.
        MemoryBlock blk = null;
        long bestLen = -1;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; blk = b; }
        }
        if (blk == null) { println("MarkJumpTables: no initialized memory block found"); return; }
        Address start = blk.getStart(), end = blk.getEnd();
        base = start.getOffset() / 2;
        long nbytes = end.getOffset() - start.getOffset() + 1;
        mem = new byte[(int) nbytes];
        blk.getBytes(start, mem);
        long nwords = nbytes / 2;
        lo = base; hi = base + nwords - 1;

        DataType ptr = new PointerDataType();
        int tablesFound = 0, entriesMarked = 0;
        List<long[]> tables = new ArrayList<>();   // {tableStart, run} per detected table

        long w = base;
        while (w + 1 <= hi) {
            // try to start a table run at w
            int run = 0;
            long p = w;
            while (pointerAt(p) >= 0) { run++; p += 2; }
            if (run >= minEntries) {
                // SAFETY: never clobber a run that sits inside a defined function body —
                // real code can coincidentally form a pointer-like run. Tables live BETWEEN
                // functions (after an LRETR), so a candidate inside a function is a false hit.
                if (currentProgram.getFunctionManager().getFunctionContaining(addr(w)) != null) {
                    w++;
                    continue;
                }
                tablesFound++;
                long tableStart = w, tableEnd = w + run * 2 - 1;   // inclusive word range
                StringBuilder tgts = new StringBuilder();
                for (int i = 0; i < Math.min(run, 6); i++)
                    tgts.append(String.format("0x%x ", pointerAt(w + i * 2)));
                println(String.format("jmptbl @0x%x  %d entries (0x%x..0x%x) -> %s%s",
                    tableStart, run, tableStart, tableEnd, tgts, run > 6 ? "..." : ""));
                if (!dryRun) markTable(tableStart, run, ptr);
                entriesMarked += run;
                tables.add(new long[] { tableStart, run });
                w = tableEnd + 1;                                 // skip past the table
            } else {
                w++;
            }
        }
        println(String.format("%s: %d tables, %d pointer entries%s",
            dryRun ? "DRY RUN" : "done", tablesFound, entriesMarked, dryRun ? " (no changes made)" : ""));

        // Recovery runs only after EVERY table has been marked, so a target that happens to
        // land in a later table's extent is judged against the finished markup rather than
        // against whatever the scan had reached at the time.
        if (!Boolean.getBoolean("c28x.jmptbl.noRecover")) recoverTargets(tables, dryRun);
    }

    /**
     * Turn jump/dispatch-table targets into real functions. See the TARGET RECOVERY note in
     * the header for why this is safe here but not in a blind whole-image pointer scan.
     */
    void recoverTargets(List<long[]> tables, boolean dryRun) throws Exception {
        int minLeafWords = Integer.getInteger("c28x.jmptbl.minLeafWords", 3);
        double prologFrac = Double.parseDouble(System.getProperty("c28x.jmptbl.prologFrac", "0.5"));

        var fmgr = currentProgram.getFunctionManager();
        var listing = currentProgram.getListing();

        int dispatchTables = 0, switchTables = 0;
        int interior = 0, alreadyFn = 0, created = 0, rejected = 0, skippedCase = 0;

        for (long[] t : tables) {
            long tableStart = t[0];
            int run = (int) t[1];

            // Distinct targets only: dispatch tables routinely repeat a default handler, and
            // a duplicate must not be counted twice when scoring the table.
            TreeSet<Long> targets = new TreeSet<>();
            for (int i = 0; i < run; i++) {
                long tgt = pointerAt(tableStart + i * 2);
                if (tgt >= 0) targets.add(tgt);
            }

            List<Long> unowned = new ArrayList<>();
            int localInterior = 0;
            for (long tgt : targets) {
                Address a = addr(tgt);
                Function f = fmgr.getFunctionContaining(a);
                if (f != null) {
                    // Entry of an existing function = already recovered. Strictly inside one =
                    // a case block (or an offcut); either way, not ours to carve up.
                    if (f.getEntryPoint().equals(a)) alreadyFn++;
                    else { interior++; localInterior++; }
                    continue;
                }
                unowned.add(tgt);
            }
            if (unowned.isEmpty()) continue;

            int withProlog = 0;
            for (long tgt : unowned) if (prologueRun(tgt) > 0) withProlog++;
            double frac = (double) withProlog / unowned.size();
            // An interior target is direct evidence of a switch: the table points into a
            // function body. Combined with a weak prologue score it settles the question.
            boolean dispatch = frac >= prologFrac && localInterior == 0;
            if (dispatch) dispatchTables++; else switchTables++;

            println(String.format("  jmptbl_%06x  %s  unowned=%d prologue=%d/%d (%.2f)%s",
                tableStart, dispatch ? "DISPATCH" : "switch  ", unowned.size(), withProlog,
                unowned.size(), frac,
                localInterior > 0 ? String.format(" interior=%d", localInterior) : ""));

            for (long tgt : unowned) {
                boolean hasProlog = prologueRun(tgt) > 0;
                // In a switch table only a prologue-bearing target is promoted; a bare case
                // block is left for the containing function's own flow to pick up.
                if (!dispatch && !hasProlog) { skippedCase++; continue; }

                Address a = addr(tgt);
                MemoryBlock b = currentProgram.getMemory().getBlock(a);
                if (b == null || !b.isInitialized() || !b.isExecute()) { rejected++; continue; }
                if (dryRun) { created++; continue; }

                if (listing.getInstructionAt(a) == null)
                    new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                if (listing.getInstructionAt(a) == null) { rejected++; continue; }  // would not decode

                new CreateFunctionCmd(a).applyTo(currentProgram, monitor);
                Function nf = fmgr.getFunctionAt(a);
                if (nf == null) { rejected++; continue; }

                // Reject padding / a stranded LRETR tail that technically "creates".
                long sz = nf.getBody().getMaxAddress().getOffset() / 2 - tgt + 1;
                if (sz < minLeafWords) {
                    new DeleteFunctionCmd(a).applyTo(currentProgram);
                    rejected++;
                    continue;
                }
                created++;
            }
        }

        println(String.format(
            "recover%s: %d dispatch / %d switch tables; %d functions %s, "
                + "%d already functions, %d interior (case blocks), %d case targets left, %d rejected",
            dryRun ? " DRY RUN" : "", dispatchTables, switchTables, created,
            dryRun ? "would be created" : "created", alreadyFn, interior, skippedCase, rejected));
    }

    /**
     * Length of the callee-saved push run opening a C28x function, in pushes. Same test as
     * SeedFunctions pass B, so "is this a function entry" means one thing across the pipeline.
     */
    int prologueRun(long wi) {
        int n = 0; long p = wi;
        for (int k = 0; k < 8; k++) {
            int w = wordAt((p - base) * 2);
            if (w < 0) break;
            int hi8 = (w >> 8) & 0xff, lo8 = w & 0xff;
            boolean isPush =
                (lo8 == 0xBD) ||                          // MOVL *SP++,XARn
                (hi8 == 0xFE && (lo8 & 0x80) == 0) ||     // ADDB SP,#7bit (frame alloc)
                (hi8 == 0xE2 && lo8 == 0x03);             // MOV32 *SP++,RnH (2-word)
            if (isPush) { n++; p += (hi8 == 0xE2 ? 2 : 1); }
            else break;
        }
        return n;
    }

    void markTable(long tableStart, int run, DataType ptr) throws Exception {
        var listing = currentProgram.getListing();
        var refMgr = currentProgram.getReferenceManager();
        // clear any bogus instructions/data over the table extent first
        Address a0 = addr(tableStart), a1 = addr(tableStart + run * 2 - 1);
        listing.clearCodeUnits(a0, a1, false);
        for (int i = 0; i < run; i++) {
            long ew = tableStart + i * 2;
            Address ea = addr(ew);
            long tgt = pointerAt(ew);
            try { listing.createData(ea, ptr); } catch (Exception e) { /* leave as raw words */ }
            if (tgt >= 0) refMgr.addMemoryReference(ea, addr(tgt), RefType.DATA,
                                                    SourceType.USER_DEFINED, 0);
        }
        try {
            currentProgram.getSymbolTable().createLabel(
                addr(tableStart), String.format("jmptbl_%06x", tableStart), SourceType.USER_DEFINED);
        } catch (Exception e) { /* label collision — fine */ }
    }
}
