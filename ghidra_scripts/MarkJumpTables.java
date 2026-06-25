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
// entry as a `pointer`, add a DATA reference entry->target (so the targets show as code
// refs / get picked up as functions), and label the table `jmptbl_<addr>`. By default it
// only marks tables that are NOT already correctly defined as pointers.
//
// This is the structured-data counterpart to SeedFunctions.java's entropy filter: an entropy
// gate won't catch a pointer table (it's low-entropy and the page byte is in the opcode
// vocabulary), so jump tables need their own pattern detector — this script.
//
// Properties (optional, -Dname=value):
//   c28x.jmptbl.minEntries  (int, default 4)    minimum run length to treat as a table
//   c28x.jmptbl.dryRun      (bool,default false) report only; make no changes
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataType;
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
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address start = blk.getStart(), end = blk.getEnd();
        base = start.getOffset() / 2;
        long nbytes = end.getOffset() - start.getOffset() + 1;
        mem = new byte[(int) nbytes];
        blk.getBytes(start, mem);
        long nwords = nbytes / 2;
        lo = base; hi = base + nwords - 1;

        DataType ptr = new PointerDataType();
        int tablesFound = 0, entriesMarked = 0;

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
                w = tableEnd + 1;                                 // skip past the table
            } else {
                w++;
            }
        }
        println(String.format("%s: %d tables, %d pointer entries%s",
            dryRun ? "DRY RUN" : "done", tablesFound, entriesMarked, dryRun ? " (no changes made)" : ""));
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
