// Materialize a TI EABI compressed copy-table (__TI_auto_init / "rom_model") for C28x images.
//
// Newer (2026+) Tesla C28x firmwares copy their .ramfunc / .cinit sections at C-startup via a
// COPY TABLE instead of the memcpy-with-constant-args startup that MaterializeSections handles.
// The table is a list of 6-word records {size:u32, load:u32, run:u32}:
//   * size != 0  -> RAW copy: copy `size` words from flash `load` to RAM `run`.
//   * size == 0  -> handler dispatch: the load block starts with a handler index (*load); the
//                   compressed payload begins at load+1. This script implements the LZSS handler
//                   (the one the .ramfunc uses):
//                       read a 16-bit control word (LSB first). For each of its 16 bits:
//                         bit==1 -> literal: copy one word verbatim from src.
//                         bit==0 -> back-ref word W: len=(W&0xf)+2 (if ==0x11, len=nextWord+0x11),
//                                   off=(W>>4)&0xfff (if ==0xfff, END), copy len words from dest-1-off.
//
// The table is found by a structural scan (a run of >=3 consecutive valid records). Override with
// -Dc28x.ct.base=0xWORD. Materializes each record into RAM (splitting writes across block seams via
// convertToInitialized), disassembles the CODE run regions at their flash call-targets, and marks
// each record's flash LOAD image + the table itself as undefined2[] data so they stop decoding as
// code (the "halt_baddata" / wild-call noise). Idempotent. Run AFTER Setup/Seed, like MaterializeSections.
//
//@category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import java.util.*;

public class MaterializeCopyTable extends GhidraScript {
    AddressSpace space;
    Memory mem;
    long fStart, fEnd;          // flash word range (initialized high memory)
    ArrayList<Integer> lzOut;   // last LZSS output
    long lzSrcEnd;              // word after the last consumed LZSS source word

    long rdw(long w)  { try { return mem.getShort(space.getAddress(w * 2)) & 0xffffL; } catch (Exception e) { return -1L; } }
    long rd32(long w) { return (rdw(w + 1) << 16) | rdw(w); }
    Address wa(long w) { return space.getAddress(w * 2); }

    void lzss(long src) {
        lzOut = new ArrayList<>();
        boolean done = false; int guard = 0;
        while (!done && guard++ < 8_000_000) {
            long ctrl = rdw(src++);
            for (int b = 0; b < 16 && !done; b++) {
                if ((ctrl & 1L) == 1L) {
                    lzOut.add((int) rdw(src++));
                } else {
                    long W = rdw(src++);
                    int len = (int) ((W & 0xfL) + 2);
                    int off = (int) ((W >> 4) & 0xfffL);
                    if (len == 0x11) len = (int) (rdw(src++) + 0x11);
                    if (off == 0xfff) { done = true; break; }
                    int sp = lzOut.size() - 1 - off;
                    if (sp < 0) { done = true; break; }
                    for (int k = 0; k < len; k++) lzOut.add(lzOut.get(sp + k));
                }
                ctrl >>= 1;
                if (lzOut.size() > 400_000) done = true;
            }
        }
        lzSrcEnd = src;
    }

    boolean validRec(long size, long load, long run) {
        return load >= fStart && load <= fEnd && run <= 0x1bfffL && (size & 0xffffffffL) < 0x40000L;
    }

    // A real copy table is a run of >=3 valid {size,load,run} records, IMMEDIATELY followed by an
    // all-0xffffffff terminator record, and containing at least one handler-dispatched (size==0)
    // record whose *load is a small handler index (0..7). These three constraints reject the
    // coincidental short runs of flash data that a looser scan false-positives on (e.g. the CPU1
    // PMR images, which use memcpy-with-constants and have NO copy table at all).
    long detectTable() {
        long bestBase = -1; int bestCount = 0;
        for (long w = fStart; w <= fEnd - 24; w++) {
            int cnt = 0; boolean sawHandler = false;
            for (int i = 0; i < 256; i++) {
                long a = w + 6L * i, sz = rd32(a), ld = rd32(a + 2), rn = rd32(a + 4);
                if (ld == 0xffffffffL || !validRec(sz, ld, rn)) break;
                if (sz == 0) { if (rdw(ld) > 7) break; sawHandler = true; }
                cnt++;
            }
            boolean terminated = (rd32(w + 6L * cnt + 2) == 0xffffffffL);
            if (cnt >= 3 && terminated && sawHandler && cnt > bestCount) { bestCount = cnt; bestBase = w; }
            if (cnt >= 3) w += 6L * cnt; // skip past a found run
        }
        return bestBase;
    }

    void ensureInit(long w) {
        MemoryBlock blk = mem.getBlock(wa(w));
        if (blk != null && !blk.isInitialized()) {
            try { mem.convertToInitialized(blk, (byte) 0); } catch (Exception e) {}
        }
    }

    // clear any functions/code in [wordStart, wordStart+words) and stamp undefined2[] so it stops
    // decoding as code; drops phantom functions created over a load image and deletes stale
    // "Bad Instruction" error bookmarks now sitting on that data.
    void markData(long wordStart, long words) {
        if (words <= 0) return;
        long lo = wordStart, hi = wordStart + words - 1;
        Address s = wa(lo), e = wa(hi);
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSet set = new AddressSet(s, e);
        ArrayList<Address> entries = new ArrayList<>();
        for (Function f : fm.getFunctions(set, true)) entries.add(f.getEntryPoint());
        for (Address a : entries) {
            try { new ghidra.app.cmd.function.DeleteFunctionCmd(a).applyTo(currentProgram); } catch (Exception ex) {}
        }
        Listing listing = currentProgram.getListing();
        try { listing.clearCodeUnits(s, e, false); } catch (Exception ex) {}
        try {
            DataType u2 = Undefined2DataType.dataType;
            listing.createData(s, new ArrayDataType(u2, (int) words, u2.getLength()));
        } catch (Exception ex) { /* leave cleared/undefined if the array won't fit */ }
        var bm = currentProgram.getBookmarkManager();
        ArrayList<ghidra.program.model.listing.Bookmark> del = new ArrayList<>();
        var bit = bm.getBookmarksIterator("Error");
        while (bit.hasNext()) { var b = bit.next(); long w = b.getAddress().getOffset() / 2; if (w >= lo && w <= hi) del.add(b); }
        for (var b : del) bm.removeBookmark(b);
    }

    public void run() throws Exception {
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        mem = currentProgram.getMemory();

        // flash word range = initialized blocks at/above 0x80000 (word)
        fStart = Long.MAX_VALUE; fEnd = 0;
        for (MemoryBlock blk : mem.getBlocks()) {
            long s = blk.getStart().getOffset() / 2, e = blk.getEnd().getOffset() / 2;
            if (blk.isInitialized() && s >= 0x80000L) { fStart = Math.min(fStart, s); fEnd = Math.max(fEnd, e); }
        }
        if (fEnd == 0) { println("no initialized flash block >= 0x80000 found"); return; }

        String p = System.getProperty("c28x.ct.base");
        long tbase = (p != null) ? Long.decode(p.trim()) : detectTable();
        if (tbase < 0) { println("copy-table not found; pass -Dc28x.ct.base=0xWORD"); return; }
        println(String.format("flash 0x%05x-0x%05x ; copy table @ 0x%05x", fStart, fEnd, tbase));

        boolean dry = Boolean.getBoolean("c28x.ct.dryRun");
        ArrayList<long[]> allRuns = new ArrayList<>();   // {run, words} for every materialized record
        ArrayList<long[]> loadImgs = new ArrayList<>();  // {load, words}
        int nrec = 0; long totalWords = 0; long lastRec = tbase;
        for (int i = 0; i < 256; i++) {
            long a = tbase + 6L * i, size = rd32(a), load = rd32(a + 2), run = rd32(a + 4);
            if (load == 0xffffffffL || !validRec(size, load, run)) break;
            ArrayList<Integer> out; long loadWords;
            if (size != 0) {
                out = new ArrayList<>();
                for (long k = 0; k < size; k++) out.add((int) rdw(load + k));
                loadWords = size;
            } else {
                long h = rdw(load);
                lzss(load + 1);
                out = lzOut; loadWords = lzSrcEnd - load;
                if (out.isEmpty()) { println(String.format("  rec %2d run=%05x handler=%d -> 0 words, SKIP", i, run, h)); continue; }
            }
            println(String.format("  rec %2d: %s size=%08x load=%05x run=%05x len=0x%x",
                    i, (size != 0 ? "RAW " : "LZSS"), size, load, run, out.size()));
            if (!dry) {
                for (long w = run; w < run + out.size() + 1; w += 0x100) ensureInit(w);
                // clear any prior code/data in the run region so the bytes can be (re)written
                try { currentProgram.getListing().clearCodeUnits(wa(run), wa(run + out.size() - 1), false); } catch (Exception ex) {}
                for (int k = 0; k < out.size(); k++) mem.setShort(wa(run + k), (short) (int) out.get(k));
            }
            nrec++; totalWords += out.size();
            allRuns.add(new long[]{run, out.size()});
            loadImgs.add(new long[]{load, loadWords});
            lastRec = a + 6;
        }
        println("materialized " + nrec + " record(s), 0x" + Long.toHexString(totalWords) + " words");
        if (dry) return;

        // Classify + handle each materialized RUN region. A run holds CODE iff at least one address
        // in it has an incoming CALL/JUMP reference (from a flash LCR or another ramfunc) -- NOT by
        // address range. Sections copied into LS/D RAM can be float CONST POOLS or .cinit DATA with
        // zero code refs (e.g. an IEEE-754 pool copied to a run at 0x9200); disassembling those
        // yields halt_baddata / phantom functions. So: code runs are cleared and disassembled at
        // every call/jump target then bound to functions (following flow covers the bodies); data
        // runs are marked undefined2[] so they stay data.
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        int codeRuns = 0, dataRuns = 0, made = 0, totTargets = 0;
        for (long[] cr : allRuns) {
            long lo = cr[0], hi = cr[0] + cr[1] - 1;
            TreeSet<Long> entries = new TreeSet<>();
            AddressIterator it = rm.getReferenceDestinationIterator(new AddressSet(wa(lo), wa(hi)), true);
            while (it.hasNext()) {
                Address d = it.next();
                for (Reference r : rm.getReferencesTo(d)) {
                    RefType t = r.getReferenceType();
                    if (t.isCall() || t.isJump()) { entries.add(d.getOffset()); break; }
                }
            }
            if (entries.isEmpty()) { markData(lo, cr[1]); dataRuns++; continue; }  // DATA run (pool/.cinit)
            try { currentProgram.getListing().clearCodeUnits(wa(lo), wa(hi), false); } catch (Exception ex) {}
            for (long off : entries) new DisassembleCommand(space.getAddress(off), null, true).applyTo(currentProgram);
            for (long off : entries) {
                Address addr = space.getAddress(off);
                if (fm.getFunctionAt(addr) == null && new CreateFunctionCmd(addr).applyTo(currentProgram)) made++;
            }
            codeRuns++; totTargets += entries.size();
        }
        println(String.format("run regions: %d code (%d call/jump targets, %d functions bound), %d data",
                codeRuns, totTargets, made, dataRuns));

        // Mark the copy table + each record's flash LOAD image as data so they stop decoding as
        // tangled phantom functions ("unreachable block" / halt_baddata).
        //
        // Two layouts occur. When the table sits near flash-END (e.g. dir2026 @0xb7752), EVERYTHING
        // from the table to flash-end is data (table + const pools + LZSS load images + handler
        // tables) and there is NO executable flash beyond it -> a single blanket [table..end] mark is
        // both correct and maximally clean. But when the table sits EARLY (e.g. dir_pedal_dit0
        // @0x81f94), the bulk of executable flash lives BETWEEN the table and the tail load images,
        // so a blanket mark would ERASE all of it. Detect the layout by where the table sits: only
        // blanket-mark when the table is in the last 1/8 of flash; otherwise mark precisely (the
        // table extent + each record's own load-image extent), which never touches the executable
        // flash between load images. -Dc28x.ct.noTailData=true disables all of this.
        if (!Boolean.getBoolean("c28x.ct.noTailData")) {
            long flashLen = fEnd - fStart + 1;
            boolean tableNearEnd = (tbase - fStart) > (flashLen * 7L) / 8L;
            if (tableNearEnd) {
                markData(tbase, fEnd - tbase + 1);
                for (long[] li : loadImgs) if (li[0] < tbase) markData(li[0], li[1]);
                println("marked flash tail [0x" + Long.toHexString(tbase) + "-0x" + Long.toHexString(fEnd)
                        + "] + below-table load images as data (table near flash-end)");
            } else {
                markData(tbase, 6L * nrec + 6);                       // copy table records + terminator
                for (long[] li : loadImgs) markData(li[0], li[1]);    // each record's load image, precisely
                println("marked copy table @0x" + Long.toHexString(tbase) + " + " + loadImgs.size()
                        + " load image(s) as data (table early in flash; executable flash preserved)");
            }
        }
        println("NOTE: run FinalizeRamfuncs.java after analysis settles.");
    }
}
