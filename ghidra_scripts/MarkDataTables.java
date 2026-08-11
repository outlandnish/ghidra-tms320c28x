// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Find and mark FLOAT-CONSTANT data tables in a C28x firmware image.
//
// THE PROBLEM. Firmware embeds large tables of IEEE-754 float constants (gain curves,
// sine/cosine LUTs, calibration data) between/after functions. A linear or prologue/call
// seeded disassembler that wanders into one decodes the float words as bogus instructions,
// producing garbage code and Ghidra's red "bad instruction / conflicting data" blocks. The
// call-target byte-scan is also fooled: a float pair can look like an LCR/LC opcode, adding a
// spurious "call" into the table that makes the data look like a real function. This is DATA
// misread as code — the fix is markup, not a SLEIGH change.
//
// THE SIGNAL. The C28x stores a 32-bit float as two 16-bit words (low @ even, high @ odd).
// A float table is a run of word-pairs that are ALL "sane floats": nonzero, exponent in a
// normal range (≈1e-19 .. 1e19), not inf/NaN/denormal. Real code, decoded as float pairs,
// scores far lower (opcodes/operands rarely land in normal-float exponent territory). So a
// long run with a high sane-float fraction is a data table.
//
// POOL EXTENSION. A real compiler literal pool interleaves float constants with FIXED-POINT
// (Q-format) constants and zero padding — e.g. a 32-bit Q value like 0xFA25E350 reads as a
// huge/tiny "float" (exponent outside the sane range), so a float-only scan stops at every
// fixed-point word and leaves those sub-runs decoding as bogus code (Ghidra `halt_baddata`).
// So, once a sane-float run ANCHORS a pool, we grow the span in both directions across floats
// and across SMOOTH runs of fixed-point/zero constants — a run is "smooth" if its consecutive
// 32-bit values mostly repeat or change by <=40% (coefficient tables / LUTs), which UNdecoded
// code does not (its words jump erratically). Growth stops at a real instruction, inf/NaN,
// uninitialized memory, or a non-smooth (code-like) run. Float words are marked Float4, the
// rest Undefined4. Requires SeedFunctions first so genuine code is disassembled (a stop); the
// smoothness gate is what keeps undecoded/missing-opcode code regions from being eaten.
//
// CONSERVATIVE BY DESIGN. Marking real code as data is much worse than leaving a table
// unmarked, so a pool must be ANCHORED by a real sane-float run (minRun) and must not contain
// a referenced function's entry. Defaults err toward false negatives. Use dryRun first.
//
// Properties (-Dname=value):
//   c28x.dtbl.minRun     (int,   default 8)    min consecutive sane-float pairs to anchor a pool
//   c28x.dtbl.minFrac    (double,default 0.90) legacy sane-float fraction (unused when extend=true)
//   c28x.dtbl.extend     (bool,  default true) grow the pool across fixed-point/zero constants
//   c28x.dtbl.maxPool    (int,   default 8192) safety cap on pool length in word-pairs
//   c28x.dtbl.dryRun     (bool,  default false) report only; make no changes
//   c28x.dtbl.clearCode  (bool,  default true)  clear bogus instructions over the pool
//
// Pairs well with MarkJumpTables.java (pointer/jump tables) and SeedFunctions.java (which
// has an entropy gate but can't catch a low-entropy float table — this script is that gap).
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class MarkDataTables extends GhidraScript {
    long base, lo, hi;
    byte[] mem;
    boolean[] init;
    AddressSpace space;

    int wordAt(long byteOff) {
        if (byteOff < 0 || byteOff + 1 >= mem.length) return -1;
        if (init != null && (!init[(int)byteOff] || !init[(int)(byteOff+1)])) return -1;
        return (mem[(int)byteOff] & 0xff) | ((mem[(int)(byteOff+1)] & 0xff) << 8);
    }
    Address addr(long word) { return space.getAddress(word * 2); }

    // Is the float32 assembled from (lo@w, hi@w+1) a "sane" normal float?
    boolean saneFloat(long w) {
        long sb = (w - base) * 2;
        int loW = wordAt(sb), hiW = wordAt(sb + 2);
        if (loW < 0 || hiW < 0) return false;
        long bits = (((long) hiW) << 16) | (loW & 0xffff);
        if (bits == 0) return false;                 // 0.0 — common in code (padding), exclude
        int exp = (int) ((bits >> 23) & 0xff);
        return exp >= 0x40 && exp <= 0x9e;            // ~1e-19..1e19, excludes 0/denorm/inf/nan
    }

    // Finite constant word-pair: any float bits except inf/NaN (so it INCLUDES zero padding,
    // denormals, and the huge/tiny magnitudes a fixed-point / Q-format value shows as when
    // read as a float). This is the "still inside a literal pool" test used to grow a float
    // table across its fixed-point and zero neighbours (see run()).
    boolean finiteConst(long w) {
        long sb = (w - base) * 2;
        int loW = wordAt(sb), hiW = wordAt(sb + 2);
        if (loW < 0 || hiW < 0) return false;         // uninitialized -> stop the pool
        long bits = (((long) hiW) << 16) | (loW & 0xffff);
        int exp = (int) ((bits >> 23) & 0xff);
        return exp != 0xff;                           // finite; inf/NaN ends the pool
    }

    // Any DEFINED instruction stops pool growth, so genuine code is never absorbed — including
    // unreferenced functions (real C28x functions frequently have 0 xrefs: indirect/vectored
    // calls). This relies on SeedFunctions having disassembled real code first, so it presents
    // as instructions while a true literal pool remains undefined bytes. Bogus float-seed
    // "functions" are handled separately: their bytes are sane floats, so they fall inside the
    // anchor run and are cleared/removed there, not reached by extension.
    boolean realCode(long w) {
        return currentProgram.getListing().getInstructionContaining(addr(w)) != null;
    }

    // Signed 32-bit value of the word-pair (lo@w, hi@w+1).
    long signedVal(long w) {
        long sb = (w - base) * 2;
        int loW = wordAt(sb), hiW = wordAt(sb + 2);
        long bits = (((long) (hiW & 0xffff)) << 16) | (loW & 0xffff);
        return (int) bits;
    }

    // Is the non-float run [a,b) (word indices, step 2) "table-like"? Fixed-point coefficient
    // tables / LUTs vary SMOOTHLY (small relative deltas) or REPEAT; (undecoded) code decoded
    // as 32-bit values jumps erratically. This is what lets extension absorb a fixed-point
    // sub-table without also swallowing an undecoded-opcode code region. A lone value counts
    // as smooth (it is pool padding between float runs).
    boolean smoothRun(long a, long b) {
        int n = 0, ok = 0; long prev = 0; boolean have = false;
        for (long w = a; w + 1 < b; w += 2) {
            long v = signedVal(w);
            if (have) {
                long d = Math.abs(v - prev);
                long mag = Math.max(Math.abs(prev), Math.abs(v));
                if (d == 0 || d <= 0x20000L || d * 5 <= 2 * mag) ok++;  // repeat, small abs, or <=40%
                n++;
            }
            prev = v; have = true;
        }
        return n == 0 || ok * 4 >= n * 3;      // >=75% smooth transitions (or a single value)
    }

    @Override
    public void run() throws Exception {
        int minRun = Integer.getInteger("c28x.dtbl.minRun", 8);
        double minFrac = Double.parseDouble(System.getProperty("c28x.dtbl.minFrac", "0.90"));
        boolean dryRun = Boolean.getBoolean("c28x.dtbl.dryRun");
        boolean clearCode = Boolean.parseBoolean(System.getProperty("c28x.dtbl.clearCode", "true"));

        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory memory = currentProgram.getMemory();
        // largest initialized block = the loaded image (see SeedFunctions for why)
        MemoryBlock blk = null; long bestLen = -1;
        for (MemoryBlock b : memory.getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; blk = b; }
        }
        if (blk == null) { println("no initialized block"); return; }
        Address start = blk.getStart(), end = blk.getEnd();
        base = start.getOffset() / 2;
        long nbytes = end.getOffset() - start.getOffset() + 1;
        mem = new byte[(int) nbytes];
        init = new boolean[(int) nbytes];
        var initSet = memory.getLoadedAndInitializedAddressSet().intersect(
            currentProgram.getAddressFactory().getAddressSet(start, end));
        for (var rng : initSet) {
            int off = (int)(rng.getMinAddress().getOffset() - start.getOffset());
            int len = (int)(rng.getMaxAddress().getOffset() - rng.getMinAddress().getOffset() + 1);
            byte[] buf = new byte[len]; memory.getBytes(rng.getMinAddress(), buf);
            System.arraycopy(buf, 0, mem, off, len);
            for (int i = off; i < off + len; i++) init[i] = true;
        }
        long nwords = nbytes / 2;
        lo = base; hi = base + nwords - 1;

        DataType f4 = new Float4DataType();
        DataType u4 = ghidra.program.model.data.Undefined4DataType.dataType;
        int maxPool = Integer.getInteger("c28x.dtbl.maxPool", 8192);
        boolean extend = Boolean.parseBoolean(System.getProperty("c28x.dtbl.extend", "true"));
        int tables = 0, entriesMarked = 0;
        var fm = currentProgram.getFunctionManager();
        var listing = currentProgram.getListing();

        long w = base, floor = lo;                      // floor = end of last pool (no re-entry)
        while (w + 1 <= hi) {
            // ANCHOR: a pure run of sane IEEE-754 floats proves a real constant pool is here.
            int run = 0; long p = w;
            while (p + 1 <= hi && saneFloat(p)) { run++; p += 2; }
            if (run >= minRun) {
                long tableStart = w, spanEnd = p;       // [tableStart, spanEnd) sane floats so far
                if (extend) {
                    // A compiler literal pool interleaves floats with fixed-point / Q-format
                    // constants and zero padding. Anchored on the confirmed float run, grow the
                    // span across floats and SMOOTH fixed-point/zero runs. Stop at a real
                    // instruction, inf/NaN, uninitialized memory, or a NON-smooth fixed-point
                    // run (erratic = undecoded code, must not be marked as data).
                    boolean grow = true;                // right
                    while (grow && spanEnd + 1 <= hi && (spanEnd - tableStart) < (long) maxPool * 2) {
                        if (realCode(spanEnd)) break;
                        if (saneFloat(spanEnd)) { spanEnd += 2; continue; }
                        if (!finiteConst(spanEnd)) break;
                        long r = spanEnd;
                        while (r + 1 <= hi && finiteConst(r) && !saneFloat(r) && !realCode(r)) r += 2;
                        if (smoothRun(spanEnd, r)) spanEnd = r; else grow = false;
                    }
                    boolean grow2 = true;               // left (never below floor)
                    while (grow2 && tableStart - 2 >= floor) {
                        long c = tableStart - 2;
                        if (realCode(c)) break;
                        if (saneFloat(c)) { tableStart = c; continue; }
                        if (!finiteConst(c)) break;
                        long l = c;
                        while (l - 2 >= floor && finiteConst(l - 2) && !saneFloat(l - 2) && !realCode(l - 2)) l -= 2;
                        if (smoothRun(l, c + 2)) tableStart = l; else grow2 = false;
                    }
                }
                int sane = 0, total = 0;
                for (long e = tableStart; e + 1 < spanEnd; e += 2) { total++; if (saneFloat(e)) sane++; }
                // SAFETY: if a REAL (referenced) function's ENTRY sits inside the span we grew
                // into code — back off and leave it. 0-xref seeds don't count (bogus float seeds).
                boolean realCodeInside = false;
                for (var fn = fm.getFunctions(addr(tableStart), true); fn.hasNext(); ) {
                    Function f = fn.next();
                    long fe = f.getEntryPoint().getOffset() / 2;
                    if (fe >= spanEnd) break;            // past the span
                    if (fe < tableStart) continue;
                    int xr = 0;
                    for (var ri = currentProgram.getReferenceManager()
                            .getReferencesTo(f.getEntryPoint()); ri.hasNext(); ) { ri.next(); xr++; }
                    if (xr > 0) { realCodeInside = true; break; }   // a genuinely-called fn = real code
                }
                if (!realCodeInside) {
                    // Also back off if any referenced function's INSTRUCTIONS reach into the span
                    // (a real function whose sane-float-looking body words landed in the anchor
                    // run). Entry-only checking misses those; this protects the function body.
                    for (var ii = listing.getInstructions(
                            currentProgram.getAddressFactory().getAddressSet(addr(tableStart), addr(spanEnd - 1)), true);
                            ii.hasNext(); ) {
                        Function f = fm.getFunctionContaining(ii.next().getAddress());
                        if (f == null) continue;                 // stray/bogus instruction — ok to clear
                        int xr = 0;
                        for (var ri = currentProgram.getReferenceManager()
                                .getReferencesTo(f.getEntryPoint()); ri.hasNext() && xr < 1; ) { ri.next(); xr++; }
                        if (xr > 0) { realCodeInside = true; break; }
                    }
                }
                if (!realCodeInside) {
                    tables++;
                    println(String.format("pool @0x%x  %d words  (%d float / %d fixed-or-zero)",
                        tableStart, (spanEnd - tableStart), sane, total - sane));
                    if (!dryRun) {
                        // remove any bogus (0-xref) false-seed functions sitting in the pool
                        java.util.List<Address> kill = new java.util.ArrayList<>();
                        for (var fn = fm.getFunctions(addr(tableStart), true); fn.hasNext(); ) {
                            Function f = fn.next();
                            if (f.getEntryPoint().getOffset() / 2 >= spanEnd) break;
                            kill.add(f.getEntryPoint());
                        }
                        for (Address k : kill) fm.removeFunction(k);
                        if (clearCode) listing.clearCodeUnits(addr(tableStart), addr(spanEnd - 1), false);
                        // floats -> Float4; fixed-point / zero -> Undefined4 (each = 2 words)
                        for (long e = tableStart; e + 1 < spanEnd; e += 2) {
                            try { listing.createData(addr(e), saneFloat(e) ? f4 : u4); entriesMarked++; }
                            catch (Exception ex) {}
                        }
                        try { currentProgram.getSymbolTable().createLabel(addr(tableStart),
                            String.format("ctbl_%06x", tableStart), ghidra.program.model.symbol.SourceType.USER_DEFINED); }
                        catch (Exception ex) {}
                    }
                }
                floor = spanEnd;                        // don't let a later pool re-enter this one
                w = Math.max(spanEnd, w + 1);
            } else {
                w++;
            }
        }
        println(String.format("%s: %d constant pools, %d entries marked%s",
            dryRun ? "DRY RUN" : "done", tables, entriesMarked, dryRun ? " (no changes)" : ""));
    }
}
