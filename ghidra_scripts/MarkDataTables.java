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
// CONSERVATIVE BY DESIGN. Marking real code as data is much worse than leaving a table
// unmarked, so this requires a HIGH sane-float fraction over a real-length run AND that the
// run is NOT inside a defined function. Defaults err toward false negatives. Use dryRun first.
//
// Properties (-Dname=value):
//   c28x.dtbl.minRun     (int,   default 8)    min consecutive sane-float word-pairs
//   c28x.dtbl.minFrac    (double,default 0.90) min sane-float fraction over the run
//   c28x.dtbl.dryRun     (bool,  default false) report only; make no changes
//   c28x.dtbl.clearCode  (bool,  default true)  clear bogus instructions over the table
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
        int tables = 0, entriesMarked = 0;
        var fm = currentProgram.getFunctionManager();
        var listing = currentProgram.getListing();

        long w = base;
        while (w + 1 <= hi) {
            // extend a run of sane-float pairs from w
            int run = 0; long p = w;
            while (p + 1 <= hi && saneFloat(p)) { run++; p += 2; }
            if (run >= minRun) {
                // tolerance pass: allow a few non-sane within the span but require minFrac overall.
                // (We already counted a pure run; extend over small gaps.)
                long spanEnd = p;                       // exclusive (word index past run)
                // try to absorb a trailing few words if the overall fraction stays high
                int sane = run, total = run;
                long q = p;
                while (q + 1 <= hi) {
                    boolean s = saneFloat(q);
                    if ((sane + (s?1:0)) < minFrac * (total + 1)) break;
                    total++; if (s) { sane++; spanEnd = q + 2; }
                    q += 2;
                }
                long tableStart = w, tableWords = spanEnd - w;
                // SAFETY: skip only if a REAL (referenced) function overlaps the run. A
                // function with 0 xrefs inside the run is itself a data false-seed (the
                // call-byte-scan mistook float bytes for an LCR), so it must NOT block
                // marking — those are exactly the bogus seeds we want to replace with data.
                boolean realCodeInside = false;
                for (var fn = fm.getFunctions(addr(tableStart), true); fn.hasNext(); ) {
                    Function f = fn.next();
                    long fe = f.getEntryPoint().getOffset() / 2;
                    if (fe >= spanEnd) break;            // past the run
                    if (fe < tableStart) continue;
                    int xr = 0;
                    for (var ri = currentProgram.getReferenceManager()
                            .getReferencesTo(f.getEntryPoint()); ri.hasNext(); ) { ri.next(); xr++; }
                    if (xr > 0) { realCodeInside = true; break; }   // a genuinely-called fn = real code
                }
                if (!realCodeInside) {
                    tables++;
                    println(String.format("float-table @0x%x  %d words  (%.0f%% sane over %d pairs)",
                        tableStart, tableWords, 100.0*sane/total, total));
                    if (!dryRun) {
                        // remove any bogus (0-xref) false-seed functions sitting in the table
                        java.util.List<Address> kill = new java.util.ArrayList<>();
                        for (var fn = fm.getFunctions(addr(tableStart), true); fn.hasNext(); ) {
                            Function f = fn.next();
                            if (f.getEntryPoint().getOffset() / 2 >= spanEnd) break;
                            kill.add(f.getEntryPoint());
                        }
                        for (Address k : kill) fm.removeFunction(k);
                        if (clearCode) listing.clearCodeUnits(addr(tableStart), addr(spanEnd - 1), false);
                        // define as Float4 array (each = 2 words)
                        for (long e = tableStart; e + 1 < spanEnd; e += 2) {
                            try { listing.createData(addr(e), f4); entriesMarked++; } catch (Exception ex) {}
                        }
                        try { currentProgram.getSymbolTable().createLabel(addr(tableStart),
                            String.format("ftbl_%06x", tableStart), ghidra.program.model.symbol.SourceType.USER_DEFINED); }
                        catch (Exception ex) {}
                    }
                }
                w = spanEnd;
            } else {
                w++;
            }
        }
        println(String.format("%s: %d float tables, %d Float4 entries%s",
            dryRun ? "DRY RUN" : "done", tables, entriesMarked, dryRun ? " (no changes)" : ""));
    }
}
