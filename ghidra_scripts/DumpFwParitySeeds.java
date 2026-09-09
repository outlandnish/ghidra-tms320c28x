// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Extract data-side seed addresses for the fw-parity BOOTSTRAP sweep. Emits a
// TSV of `<word_addr_hex>\t<source>\t<label>` lines suitable for
// `run_fw_parity_bootstrap -Seeds`.
//
// Sources, in order (all byte-level extractions so their correctness does NOT
// depend on our SLEIGH being right about anything):
//
//   (crt)  Every function whose name contains `c_int00`. SeedFunctions signal D
//          finds these by scanning for the `MOV @SP,#16bit` (0x28AD) + boot-mode
//          register idiom -- literal 16-bit word matches, no decode.
//
//   (pie)  The 32-bit function pointers in the PIE vector table INITIALIZER.
//          MarkComponentRegistry labels the initializer's base as
//          `PieVectTableInit`; from there we walk 32-bit words forward while
//          they still look like code addresses (word_addr >= flashLo). Each is
//          a seed. This is a byte-level walk of raw pointer-store contents; no
//          instruction decoding is involved.
//
//   (registry) Function-pointer table entries created by MarkComponentRegistry
//              from the flash-side dispatch registry initializer -- same rules.
//              Emitted as `registry` so they can be filtered out if a
//              particular sweep only wants the strongly-typed PIE + CRT seeds.
//
// Output: -Dc28x.parity.seeds.out=<path> (default `seeds.tsv` in cwd).
//
// The seed list is INTENTIONALLY minimal: BFS will expand it via dis2000 call
// targets. A larger seed set doesn't help coverage; it just amortizes fewer BFS
// hops. What we CAN'T recover via BFS is anything reached only through an
// indirect call (`LCR *XARn`) that a runtime dispatcher fills in -- for those,
// the registry pass is the only route.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import java.io.FileWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DumpFwParitySeeds extends GhidraScript {

    @Override
    public void run() throws Exception {
        String out = getProp("c28x.parity.seeds.out", "seeds.tsv");

        // (crt) Symbols whose name contains c_int00. There can be several per
        // image (multi-runtime bootloader linkings); keep them all.
        Set<Long> crt = new LinkedHashSet<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String n = f.getName();
            if (n != null && n.toLowerCase().contains("c_int00"))
                crt.add(f.getEntryPoint().getOffset() / 2);
        }

        // (pie) PieVectTableInit label. MarkComponentRegistry sets this on the
        // 32-bit-pointer run in flash. Walk it while entries look like code
        // pointers within initialized flash.
        Set<Long> pie = new LinkedHashSet<>();
        Address pieBase = firstLabelAddr("PieVectTableInit");
        if (pieBase != null) {
            long flashLo = flashLo();
            long flashHi = flashHi();
            long w = pieBase.getOffset() / 2;
            long e = pieBase.getAddressSpace().getMaxAddress().getOffset() / 2;
            for (long k = w; k + 1 <= e; k += 2) {
                long v = readU32(k);
                if (v < flashLo || v > flashHi) break;
                pie.add(v);
            }
        }

        // (registry) Every function that MarkComponentRegistry created and
        // named. The naming convention it uses varies (`FUN_...` renamed to a
        // known ISR name, or an ISR-only heuristic label), so we take a broader
        // signal: functions that a `LCR *XARn`-style call cannot reach via
        // static analysis but which have an inbound DATA reference from flash
        // (i.e. a function-pointer store put their address into some dispatch
        // record). Cheap proxy: count references and filter for DATA refs from
        // flash. Skipping this if it grows the seed set into thousands is fine
        // -- BFS will find the interesting ones from the registry-rooted ones.
        Set<Long> registry = new LinkedHashSet<>();
        long flashLo = flashLo();
        long flashHi = flashHi();
        for (Symbol s : currentProgram.getSymbolTable().getSymbolIterator()) {
            if (s == null) continue;
            Address a = s.getAddress();
            if (a == null) continue;
            long w = a.getOffset() / 2;
            if (w < flashLo || w > flashHi) continue;
            if (currentProgram.getFunctionManager().getFunctionAt(a) == null) continue;
            // Cross-check: at least one inbound data reference from flash.
            boolean hasDataRef = false;
            for (var ref : s.getReferences()) {
                if (ref == null || !ref.getReferenceType().isData()) continue;
                long fromW = ref.getFromAddress().getOffset() / 2;
                if (fromW >= flashLo && fromW <= flashHi) { hasDataRef = true; break; }
            }
            if (hasDataRef) registry.add(w);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("# word_addr\tsource\tlabel\n");
        int nc = 0, np = 0, nr = 0;
        for (long w : crt) { sb.append(String.format("0x%x\tcrt\t%s%n", w, nameAt(w))); nc++; }
        for (long w : pie) {
            if (crt.contains(w)) continue;  // reset vector; already covered
            sb.append(String.format("0x%x\tpie\t%s%n", w, nameAt(w))); np++;
        }
        for (long w : registry) {
            if (crt.contains(w) || pie.contains(w)) continue;
            sb.append(String.format("0x%x\tregistry\t%s%n", w, nameAt(w))); nr++;
        }
        try (FileWriter fw = new FileWriter(out)) { fw.write(sb.toString()); }
        println(String.format("DumpFwParitySeeds: %d crt + %d pie + %d registry = %d unique -> %s",
            nc, np, nr, nc + np + nr, out));
    }

    private Address firstLabelAddr(String name) {
        var iter = currentProgram.getSymbolTable().getSymbols(name);
        while (iter.hasNext()) {
            Symbol s = iter.next();
            if (s != null && s.getAddress() != null) return s.getAddress();
        }
        return null;
    }

    private long readU32(long wordAddr) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(wordAddr * 2);
            return currentProgram.getMemory().getInt(a) & 0xFFFFFFFFL;
        } catch (Exception e) {
            return -1L;
        }
    }

    private long flashLo() {
        long lo = Long.MAX_VALUE;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            long s = b.getStart().getOffset() / 2;
            if (s >= 0x80000L && s < lo) lo = s;
        }
        return lo == Long.MAX_VALUE ? 0x80000L : lo;
    }

    private long flashHi() {
        long hi = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            long e = b.getEnd().getOffset() / 2;
            if (e >= 0x80000L && e > hi) hi = e;
        }
        return hi;
    }

    private String nameAt(long wordAddr) {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(wordAddr * 2);
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
        return s == null ? "" : s.getName();
    }

    private String getProp(String key, String dflt) {
        String v = System.getProperty(key);
        if (v != null) return v;
        String[] args = getScriptArgs();
        if (args != null) {
            String pfx = "-D" + key + "=";
            for (String a : args) if (a != null && a.startsWith(pfx)) return a.substring(pfx.length());
        }
        return dflt;
    }
}
