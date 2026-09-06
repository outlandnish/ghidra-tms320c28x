// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Make the C28x program and its CLA program one analysis instead of two.
//
// WHY. The CLA is a separate language, so its code has to live in a separate Ghidra program
// (ExportClaProgram.java) -- and Ghidra has no cross-program references. What the two
// programs DO share is the device's address map: 0x1486 in the CLA program is the same
// 0x1486 in the C28x program. So a name you work out on one side is already meaningful on
// the other; it just does not travel. This script carries it across.
//
// THE SHARED SURFACE, measured on the 2022 DIR CPU2 image:
//   0x1480-0x14FF  CLA1 to CPU MSGRAM   CLA writes 36 sites, reads 14 -- the CLA's OUTPUT
//   0x1500-0x157F  CPU to CLA1 MSGRAM   CLA reads 3, writes 0        -- the CLA's INPUT
//   LS/Dx window   CLA data             281 references
//   0xB00 / 0xB20  ADCARESULT/ADCBRESULT, ePWM
// The zero is the useful part: SPRUHM8K 3.11.1.5 gives the CLA write access to the "CLA to
// CPU" block and read-only access to "CPU to CLA", and the firmware matches exactly, which
// is what pins down which block is which.
//
// WHAT IT COPIES, and what it refuses to. Only symbols and data types someone actually
// applied -- a symbol whose SourceType is DEFAULT (`DAT_00001486`) carries no information
// and is skipped. Where both sides are named, SourceType decides:
//
//   DEFAULT < ANALYSIS < IMPORTED < USER_DEFINED
//
// a better-sourced name wins, an equally-sourced one that DIFFERS is reported as a conflict
// and neither side is touched. That ordering is what lets SetupClaProgram plant coarse
// region labels (ANALYSIS: `ADCARESULT`) as a fallback and still have SetupF28377D's precise
// register names (USER_DEFINED: `ADCA_RESULT_ADCRESULT0`) replace them on the first sync,
// while a name you typed by hand outranks everything. Copies carry the SOURCE's SourceType,
// so syncing back is a no-op and re-running changes nothing.
//
// It never writes over an address that holds an instruction in the target, so a C28x label
// can not land on CLA code or the reverse.
//
// Run it from either program; -Dc28x.sync.other names the other one.
//
// Properties (-Dname=value). On Windows headless pass these via JAVA_TOOL_OPTIONS:
// analyzeHeadless.bat drops everything after the `=` in a script argument.
//   c28x.sync.other   (path, REQUIRED)      the other program, by name or project path
//   c28x.sync.dir     (str,  default both)  both | push (this->other) | pull (other->this)
//   c28x.sync.lo      (word, default 0)     low end of the shared range
//   c28x.sync.hi      (word, default 0xBFFF) high end (the CLA reaches only the low 64K)
//   c28x.sync.types   (bool, default true)  carry data types as well as names
//   c28x.sync.dryRun  (bool, default false) report only
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;

public class SyncClaLabels extends GhidraScript {

    void promoteDashDArgs() {
        String[] args = getScriptArgs();
        if (args == null) return;
        boolean valued = false;
        for (String a : args)
            if (a != null && a.startsWith("-Dc28x.sync.") && a.indexOf('=') > 0) valued = true;
        if (valued)
            for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
                if (k.startsWith("c28x.sync.")) System.clearProperty(k);
        for (String a : args) {
            if (a == null || !a.startsWith("-D")) continue;
            String kv = a.substring(2);
            int eq = kv.indexOf('=');
            if (eq > 0) System.setProperty(kv.substring(0, eq), kv.substring(eq + 1));
        }
    }

    /** Depth-first search of the project for a program by path or bare name. */
    DomainFile find(DomainFolder f, String want) {
        for (DomainFile df : f.getFiles())
            if (df.getName().equals(want) || df.getPathname().equals(want)) return df;
        for (DomainFolder sub : f.getFolders()) {
            DomainFile r = find(sub, want);
            if (r != null) return r;
        }
        return null;
    }

    int copied = 0, typed = 0, conflicts = 0, skipped = 0;

    // Ghidra's own ordering, spelled out rather than relying on SourceType's comparison
    // helpers: a name carries more weight the more deliberate its origin.
    static int rank(SourceType s) {
        if (s == SourceType.USER_DEFINED) return 3;
        if (s == SourceType.IMPORTED) return 2;
        if (s == SourceType.ANALYSIS) return 1;
        return 0;                                    // DEFAULT
    }

    /**
     * Carry every applied name (and optionally data type) from `src` to `dst` over the range.
     * Both programs are word-addressed with the same map, so the offsets are interchangeable.
     */
    void carry(Program src, Program dst, long lo, long hi, boolean types, boolean dry) {
        SymbolTable st = src.getSymbolTable();
        Listing sl = src.getListing(), dl = dst.getListing();
        var sSpace = src.getAddressFactory().getDefaultAddressSpace();
        var dSpace = dst.getAddressFactory().getDefaultAddressSpace();

        for (long word = lo; word <= hi; word++) {
            if (monitor.isCancelled()) return;
            Address sa = sSpace.getAddress(word * 2);
            Symbol s = st.getPrimarySymbol(sa);
            if (s == null || s.getSource() == SourceType.DEFAULT) continue;

            Address da = dSpace.getAddress(word * 2);
            if (dst.getMemory().getBlock(da) == null) { skipped++; continue; }
            if (dl.getInstructionContaining(da) != null) { skipped++; continue; }

            Symbol d = dst.getSymbolTable().getPrimarySymbol(da);
            if (d != null && d.getName().equals(s.getName())) continue;   // already agreed
            if (d != null && rank(d.getSource()) >= rank(s.getSource())) {
                if (rank(d.getSource()) > 0) {
                    conflicts++;
                    println(String.format("  CONFLICT %05x: %s has \"%s\" (%s), %s has \"%s\" (%s)"
                        + " -- left alone", word, src.getName(), s.getName(), s.getSource(),
                        dst.getName(), d.getName(), d.getSource()));
                }
                continue;
            }

            println(String.format("  %05x  %s -> %s%s", word, s.getName(), dst.getName(),
                d == null ? "" : " (over " + d.getName() + ")"));
            copied++;
            if (dry) continue;
            try {
                if (d != null) d.delete();
                dst.getSymbolTable().createLabel(da, s.getName(), s.getSource());
            } catch (Exception e) {
                println("    could not label " + Long.toHexString(word) + ": " + e.getMessage());
                copied--;
                continue;
            }

            if (!types) continue;
            Data sd = sl.getDataAt(sa);
            if (sd == null || !sd.isDefined()) continue;
            Data dd = dl.getDataAt(da);
            if (dd != null && dd.isDefined()) continue;
            try {
                DataType dt = dst.getDataTypeManager().resolve(sd.getDataType(), null);
                dl.createData(da, dt);
                typed++;
            } catch (Exception e) { /* the target has conflicting data here; the name still landed */ }
        }
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        String otherName = System.getProperty("c28x.sync.other");
        if (otherName == null) {
            println("set -Dc28x.sync.other=<the other program's name or project path>");
            return;
        }
        String dir = System.getProperty("c28x.sync.dir", "both");
        long lo = Long.decode(System.getProperty("c28x.sync.lo", "0x0"));
        long hi = Long.decode(System.getProperty("c28x.sync.hi", "0xBFFF"));
        boolean types = !"false".equals(System.getProperty("c28x.sync.types", "true"));
        boolean dry = Boolean.getBoolean("c28x.sync.dryRun");

        var project = getState().getProject();
        if (project == null) { println("no project open"); return; }
        DomainFile df = find(project.getProjectData().getRootFolder(), otherName);
        if (df == null) { println("no program named \"" + otherName + "\" in this project"); return; }

        Program other = (Program) df.getDomainObject(this, true, false, monitor);
        int tx = -1;
        try {
            if (!dry) tx = other.startTransaction("SyncClaLabels");
            println(String.format("syncing %05x..%05x between %s and %s (%s)%s",
                lo, hi, currentProgram.getName(), other.getName(), dir, dry ? " [dry run]" : ""));

            if (dir.equals("both") || dir.equals("push")) {
                println("-- " + currentProgram.getName() + " -> " + other.getName());
                carry(currentProgram, other, lo, hi, types, dry);
            }
            if (dir.equals("both") || dir.equals("pull")) {
                println("-- " + other.getName() + " -> " + currentProgram.getName());
                carry(other, currentProgram, lo, hi, types, dry);
            }
        } finally {
            if (tx != -1) other.endTransaction(tx, true);
            if (!dry) df.save(monitor);
            other.release(this);
        }

        println("");
        println(String.format("%d label(s) %s, %d data type(s) carried, %d conflict(s) left alone,"
            + " %d address(es) not shared", copied, dry ? "would be copied" : "copied", typed,
            conflicts, skipped));
        if (conflicts > 0)
            println("A conflict means both sides were named and the names differ -- decide which is"
                + " right and rename the other by hand, then re-run.");
    }
}
