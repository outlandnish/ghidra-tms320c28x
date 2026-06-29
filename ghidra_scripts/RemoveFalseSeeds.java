// Remove false-seed functions that a prologue/call scan placed on DATA.
//
// SeedFunctions (and Ghidra's own analysis) can create a function at an address that is
// really inside a data table — a prologue byte pattern, or a data word that looks like an
// LCR/LC call target, lands in a float/coefficient/string table. Such a "function"
// immediately hits an undecodable word and decompiles to a bare halt_baddata stub, leaving a
// red error block on data. MarkDataTables/MarkJumpTables convert the recognizable table
// shapes to data, but irregular data tables (e.g. a 0x87xx-clustered coefficient table) slip
// through. This script removes the remaining bogus seeds directly.
//
// CRITERIA (all required, conservative — only kills clearly-bogus seeds):
//   - the function has ZERO references to its entry (nothing calls/branches to it), AND
//   - it decompiles to halt_baddata (truncates), AND
//   - it is small (<= maxBodyWords) — a real 0-xref entry (reset/init, vector-reached) is
//     usually large and decompiles cleanly, so the truncation+small+0-xref combo is the
//     signature of a data false-seed, not real code.
// On match: remove the function and clear its (bogus) instructions back to undefined data.
//
// A real reset/init routine reached only via the reset vector has 0 xrefs but decompiles
// CLEANLY (no halt_baddata), so it is never removed. Run after SeedFunctions / the Mark*
// scripts. Use dryRun first.
//
// Properties (-Dname=value):
//   c28x.rmseed.maxBodyWords (int, default 64)   only remove seeds whose body is <= this
//   c28x.rmseed.dryRun       (bool,default false) report only; make no changes
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import java.util.*;

public class RemoveFalseSeeds extends GhidraScript {
    @Override
    public void run() throws Exception {
        int maxBody = Integer.getInteger("c28x.rmseed.maxBodyWords", 64);
        boolean dryRun = Boolean.getBoolean("c28x.rmseed.dryRun");

        var fm = currentProgram.getFunctionManager();
        var listing = currentProgram.getListing();
        var refMgr = currentProgram.getReferenceManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // collect candidates first (don't mutate while iterating the function manager)
        List<Function> kill = new ArrayList<>();
        int scanned = 0, zeroXref = 0;
        for (var it = fm.getFunctions(true); it.hasNext(); ) {
            Function f = it.next();
            scanned++;
            // 0 references to entry?
            int xr = 0;
            for (var ri = refMgr.getReferencesTo(f.getEntryPoint()); ri.hasNext(); ) { ri.next(); xr++; }
            if (xr != 0) continue;
            zeroXref++;
            long bodyWords = f.getBody().getNumAddresses() / 2;
            if (bodyWords > maxBody) continue;            // large 0-xref fn = likely real (vector-reached)
            DecompileResults r = decomp.decompileFunction(f, 8, monitor);
            boolean trunc = r != null && r.getDecompiledFunction() != null
                          && r.getDecompiledFunction().getC().contains("halt_baddata");
            if (trunc) kill.add(f);
        }

        println(String.format("scanned %d fns, %d with 0 xrefs, %d match (0-xref + truncating + <=%d words)",
            scanned, zeroXref, kill.size(), maxBody));
        for (Function f : kill) {
            long w = f.getEntryPoint().getOffset() / 2;
            println(String.format("  %s 0x%x  (%d words)",
                dryRun ? "would remove" : "removing", w, f.getBody().getNumAddresses() / 2));
            if (!dryRun) {
                Address bmin = f.getBody().getMinAddress(), bmax = f.getBody().getMaxAddress();
                fm.removeFunction(f.getEntryPoint());
                listing.clearCodeUnits(bmin, bmax, false);   // back to undefined data
            }
        }
        println(dryRun ? "DRY RUN — no changes" : ("removed " + kill.size() + " false-seed functions"));
    }
}
