// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Which functions in a headerless C28x image are actually REACHABLE from reset?
//
// This is the question the image-setup guide asks you to answer by hand before chasing an
// un-materialized section: "is the flash code that references it reachable from _c_int00?" On a
// partial dump that used to be unanswerable, because the reset vector's sector is missing and
// _c_int00 was never found. SeedFunctions signal D recovers it, so the BFS can finally be run --
// and it separates the two things that look identical in the listing:
//
//   * a function nothing reaches because the image genuinely never runs it (dead flash left by
//     the linker, an unused library member) -- do NOT chase it, and
//   * a function nothing reaches because a REFERENCE is missing (its section was never
//     materialized, its caller is a jump table we haven't marked, its address only ever appears
//     inside a const table) -- these are the real analysis gaps, and they are worth chasing.
//
// The report separates them by asking, for every unreachable function, whether anything points at
// it at all:
//
//   UNREACHABLE, NO REFS AT ALL   -- nothing in the image mentions this address. On an image whose
//                                    data initialization has been replayed this is most likely dead
//                                    flash; on one where it has NOT, read the warning below first.
//   UNREACHABLE, DATA REFS ONLY   -- its address is stored somewhere but never called from
//                                    reachable code: a fn-ptr table, an ISR vector, a .cinit
//                                    record that installs it at runtime. Usually LIVE code whose
//                                    call edge is indirect -- the highest-value bucket.
//   UNREACHABLE, CALLED ONLY BY   -- called, but only by other unreachable functions: an entire
//   UNREACHABLE CODE                 orphaned component. Follow it to its root, which is usually
//                                    one of the DATA-REFS-ONLY entries above.
//
// READ THIS BEFORE BELIEVING A LOW REACHABLE PERCENTAGE. A static call graph only sees edges that
// exist as REFERENCES, and on a component/task-dispatch firmware most edges do not: the dispatcher
// calls through a function-pointer registry in RAM that `.cinit` populates AT RUNTIME. Until that
// data initialization is replayed (EmulateStartup, or Materialize*), those pointers are just words
// in a flash table, no reference exists, and genuinely live handlers land in NO-REFS-AT-ALL.
//
// Measured on an F28377D application image straight out of the pipeline: 53 of 2124 functions
// reachable (2.5%), with a 1371-word function that had been confirmed live by hand sitting in
// NO-REFS-AT-ALL. Nothing was dead -- the registry had simply never been filled in. So the script
// WARNS when the reachable fraction is implausibly low and tells you to replay startup first.
// Treat a low number as "my reference graph is incomplete", never as "this firmware is mostly dead".
//
// ROOTS. External entry points (signal D registers _c_int00 as one), plus anything named
// _c_int00*/main/reset*, plus -Dc28x.reach.roots=0xW,0xW. Interrupt handlers are a deliberate
// second class: on a partial dump the PIE vector table often is not in the image, so ISRs are
// legitimately unreachable by call graph while being very much live. They surface as
// DATA-REFS-ONLY rather than being silently counted as dead.
//
// TRAVERSAL follows CALL and JUMP references, which on this target includes the byte-scanned
// call-site refs SeedFunctions adds, so the graph is populated even where flow analysis stopped.
// Indirect calls (LCR *XARn) have no edge by construction -- that is exactly why the DATA-REFS
// bucket exists rather than being folded into "dead".
//
// Read-only: this script reports and bookmarks, it never deletes or renames. Run it AFTER the
// rest of the pipeline has settled (post-FinalizeRamfuncs), or the un-materialized sections it is
// meant to help you find will dominate the output.
//
// Properties:
//   c28x.reach.roots       (csv,  default "")     extra root word addresses, e.g. 0x82000,0x88000
//   c28x.reach.list        (int,  default 40)     how many functions to list per bucket
//   c28x.reach.bookmark    (bool, default false)  drop an Analysis bookmark on each unreachable fn
//   c28x.reach.out         (path, default none)   write the full classification to a file
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import java.util.*;

public class ReachabilityReport extends GhidraScript {

    // run_ghidra_script / the MCP bridge deliver -Dkey=value as getScriptArgs(), NOT as JVM system
    // properties, so the c28x.reach.* overrides silently no-op over MCP/headless. Promote any
    // -Dkey=value (or bare -Dkey -> "true") script arg to a real property first.
    // Clear first: system properties are JVM-global and survive between script runs in one Ghidra
    // session, so a flag passed once would stay set for every later run in that session.
    void promoteDashDArgs() {
        for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
            if (k.startsWith("c28x.reach.")) System.clearProperty(k);
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String a : args) {
            if (a == null || !a.startsWith("-D")) continue;
            String kv = a.substring(2);
            int eq = kv.indexOf('=');
            if (eq > 0) System.setProperty(kv.substring(0, eq), kv.substring(eq + 1));
            else if (!kv.isEmpty()) System.setProperty(kv, "true");
        }
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        var fm = currentProgram.getFunctionManager();
        var rm = currentProgram.getReferenceManager();
        int listN = Integer.getInteger("c28x.reach.list", 40);

        // --- collect every function up front -------------------------------------------
        TreeMap<Long,Function> all = new TreeMap<>();
        for (Function f : fm.getFunctions(true)) all.put(f.getEntryPoint().getOffset() / 2, f);
        if (all.isEmpty()) { println("no functions -- run SeedFunctions first."); return; }

        // --- roots ----------------------------------------------------------------------
        TreeSet<Long> roots = new TreeSet<>();
        for (AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator(); it.hasNext(); ) {
            Address a = it.next();
            if (fm.getFunctionAt(a) != null) roots.add(a.getOffset() / 2);
        }
        // Match on CONTAINS, not startsWith: an image analysed by hand before signal D existed
        // usually carries a module-prefixed name like `<prefix>_c_int00`, still the reset entry.
        for (Map.Entry<Long,Function> e : all.entrySet()) {
            String n = e.getValue().getName();
            String lower = n.toLowerCase();
            if (lower.contains("c_int00") || n.equals("main") || lower.startsWith("reset"))
                roots.add(e.getKey());
        }
        String extra = System.getProperty("c28x.reach.roots", "").trim();
        if (!extra.isEmpty())
            for (String s : extra.split(","))
                if (!s.trim().isEmpty()) roots.add(Long.decode(s.trim()));
        // keep only roots that really are functions
        roots.removeIf(w -> !all.containsKey(w));

        if (roots.isEmpty()) {
            println("NO ROOTS. Nothing is registered as an entry point and no _c_int00/main was found.");
            println("Run SeedFunctions (signal D recovers _c_int00 and registers it), or pass");
            println("-Dc28x.reach.roots=0xWORD. Without a root, reachability is undefined -- refusing");
            println("to report every function as dead.");
            return;
        }
        println("roots (" + roots.size() + "):");
        for (long r : roots) println(String.format("  %05x  %s", r, all.get(r).getName()));

        // --- BFS over call/jump edges ---------------------------------------------------
        TreeSet<Long> live = new TreeSet<>();
        ArrayDeque<Long> queue = new ArrayDeque<>(roots);
        live.addAll(roots);
        while (!queue.isEmpty()) {
            Function f = all.get(queue.poll());
            if (f == null) continue;
            // only addresses that actually carry a reference (whole-body iteration is far slower)
            for (AddressIterator ai = rm.getReferenceSourceIterator(f.getBody(), true); ai.hasNext(); ) {
                Address from = ai.next();
                for (Reference r : rm.getReferencesFrom(from)) {
                    RefType t = r.getReferenceType();
                    if (!t.isCall() && !t.isJump()) continue;
                    long tw = r.getToAddress().getOffset() / 2;
                    // a jump inside the same body is not a new function
                    if (all.containsKey(tw) && live.add(tw)) queue.add(tw);
                }
            }
        }

        // --- classify the unreachable ---------------------------------------------------
        ArrayList<long[]> noRefs = new ArrayList<>();      // {word, size}
        ArrayList<long[]> dataRefs = new ArrayList<>();
        ArrayList<long[]> deadCallers = new ArrayList<>();
        for (Map.Entry<Long,Function> e : all.entrySet()) {
            long w = e.getKey();
            if (live.contains(w)) continue;
            Function f = e.getValue();
            long size = f.getBody().getNumAddresses() / 2;
            boolean anyCodeRef = false, anyDataRef = false;
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                RefType t = r.getReferenceType();
                if (t.isCall() || t.isJump()) anyCodeRef = true;
                else anyDataRef = true;
            }
            if (anyCodeRef) deadCallers.add(new long[]{w, size});
            else if (anyDataRef) dataRefs.add(new long[]{w, size});
            else noRefs.add(new long[]{w, size});
        }

        int total = all.size(), nLive = live.size();
        println("");
        println(String.format("functions: %d total | %d reachable (%.1f%%) | %d unreachable",
            total, nLive, 100.0 * nLive / total, total - nLive));
        println(String.format("  unreachable, DATA REFS ONLY  : %4d   <- indirect/ISR/fn-ptr; usually LIVE, chase these",
            dataRefs.size()));
        println(String.format("  unreachable, called only by unreachable code: %4d   <- orphaned components",
            deadCallers.size()));
        println(String.format("  unreachable, NO REFS AT ALL  : %4d   <- most likely dead flash",
            noRefs.size()));

        // A dispatch-driven image with un-replayed .cinit reports almost everything as unreachable.
        // Say so loudly rather than letting the buckets be read as a dead-code census.
        double frac = (double) nLive / total;
        int minPct = Integer.getInteger("c28x.reach.warnPct", 25);
        if (frac * 100 < minPct) {
            println("");
            println("*** WARNING: only " + String.format("%.1f%%", frac * 100) + " of functions are reachable."
                + " That is too low to be a real dead-code result.");
            println("*** The call graph is almost certainly MISSING INDIRECT EDGES: on a component/task"
                + " dispatch firmware the");
            println("*** function-pointer registry lives in RAM and is filled in by .cinit at startup, so"
                + " until that is replayed");
            println("*** the pointers are inert flash words and live handlers look unreferenced.");
            println("*** Run EmulateStartup (or the Materialize* scripts) first, then re-run this report.");
            println("*** Until then, read NO-REFS-AT-ALL as 'no edge recovered yet', NOT as 'dead'.");
        }

        dump("DATA REFS ONLY (address stored somewhere, never called from live code)", dataRefs, all, listN);
        dump("CALLED ONLY BY UNREACHABLE CODE (orphaned components)", deadCallers, all, listN);
        dump("NO REFS AT ALL (nothing in the image mentions this address)", noRefs, all, listN);

        if (Boolean.getBoolean("c28x.reach.bookmark")) {
            int n = 0;
            for (ArrayList<long[]> bucket : List.of(dataRefs, deadCallers, noRefs))
                for (long[] r : bucket) {
                    Address a = all.get(r[0]).getEntryPoint();
                    String kind = bucket == dataRefs ? "data-refs-only"
                                : bucket == deadCallers ? "unreachable-caller" : "no-refs";
                    currentProgram.getBookmarkManager().setBookmark(
                        a, "Analysis", "c28x-unreachable", kind);
                    n++;
                }
            println("\nbookmarked " + n + " unreachable functions (Analysis / c28x-unreachable)");
        }

        String out = System.getProperty("c28x.reach.out");
        if (out != null) {
            try (java.io.PrintWriter pw = new java.io.PrintWriter(out)) {
                pw.printf("# addr size bucket name%n");
                for (Map.Entry<Long,Function> e : all.entrySet()) {
                    long w = e.getKey();
                    String b = live.contains(w) ? "reachable"
                        : contains(dataRefs, w) ? "data-refs-only"
                        : contains(deadCallers, w) ? "unreachable-caller" : "no-refs";
                    pw.printf("0x%05x %d %s %s%n", w,
                        e.getValue().getBody().getNumAddresses() / 2, b, e.getValue().getName());
                }
            }
            println("full classification -> " + out);
        }
    }

    boolean contains(ArrayList<long[]> l, long w) {
        for (long[] r : l) if (r[0] == w) return true;
        return false;
    }

    // Largest first: a big unreachable function is far more interesting than a 3-word stub.
    void dump(String title, ArrayList<long[]> l, TreeMap<Long,Function> all, int listN) {
        if (l.isEmpty()) return;
        l.sort((a, b) -> Long.compare(b[1], a[1]));
        println("\n" + title + " -- " + l.size() + " function(s), largest first:");
        int shown = 0;
        for (long[] r : l) {
            if (shown++ >= listN) { println(String.format("  ... and %d more", l.size() - listN)); break; }
            println(String.format("  %05x  %5d words  %s", r[0], r[1], all.get(r[0]).getName()));
        }
    }
}
