// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// MarkComponentRegistry.java — recover the INDIRECT call edges of a component/task-dispatch
// firmware, once startup has been replayed (Step 4/4b/4c).
//
// WHY THIS EXISTS
// ---------------
// On a dispatch-driven image the scheduler never calls a handler by name. It walks a RAM table of
// pointers and calls through them. That table is written at boot by the C runtime — SPRU513Z
// §3.3.1 responsibility 3, "process the .cinit run-time initialization table to autoinitialize
// global variables (--rom_model)" — so in a static image the table is all zeros and every handler
// looks dead. (EABI ROM model: the linker points __TI_CINIT_Base at those tables, §3.3.2.1.)
//
// `EmulateStartup` / `Materialize*` fix the *bytes*: after them the table holds real pointers.
// They do NOT fix the *graph*. Ghidra's call graph is built from references, and nothing turns a
// materialized RAM pointer word into a reference. Measured on an F28377D application image: reachability from
// `_c_int00` was 2.5% before materialization and 2.5% after — identical — while the registry was
// visibly full of valid flash addresses. This script is the missing half: it reads the
// materialized table and emits the references, so the graph finally matches the firmware.
//
// WHAT IT RECOGNIZES
// ------------------
// Two table shapes, told apart by what the slots point AT (both are reported):
//
//   DIRECT   slot -> function.  A plain function-pointer table copied into RAM.
//   DESCRIPTOR  slot -> a flash struct, whose fields at various word offsets are the functions.
//               This is the component-framework shape: one descriptor per component, and each
//               dispatcher pass calls ONE field of every descriptor (init, fast periodic, slow
//               periodic, ...). Measured on that image: 71 slots, 4 live field offsets,
//               147 distinct handlers.
//
// Discovery is structural, not hard-coded: scan initialized RAM for maximal runs of consecutive
// 32-bit words that all land in flash, then score each run by what its targets look like. A run
// only survives if its targets are coherent, which is what keeps ordinary data out.
//
// OFFSET ATTRIBUTION (descriptor shape)
// -------------------------------------
// Each dispatcher calls exactly one field offset, and on C28x the offset is a literal immediate a
// few instructions ahead of the indirect call:
//
//     MOVB ACC,#0xe            <- the descriptor field offset
//     ADDL ACC,*XAR1++         <- + the registry slot, post-incremented (the loop)
//     MOVL XAR4,@ACC
//     MOVL ACC,*+XAR4[0x0]     <- load the function pointer
//     SB   ...,EQ              <- skip if null
//     MOVL @XAR7,ACC
//     LCR  *XAR7               <- the indirect call
//
// So rather than pattern-match that sequence rigidly, the script asks a narrower question it can
// answer robustly: of the field offsets we already PROVED live (by profiling the descriptors),
// which ones appear as a literal scalar in the window before this call? Non-zero matches win; a
// bare 0 is accepted only when nothing else matches, because 0 appears as a displacement all over
// the place. A site that matches nothing is reported, not guessed at.
//
// This is a MAY-call edge, which is the honest thing for a dispatch loop: the call really can
// reach every descriptor's field, because the loop runs over every slot.
//
// RAM HOOKS (-Dc28x.reg.noHooks to disable)
// -----------------------------------------
// The same materialization also resolves the single-slot form, `(*DAT_xxxx)()`. That one matters
// out of proportion to its count: on that image the component scheduler itself is reached ONLY
// through such a hook, so without it the scheduler stays unreachable and every edge this script
// adds below it is stranded. The gate is deliberately strict — the slot must be in INITIALIZED RAM
// (never flash), the value must land exactly on a function entry in FLASH, and the window must
// offer exactly one such candidate. Flash-resident tables are left alone: those are jump/dispatch
// tables and belong to MarkJumpTables, and a loose version of this rule happily "resolves" a
// constant like 0x00010001 into a bogus RAM function.
//
// ORDER: run AFTER SeedFunctions + a materialization step, and re-run ReachabilityReport after.
//
// Properties (also accepted as -Dkey=value script args):
//   c28x.reg.base        (hex word) skip discovery, use this registry base
//   c28x.reg.count       (int)      slot count for -Dc28x.reg.base
//   c28x.reg.minSlots    (int,  default 16)   shortest run discovery will consider
//   c28x.reg.descWindow  (int,  default 16)   descriptor words scanned for function pointers
//   c28x.reg.minTableFrac(dbl,  default 0.50) of slots that must resolve, to accept a run
//   c28x.reg.minOffFrac  (dbl,  default 0.10) of descriptors that must expose an offset to use it
//   c28x.reg.minOffHits  (int,  default 4)    ...and at least this many, absolutely
//   c28x.reg.window      (int,  default 10)   instructions scanned back from an indirect call
//   c28x.reg.noCreateFns (bool)               don't create functions at proven dispatch targets
//   c28x.reg.noSeedDispatchers (bool)         don't recover a dispatch site's enclosing function
//   c28x.reg.maxBack     (int,  default 512)  instructions to walk back looking for that entry
//   c28x.reg.noHooks     (bool)               skip the single-slot RAM hook pass
//   c28x.reg.noPie       (bool)               skip the PIE vector-table initializer pass
//   c28x.reg.minPieEntries (int, default 64)  shortest code-pointer run treated as a vector table
//   c28x.reg.noRootDispatched (bool)          don't register runtime-dispatched functions as roots
//   c28x.reg.noLabels    (bool)               don't label descriptors
//   c28x.reg.dryRun      (bool)               report only, change nothing
//
//@category TMS320C28x

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import java.util.*;

public class MarkComponentRegistry extends GhidraScript {

    AddressSpace space;
    Memory mem;
    FunctionManager fm;
    ReferenceManager rm;
    long flashLo = Long.MAX_VALUE, flashHi = 0;
    boolean dry;

    Address wa(long w) { return space.getAddress(w * 2); }
    boolean inFlash(long w) { return w >= flashLo && w <= flashHi; }

    /** 32-bit little-endian value stored at word address w (two words), or -1 if unreadable. */
    long word32(long w) {
        try { return mem.getInt(wa(w)) & 0xFFFFFFFFL; } catch (Exception e) { return -1; }
    }

    Function fnAt(long w) { return inFlash(w) ? fm.getFunctionAt(wa(w)) : null; }

    // run_ghidra_script / the MCP bridge deliver -Dkey=value as getScriptArgs(), NOT as JVM system
    // properties, so every c28x.reg.* override would silently no-op over MCP/headless.
    //
    // The clear-first step is not cosmetic: system properties are JVM-global and survive between
    // script runs in one Ghidra session, so a flag passed once stays set for every later run. A
    // -Dc28x.reg.dryRun=true from an earlier invocation silently turns the next "apply" into
    // another dry run that still reports success. Wiping this script's namespace first makes the
    // arguments of THIS invocation the whole truth.
    void promoteDashDArgs() {
        final String prefix = "c28x.reg.";
        for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
            if (k.startsWith(prefix)) System.clearProperty(k);
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

    /** One accepted pointer table. */
    static class Table {
        long base; int slots; boolean descriptor;
        List<Long> ptrs = new ArrayList<>();       // slot values (descriptor or function addrs)
        TreeMap<Integer,List<Long>> byOffset = new TreeMap<>(); // profiled: offset -> target functions
        TreeSet<Integer> used = new TreeSet<>();   // offsets a dispatcher was seen to call through
        List<Long> direct = new ArrayList<>();     // DIRECT shape: the functions themselves
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        mem = currentProgram.getMemory();
        fm = currentProgram.getFunctionManager();
        rm = currentProgram.getReferenceManager();
        dry = Boolean.getBoolean("c28x.reg.dryRun");

        int minSlots   = Integer.getInteger("c28x.reg.minSlots", 16);
        int descWindow = Integer.getInteger("c28x.reg.descWindow", 16);
        int window     = Integer.getInteger("c28x.reg.window", 10);
        double minTableFrac = Double.parseDouble(System.getProperty("c28x.reg.minTableFrac", "0.50"));
        double minOffFrac   = Double.parseDouble(System.getProperty("c28x.reg.minOffFrac", "0.10"));
        int minOffHits      = Integer.getInteger("c28x.reg.minOffHits", 4);

        // flash = initialized blocks at/above 0x80000 (word), same rule as the other scripts
        for (MemoryBlock b : mem.getBlocks()) {
            long s = b.getStart().getOffset() / 2, e = b.getEnd().getOffset() / 2;
            if (b.isInitialized() && s >= 0x80000L) { flashLo = Math.min(flashLo, s); flashHi = Math.max(flashHi, e); }
        }
        if (flashHi == 0) { println("no initialized flash block >= 0x80000 -- nothing to do."); return; }
        println(String.format("flash %05x..%05x | functions %d%s",
            flashLo, flashHi, fm.getFunctionCount(), dry ? " | DRY RUN" : ""));

        int liveBefore = closureSize();

        // ---- 1. find the tables ------------------------------------------------------------
        List<Table> tables = new ArrayList<>();
        String forced = System.getProperty("c28x.reg.base");
        if (forced != null) {
            long base = Long.decode(forced.trim());
            int n = Integer.getInteger("c28x.reg.count", 0);
            if (n <= 0) { println("-Dc28x.reg.base needs -Dc28x.reg.count too."); return; }
            Table t = score(base, n, descWindow);
            println(String.format("forced table @%05x x%d", base, n));
            tables.add(t);
        } else {
            List<long[]> runs = discoverRuns(minSlots);
            println("candidate pointer runs in initialized RAM: " + runs.size());
            for (long[] r : runs) {
                Table t = score(r[0], (int) r[1], descWindow);
                int resolved = t.descriptor ? countDescResolving(t, descWindow) : t.direct.size();
                double frac = (double) resolved / t.slots;
                println(String.format("  @%05x x%-4d  %-10s  %d/%d slots resolve (%.2f)%s",
                    t.base, t.slots, t.descriptor ? "DESCRIPTOR" : "DIRECT", resolved, t.slots, frac,
                    frac >= minTableFrac ? "  <- accepted" : "  rejected"));
                if (frac >= minTableFrac) tables.add(t);
            }
        }
        if (tables.isEmpty()) {
            println("");
            println("No component registry found. If this image IS dispatch-driven, the table is");
            println("probably not materialized yet -- run EmulateStartup (Step 4c) or a Materialize*");
            println("script first, then re-run. A registry that has never been written reads as all");
            println("zeros, and zeros are not pointers.");
            return;
        }

        // ---- 2. profile descriptor field offsets --------------------------------------------
        for (Table t : tables) {
            if (!t.descriptor) continue;
            println("");
            println(String.format("descriptor field profile for @%05x (%d slots, first %d words):",
                t.base, t.slots, descWindow));
            for (int off = 0; off < descWindow; off++) {
                List<Long> hits = new ArrayList<>();
                for (long d : t.ptrs) {
                    long v = word32(d + off);
                    if (fnAt(v) != null) hits.add(v);
                }
                double frac = (double) hits.size() / t.slots;
                boolean keep = hits.size() >= minOffHits && frac >= minOffFrac;
                if (hits.size() > 0)
                    println(String.format("  +%-3d %3d/%d (%.2f)%s", off, hits.size(), t.slots, frac,
                        keep ? "  <- live field" : "  (below threshold, ignored)"));
                if (keep) t.byOffset.put(off, hits);
            }
            Set<Long> distinct = new LinkedHashSet<>();
            for (List<Long> l : t.byOffset.values()) distinct.addAll(l);
            println(String.format("  => %d live field offset(s), %d distinct handler functions",
                t.byOffset.size(), distinct.size()));
        }

        // ---- 3. the call edges: read each dispatch site's field offset out of the code ---------
        boolean createFns = !Boolean.getBoolean("c28x.reg.noCreateFns");
        boolean seedDispatchers = !Boolean.getBoolean("c28x.reg.noSeedDispatchers");
        int maxBack = Integer.getInteger("c28x.reg.maxBack", 512);
        int sites = 0, attributed = 0, unattributed = 0, callRefs = 0, outsideFn = 0, dispatchFns = 0;
        int[] mk = new int[2];                       // [0] functions created, [1] left unresolved
        println("");
        for (Table t : tables) {
            long lo = t.base, hi = t.base + t.slots * 2L - 1;
            Set<Address> seen = new HashSet<>();
            for (Reference r : refsInto(lo, hi)) {
                Instruction call = forwardToIndirectCall(r.getFromAddress(), window);
                if (call == null || !seen.add(call.getAddress())) continue;
                sites++;
                boolean orphanSite = fm.getFunctionContaining(call.getAddress()) == null;
                String seeded = "";
                if (orphanSite && seedDispatchers) {
                    long ew = enclosingEntry(call, maxBack);
                    if (ew >= 0) {
                        boolean ok = makeFunction(ew);
                        if (ok) {
                            dispatchFns++;
                            seeded = String.format("   [%s enclosing fn @%05x]", dry ? "would seed" : "seeded", ew);
                            orphanSite = !dry && fm.getFunctionContaining(call.getAddress()) == null;
                        }
                    }
                }
                if (orphanSite) outsideFn++;

                List<Long> targets;
                String how;
                if (!t.descriptor) {
                    targets = t.direct; how = "direct table";
                } else {
                    int off = attributeOffset(call, window);
                    if (off < 0) {
                        unattributed++;
                        println(String.format("  %05x  indirect call: field offset not recognized in the "
                            + "preceding %d instructions -- left alone",
                            call.getAddress().getOffset() / 2, window));
                        continue;
                    }
                    attributed++;
                    t.used.add(off);
                    targets = targetsAt(t, off, createFns, mk);
                    how = String.format("field +%d", off);
                }
                int added = 0;
                for (long tgt : targets) if (addRef(call.getAddress(), wa(tgt), RefType.COMPUTED_CALL)) added++;
                callRefs += added;
                println(String.format("  %05x  %-16s -> %-11s %3d target(s)%s",
                    call.getAddress().getOffset() / 2, call.toString(), how, added,
                    !seeded.isEmpty() ? seeded : (orphanSite ? "   [not inside any function]" : "")));
            }
        }
        println("");
        println(String.format("dispatch sites: %d found, %d attributed, %d unattributed, %d outside any function",
            sites, attributed, unattributed, outsideFn));
        println(String.format("computed-call refs added: %d; functions created at proven call targets: %d"
            + " (%d target pointers left unresolved); dispatcher functions recovered: %d",
            callRefs, mk[0], mk[1], dispatchFns));
        if (outsideFn > 0)
            println("  NOTE: " + outsideFn + " site(s) still sit outside any function and therefore contribute NO\n"
                  + "        reachability -- the BFS only walks references originating inside a function body.");

        // ---- 4. data references: slot -> descriptor -> handler ---------------------------------
        // Union of the profiled offsets and the ones the dispatchers actually use: the profile
        // finds fields that are widely populated, attribution finds fields that are actually
        // called. Neither is a superset of the other.
        int slotRefs = 0, fieldRefs = 0, labels = 0;
        for (Table t : tables) {
            for (int i = 0; i < t.slots; i++) {
                long slot = t.base + i * 2, val = t.ptrs.get(i);
                if (!inFlash(val)) continue;
                if (addRef(wa(slot), wa(val), RefType.DATA)) slotRefs++;
                if (t.descriptor && !Boolean.getBoolean("c28x.reg.noLabels")
                        && labelIfUnnamed(val, String.format("compdesc_%05x", val))) labels++;
            }
            TreeSet<Integer> offs = new TreeSet<>(t.byOffset.keySet());
            offs.addAll(t.used);
            for (int off : offs)
                for (long d : t.ptrs) {
                    long v = word32(d + off);
                    if (fnAt(v) == null) continue;
                    if (addRef(wa(d + off), wa(v), RefType.DATA)) fieldRefs++;
                }
        }
        println("");
        println(String.format("data refs: %d slot->descriptor, %d descriptor-field->handler, %d descriptor labels",
            slotRefs, fieldRefs, labels));

        // ---- 5. single-slot RAM hooks --------------------------------------------------------
        int hooks = 0;
        if (!Boolean.getBoolean("c28x.reg.noHooks")) hooks = resolveRamHooks(window);
        println(String.format("RAM single-slot hooks resolved: %d", hooks));

        // ---- 5b. interrupt handlers, from the PIE vector table's flash initializer --------------
        // Run this BEFORE the inference pass below: a handler rooted from the vector table is
        // rooted on evidence, and rooting it here means the heuristic never has to guess at it.
        int pie = 0;
        if (!Boolean.getBoolean("c28x.reg.noPie")) {
            println("");
            pie = markPieVectors(Integer.getInteger("c28x.reg.minPieEntries", 64), createFns);
        }

        // ---- 5c. roots for what the runtime dispatches and nothing calls -----------------------
        int rooted = 0;
        if (!Boolean.getBoolean("c28x.reg.noRootDispatched")) {
            println("");
            rooted = rootRuntimeDispatched(createFns);
            println(String.format("runtime-dispatched entry points registered: %d", rooted));
        }

        // ---- 6. what it bought ---------------------------------------------------------------
        int liveAfter = closureSize();
        int total = fm.getFunctionCount();
        println("");
        println(String.format("reachable: %d -> %d of %d  (%.1f%% -> %.1f%%, %+d)",
            liveBefore, liveAfter, total,
            100.0 * liveBefore / total, 100.0 * liveAfter / total, liveAfter - liveBefore));
        if (dry) println("DRY RUN -- nothing was written (the reachability delta above is therefore 0).");
        else println("Re-run ReachabilityReport for the full bucketed picture.");
    }

    // ---------------------------------------------------------------------------------------
    // discovery
    // ---------------------------------------------------------------------------------------

    /** Maximal stride-2 runs of consecutive 32-bit words that all point into flash, in RAM. */
    List<long[]> discoverRuns(int minSlots) {
        List<long[]> out = new ArrayList<>();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            long s = b.getStart().getOffset() / 2, e = b.getEnd().getOffset() / 2;
            if (s >= 0x80000L) continue;                       // flash: not where .cinit writes
            int n = (int) Math.min(e - s + 1, 1 << 20);
            if (n < minSlots * 2) continue;
            boolean[] ptr = new boolean[n];
            for (int i = 0; i + 1 < n; i++) ptr[i] = inFlash(word32(s + i));
            for (int start = 0; start < n; start++) {
                if (!ptr[start]) continue;
                if (start >= 2 && ptr[start - 2]) continue;    // mid-run, not a start
                int len = 0, i = start;
                while (i < n && ptr[i]) { len++; i += 2; }
                if (len >= minSlots) out.add(new long[]{s + start, len});
            }
        }
        return out;
    }

    /** Read a run's slots and decide DIRECT vs DESCRIPTOR. */
    Table score(long base, int slots, int descWindow) {
        Table t = new Table();
        t.base = base; t.slots = slots;
        int direct = 0;
        for (int i = 0; i < slots; i++) {
            long v = word32(base + i * 2);
            t.ptrs.add(v);
            if (fnAt(v) != null) { direct++; t.direct.add(v); }
        }
        // If the slots ARE functions it is a plain function-pointer table; otherwise the slots are
        // structs and the functions live inside them.
        t.descriptor = direct < slots / 2;
        return t;
    }

    int countDescResolving(Table t, int descWindow) {
        int n = 0;
        for (long d : t.ptrs) {
            for (int off = 0; off < descWindow; off++)
                if (fnAt(word32(d + off)) != null) { n++; break; }
        }
        return n;
    }

    // ---------------------------------------------------------------------------------------
    // dispatch-site plumbing
    // ---------------------------------------------------------------------------------------

    List<Reference> refsInto(long loWord, long hiWord) {
        List<Reference> out = new ArrayList<>();
        AddressSet set = new AddressSet(wa(loWord), wa(hiWord + 1));
        for (AddressIterator it = rm.getReferenceDestinationIterator(set, true); it.hasNext(); )
            for (Reference r : rm.getReferencesTo(it.next())) {
                RefType ty = r.getReferenceType();
                if (ty.isCall() || ty.isJump()) continue;
                out.add(r);
            }
        return out;
    }

    /** From a registry-reading instruction, the next computed call within `window` instructions. */
    Instruction forwardToIndirectCall(Address from, int window) {
        Instruction in = getInstructionAt(from);
        if (in == null) in = getInstructionContaining(from);
        for (int k = 0; k < window && in != null; k++) {
            if (in.getFlowType().isCall() && in.getFlowType().isComputed()) return in;
            in = in.getNext();
        }
        return null;
    }

    /**
     * The descriptor field offset this dispatcher uses, read straight out of the code.
     *
     * An earlier version of this asked instead "which PROFILED offset appears as a scalar in the
     * window", and it was wrong in both directions on the first image tried. The scheduler's two
     * passes use +0xc and +0xe, but only 2 of 71 components have a periodic handler installed
     * (the dispatch loops guard on a null field), so profiling scored those offsets below any
     * sane threshold and never offered them — and the scalar match then silently picked +0 and
     * +10 instead. The immediate in the instruction stream is ground truth; the profile is a
     * population statistic and must not be allowed to overrule it.
     *
     * Two shapes, both ending in the same pointer load:
     *   MOVB ACC,#off ; ADDL ACC,*XARn++ ; MOVL XAR4,@ACC ; MOVL ACC,*+XAR4[d]   -> off + d
     *   MOVL XAR4,*+XARb[0] ;                              MOVL ACC,*+XAR4[d]   ->       d
     * Returns -1 when neither is recognized, and the caller reports that rather than guessing.
     */
    int attributeOffset(Instruction call, int window) {
        Integer disp = null, add = null;
        Instruction p = call;
        for (int k = 0; k < window; k++) {
            p = p.getPrevious();
            if (p == null) break;
            String m = p.getMnemonicString();
            if (p.getNumOperands() < 2) continue;
            String op0 = p.getDefaultOperandRepresentation(0);
            String op1 = p.getDefaultOperandRepresentation(1);
            // the function-pointer load: MOVL ACC,*+XARn[d]  (nearest one wins)
            if (disp == null && m.equals("MOVL") && op0.equals("ACC") && op1.contains("*+XAR")) {
                long v = firstScalar(p, 1);
                disp = (int) (v < 0 ? 0 : v);
                continue;
            }
            // the slot add: ADDL ACC,*XARn++  preceded by the field offset immediate
            if (add == null && m.equals("ADDL") && op0.equals("ACC") && op1.contains("XAR")) {
                Instruction q = p.getPrevious();
                if (q != null && q.getNumOperands() >= 2
                        && (q.getMnemonicString().equals("MOVB") || q.getMnemonicString().equals("MOV"))
                        && q.getDefaultOperandRepresentation(0).equals("ACC")) {
                    long v = firstScalar(q, 1);
                    if (v >= 0) add = (int) v;
                }
            }
        }
        if (disp == null && add == null) return -1;
        return (disp == null ? 0 : disp) + (add == null ? 0 : add);
    }

    long firstScalar(Instruction in, int op) {
        for (Object o : in.getOpObjects(op)) if (o instanceof Scalar) return ((Scalar) o).getUnsignedValue();
        return -1;
    }

    /**
     * Every non-null flash pointer at descriptor field `off`. A pointer the framework provably
     * calls through is a function even if nothing else in the image mentions it, so create one
     * where it is missing (counters: [0]=created, [1]=left unresolved).
     */
    List<Long> targetsAt(Table t, int off, boolean createFns, int[] counters) {
        List<Long> out = new ArrayList<>();
        for (long d : t.ptrs) {
            long v = word32(d + off);
            if (v == 0 || !inFlash(v)) continue;
            if (fnAt(v) != null) { out.add(v); continue; }
            if (createFns && makeFunction(v)) { counters[0]++; out.add(v); }
            else counters[1]++;
        }
        return out;
    }

    /**
     * A dispatch site outside any function means the ENCLOSING function was never seeded — nothing
     * calls it either, because it hangs off a task table instead of a call site. Recover its entry
     * the way a backward linear sweep does: walk back to the previous RETURN; the entry is the
     * instruction after it, because functions are emitted back to back.
     *
     * Only a return ends a function. A first cut stopped at any instruction without fall-through,
     * and an unconditional INTRA-function branch (`SB ...,UNC`) then yielded a bogus "entry" in the
     * middle of the dispatcher — for one of the five sites on the first image tried. Returns only
     * puts that site back on the same real entry as its sibling.
     *
     * Returns the entry word address, or -1 if no return is found within `maxBack` instructions.
     */
    long enclosingEntry(Instruction site, int maxBack) {
        Instruction p = site;
        for (int k = 0; k < maxBack; k++) {
            Instruction q = p.getPrevious();
            if (q == null) return -1;
            if (q.getFlowType().isTerminal()) return p.getAddress().getOffset() / 2;
            p = q;
        }
        return -1;
    }

    boolean makeFunction(long w) {
        Address a = wa(w);
        if (fm.getFunctionContaining(a) != null) return false;   // interior of something real
        if (dry) return true;                                     // would create
        try {
            if (getInstructionAt(a) == null) disassemble(a);
            if (getInstructionAt(a) == null) return false;
            return createFunction(a, null) != null;
        } catch (Exception e) { return false; }
    }

    /**
     * `(*DAT_xxxx)()` where DAT_xxxx is a materialized RAM slot. Strict: the slot must live in
     * initialized RAM (never flash — flash tables are MarkJumpTables' job), the value must land
     * exactly on a function entry in flash, and the window must offer exactly one candidate.
     */
    int resolveRamHooks(int window) {
        int done = 0;
        for (Function f : fm.getFunctions(true)) {
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction in = ii.next();
                if (!in.getFlowType().isCall() || !in.getFlowType().isComputed()) continue;
                if (!rm.getReferencesFrom(in.getAddress()).equals(Collections.emptyList())) {
                    boolean already = false;
                    for (Reference r : rm.getReferencesFrom(in.getAddress()))
                        if (r.getReferenceType().isCall()) already = true;
                    if (already) continue;              // registry pass (or Ghidra) already resolved it
                }
                Set<Long> cands = new LinkedHashSet<>();
                Instruction p = in;
                for (int k = 0; k < window; k++) {
                    p = p.getPrevious();
                    if (p == null || !f.getBody().contains(p.getAddress())) break;
                    for (Reference r : rm.getReferencesFrom(p.getAddress())) {
                        RefType ty = r.getReferenceType();
                        if (ty.isCall() || ty.isJump() || ty.isFlow()) continue;
                        long slot = r.getToAddress().getOffset() / 2;
                        if (inFlash(slot)) continue;                       // RAM only
                        MemoryBlock b = mem.getBlock(r.getToAddress());
                        if (b == null || !b.isInitialized()) continue;
                        long v = word32(slot);
                        if (fnAt(v) != null) cands.add(v);
                    }
                }
                if (cands.size() != 1) continue;                            // ambiguous -> leave alone
                long tgt = cands.iterator().next();
                if (addRef(in.getAddress(), wa(tgt), RefType.COMPUTED_CALL)) {
                    done++;
                    println(String.format("  hook %05x in %-20s -> %s",
                        in.getAddress().getOffset() / 2, f.getName(), fnAt(tgt).getName()));
                }
            }
        }
        return done;
    }

    // ---------------------------------------------------------------------------------------
    // mutation helpers (all no-ops under dryRun) + measurement
    // ---------------------------------------------------------------------------------------

    boolean addRef(Address from, Address to, RefType type) {
        for (Reference r : rm.getReferencesFrom(from))
            if (r.getToAddress().equals(to) && r.getReferenceType() == type) return false;
        if (dry) return true;
        try { rm.addMemoryReference(from, to, type, SourceType.ANALYSIS, 0); return true; }
        catch (Exception e) { return false; }
    }

    boolean labelIfUnnamed(long w, String name) {
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(wa(w));
        if (s != null && s.getSource() != SourceType.DEFAULT) return false;   // never clobber a name
        if (dry) return true;
        try { createLabel(wa(w), name, true, SourceType.ANALYSIS); return true; }
        catch (Exception e) { return false; }
    }

    /**
     * The PIE vector table's FLASH initializer -- the best roots in the image, because they are
     * evidence rather than inference.
     *
     * On C28x the PIE vector table itself is RAM (F28377D: 0x000D00-0x000DFF, 128 vectors x 2
     * words), written at runtime by TI's InitPieVectTable, which copies a const table out of flash.
     * A static image therefore has an EMPTY vector table and a fully populated initializer sitting
     * in flash with nothing pointing into it.
     *
     * The signature is unusually strong, so this needs no per-image tuning:
     *   * a long run of consecutive 32-bit words that are all plausible code addresses, and
     *   * one value repeated across most of the run -- the default/unused-interrupt handler that
     *     TI fills every unused slot with (209 of 224 entries on the image tested), and
     *   * entry 0 is the reset vector, i.e. exactly the _c_int00 signal D already recovered.
     *
     * Each distinct target is an interrupt handler: it runs, and nothing calls it. Create it,
     * reference it from its slot, and register it as an entry point. Targets may live in RAM
     * (time-critical ISRs are ramfuncs), which only resolve if a materialize step has run -- those
     * are reported and skipped rather than guessed at.
     */
    int markPieVectors(int minEntries, boolean createFns) {
        long cint = -1;
        for (Function f : fm.getFunctions(true))
            if (f.getName().toLowerCase().contains("c_int00")) { cint = f.getEntryPoint().getOffset() / 2; break; }
        if (cint < 0) { println("  no _c_int00 -- run SeedFunctions signal D first; skipping PIE scan"); return 0; }

        long bestBase = -1; int bestLen = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            long s = b.getStart().getOffset() / 2, e = b.getEnd().getOffset() / 2;
            if (s < 0x80000L) continue;                       // the initializer lives in flash
            for (long w = s; w + 1 <= e; w++) {
                if (word32(w) != cint) continue;              // anchor: entry 0 = the reset vector
                int len = 0;
                for (long k = w; k + 1 <= e; k += 2) {
                    long v = word32(k);
                    if (!isCodeAddr(v)) break;
                    len++;
                }
                if (len >= minEntries && len > bestLen) { bestLen = len; bestBase = w; }
            }
        }
        if (bestBase < 0) { println("  no PIE initializer found (no long code-pointer run starting at _c_int00)"); return 0; }

        // corroborate: an unused-vector fill should dominate
        HashMap<Long,Integer> histo = new HashMap<>();
        for (int i = 0; i < bestLen; i++) histo.merge(word32(bestBase + i * 2), 1, Integer::sum);
        long dflt = -1; int best = 0;
        for (Map.Entry<Long,Integer> e : histo.entrySet()) if (e.getValue() > best) { best = e.getValue(); dflt = e.getKey(); }
        println(String.format("  PIE initializer @%05x: %d entries, %d distinct, default handler %05x x%d (%.0f%%)",
            bestBase, bestLen, histo.size(), dflt, best, 100.0 * best / bestLen));
        if (best * 2 < bestLen) {
            println("  ...but no value dominates the run, so this is probably NOT a vector table -- skipping");
            return 0;
        }
        if (!dry) labelIfUnnamed(bestBase, "PieVectTableInit");

        int rooted = 0, made = 0, unresolved = 0;
        LinkedHashSet<Long> targets = new LinkedHashSet<>();
        for (int i = 0; i < bestLen; i++) {
            long v = word32(bestBase + i * 2);
            targets.add(v);
            if (!dry) addRef(wa(bestBase + i * 2), wa(v), RefType.DATA);
        }
        for (long v : targets) {
            if (v == cint) continue;                          // already the program entry
            Function f = fm.getFunctionAt(wa(v));
            if (f == null) {
                MemoryBlock b = mem.getBlock(wa(v));
                if (b == null || !b.isInitialized()) {
                    println(String.format("  vector target %05x is not in initialized memory "
                        + "(a RAM-resident ISR? run a materialize step first) -- skipped", v));
                    unresolved++;
                    continue;
                }
                if (!createFns || !makeFunction(v)) { unresolved++; continue; }
                made++;
                f = fm.getFunctionAt(wa(v));
                if (f == null) continue;
            }
            if (currentProgram.getSymbolTable().isExternalEntryPoint(f.getEntryPoint())) continue;
            rooted++;
            println(String.format("  ISR %05x %-22s %s", v, f.getName(),
                v == dflt ? "(default/unused-interrupt handler)" : ""));
            if (dry) continue;
            currentProgram.getSymbolTable().addExternalEntryPoint(f.getEntryPoint());
            if (getPlateComment(f.getEntryPoint()) == null)
                setPlateComment(f.getEntryPoint(),
                    "Interrupt handler, from the PIE vector table's flash initializer.\n"
                    + "The PIE vector table itself is RAM written at runtime by InitPieVectTable, so in a "
                    + "static image it is empty and this handler has no caller. Registered as an entry point.");
        }
        println(String.format("  PIE: %d handlers rooted, %d functions created, %d targets unresolved",
            rooted, made, unresolved));
        return rooted;
    }

    /** Flash, or an initialized executable RAM block (ramfunc ISRs live there). */
    boolean isCodeAddr(long w) {
        if (w <= 0) return false;
        if (inFlash(w)) return true;
        MemoryBlock b = mem.getBlock(wa(w));
        return b != null && b.isExecute();
    }

    /**
     * Roots for code the RUNTIME dispatches and no static caller ever names.
     *
     * Emitting the registry edges is not enough on its own, and chasing the chain upward explains
     * why. The component dispatchers are called from OS task-control blocks that `.cinit` builds in
     * RAM as a circular linked list -- a header word pointing at the first node, each node holding
     * next/prev links and the task function at a fixed offset inside it. Because the walker reaches
     * a node through a POINTER rather than an array base, no instruction anywhere contains a node's
     * address as an immediate, and nothing in the image references the records at all.
     *
     * The function that walks that list has zero incoming references itself: it is the tick ISR,
     * and on F28377D the PIE vector table that would name it lives in RAM at 0x000D00-0x000DFF and
     * is written AT RUNTIME. That region is mapped but uninitialized here, because replaying
     * startup stops at the handoff into main and any PIE setup the application does happens after
     * that point. So the chain terminates in a vector table that has never been filled in, and no
     * amount of static edge recovery can root it. (Emulating past the handoff would populate it --
     * see the note in the image-setup guide -- but that means running application init against
     * peripherals the emulator does not model.)
     *
     * That is the same situation this repo already accepts for ISRs generally, so treat it the same
     * way. A flash function whose address `.cinit` planted in RAM, and which nothing calls, is
     * dispatched at runtime -- an entry point in every sense except that its vector is unwritten.
     * Register it as one.
     *
     * Deliberately narrow, so this cannot paper over a real missing edge: the value must land
     * exactly on a function ENTRY in flash, and the function must have no incoming call/jump
     * reference at all. Anything the registry pass above just connected is therefore skipped.
     */
    int rootRuntimeDispatched(boolean createFns) {
        LinkedHashMap<Long,Long> firstSite = new LinkedHashMap<>();   // fn word -> RAM word holding it
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            long s = b.getStart().getOffset() / 2, e = b.getEnd().getOffset() / 2;
            if (s >= 0x80000L) continue;                              // RAM only
            for (long w = s; w + 1 <= e; w++) {
                long v = word32(w);
                if (v <= 0 || !inFlash(v)) continue;
                if (fnAt(v) == null) {
                    if (!createFns || fm.getFunctionContaining(wa(v)) != null) continue;
                    if (!makeFunction(v)) continue;
                    if (fnAt(v) == null) continue;
                }
                firstSite.putIfAbsent(v, w);
            }
        }
        int rooted = 0;
        for (Map.Entry<Long,Long> e : firstSite.entrySet()) {
            Function f = fnAt(e.getKey());
            if (f == null) continue;
            boolean called = false;
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                RefType t = r.getReferenceType();
                if (t.isCall() || t.isJump()) { called = true; break; }
            }
            if (called) continue;
            if (currentProgram.getSymbolTable().isExternalEntryPoint(f.getEntryPoint())) continue;
            rooted++;
            println(String.format("  root %05x %-22s (pointer planted in RAM at %05x, no static caller)",
                e.getKey(), f.getName(), e.getValue()));
            if (dry) continue;
            currentProgram.getSymbolTable().addExternalEntryPoint(f.getEntryPoint());
            if (getPlateComment(f.getEntryPoint()) == null)
                setPlateComment(f.getEntryPoint(),
                    "Runtime-dispatched entry point (MarkComponentRegistry).\n"
                    + "Its address was written into RAM by .cinit at startup and nothing in the image "
                    + "calls it, so it is reached only through an OS table/list walked by a dispatcher "
                    + "whose own root is an interrupt vector absent from this dump.\n"
                    + "Registered as an entry point so reachability reflects what actually runs.");
        }
        return rooted;
    }

    /** Reachable-function count, using the same roots + edge rule as ReachabilityReport. */
    int closureSize() {
        TreeMap<Long,Function> all = new TreeMap<>();
        for (Function f : fm.getFunctions(true)) all.put(f.getEntryPoint().getOffset() / 2, f);
        TreeSet<Long> roots = new TreeSet<>();
        for (AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator(); it.hasNext(); ) {
            Address a = it.next();
            if (fm.getFunctionAt(a) != null) roots.add(a.getOffset() / 2);
        }
        for (Map.Entry<Long,Function> e : all.entrySet()) {
            String n = e.getValue().getName(), lower = n.toLowerCase();
            if (lower.contains("c_int00") || n.equals("main") || lower.startsWith("reset")) roots.add(e.getKey());
        }
        roots.removeIf(w -> !all.containsKey(w));
        TreeSet<Long> live = new TreeSet<>(roots);
        ArrayDeque<Long> q = new ArrayDeque<>(roots);
        while (!q.isEmpty()) {
            Function f = all.get(q.poll());
            if (f == null) continue;
            for (AddressIterator ai = rm.getReferenceSourceIterator(f.getBody(), true); ai.hasNext(); )
                for (Reference r : rm.getReferencesFrom(ai.next())) {
                    RefType t = r.getReferenceType();
                    if (!t.isCall() && !t.isJump()) continue;
                    long tw = r.getToAddress().getOffset() / 2;
                    if (all.containsKey(tw) && live.add(tw)) q.add(tw);
                }
        }
        return live.size();
    }
}
