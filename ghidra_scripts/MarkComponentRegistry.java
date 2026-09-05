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
// BASE RESOLUTION (-Dc28x.reg.noBaseResolve to disable)
// -----------------------------------------------------
// Discovery above needs a DENSE pointer run. A sparse/inline image has none: its task registry is a
// heterogeneous collection of per-component RAM structs, each carrying a function pointer at a
// field offset, read field-by-field by many functions. Carving such a region into "descriptors" by
// stride would invent MAY-call edges over records no dispatcher actually loops, so this pass works
// from the CALL SITE instead, one site at a time:
//
//     MOVB XAR0,#0x10           <- the field offset
//     MOVL XAR4,#0x1806e        <- the struct base
//     MOVL XAR7,*+XAR4[AR0]     <- load the function pointer from base+off
//     LCR  *XAR7                <- the indirect call
//
// Walk back from the call to the instruction that defines the register it dispatches through, then
// resolve that instruction's source: an immediate, a register copy, or a load whose address is
// itself resolved the same way. One concrete address in, one function out, one COMPUTED_CALL edge.
//
// Everything about it is deliberately narrow, because a wrong edge is worse than a missing one:
// the walk is STRAIGHT-LINE (it stops at any instruction another path can branch to, so the
// definition it finds is the only one that can reach the call), the value must land EXACTLY on an
// existing function entry, and anything ambiguous is reported and skipped rather than guessed at.
// It creates no functions — an address that is not already a function entry is exactly the case
// where "resolved" usually means "read a constant that happens to look like code".
//
// And a register-derived address is resolved by THIS walk, never from the reference Ghidra's
// constant propagator left on the load. The propagator carries a value across the very arithmetic
// that makes an address unprovable: on `MOVL XAR1,#0x9b506 ; ADDL @XAR1,ACC ; MOVL XAR7,*+XAR1[0]`
// its reference names entry 0 of a table the dispatcher indexes at runtime, and taking it turns a
// MAY-call over N entries into one confidently wrong edge (measured, on the first image tried).
// Only a STATIC operand -- `*(0:addr)`, or `@6bit`, whose DP is the DP analyzer's job -- takes the
// reference, because there is no register there to prove.
//
// STRIDED TABLES (-Dc28x.reg.noStrided to disable)
// ------------------------------------------------
// A site base resolution refuses is not necessarily a site with nothing behind it. That same
// `ADDL @XARb,ACC` says the dispatcher is walking a TABLE, and every parameter of the walk is a
// literal in its own instruction stream:
//
//     MOVL XAR1,#0x9b506       <- the table base
//     MOV  ACC,@AL<<#0x2       <- the index, scaled by the record stride (4 words)
//     ADDL @XAR1,ACC
//     MOVL XAR7,*+XAR1[0x0]    <- the handler field within the record
//     LCR  *XAR7
//
// So this is NOT the strided carve #69 rules out: nothing here guesses a stride out of a region's
// shape, the code states it. Only the record COUNT is sometimes unstated, and that comes from the
// table -- walk records until one holds a word that is neither null nor code. Checked against a
// dispatcher that does state its bound (`CMPB AL,#0x12` over the table above), the structural walk
// stops at exactly 18 records: the 19th word is 0x01f400fa, plainly not a pointer.
//
// A record naming an address with an instruction already decoded at it, inside no function, gets a
// function -- a table the code provably calls through is evidence, the same rule `targetsAt`
// applies to descriptor fields. An address with no instruction ends the table instead of being
// disassembled into existence. Two tables sharing a dispatch tail both resolve; a base that any
// reaching path leaves unprovable resolves to nothing.
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
// Hooks scavenge ANY resolved slot in the window and require it to be the only candidate; base
// resolution tracks the specific register the call dispatches through. The precise pass runs first
// so it owns the sites it can prove, and hooks keep the rest.
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
//   c28x.reg.maxBack     (int,  default 512)  instructions to walk back looking for that entry,
//                                             and for a dispatched register's definition
//   c28x.reg.noBaseResolve (bool)             skip the per-call-site base-resolution pass
//   c28x.reg.noStrided   (bool)               skip the strided dispatch-table pass
//   c28x.reg.maxTable    (int,  default 256)  most records a strided table walk will read
//   c28x.reg.maxGap      (int,  default 16)   consecutive null records that end such a table
//   c28x.reg.minTargets  (int,  default 2)    handlers a strided table must yield to be accepted
//   c28x.reg.rounds      (int,  default 4)    cap on the call-site/rooting fixpoint iterations
//   c28x.reg.noHooks     (bool)               skip the single-slot RAM hook pass
//   c28x.reg.noPie       (bool)               skip the PIE vector-table initializer pass
//   c28x.reg.minPieEntries (int, default 64)  shortest code-pointer run treated as a vector table
//   c28x.reg.pieProfile  (path)               PIE vector-identity JSON; defaults to the one in
//                                             data/device_profiles matching the language variant
//   c28x.reg.noRootDispatched (bool)          don't register runtime-dispatched functions as roots
//   c28x.reg.noLabels    (bool)               don't label descriptors
//   c28x.reg.dryRun      (bool)               report only, change nothing
//
//@category TMS320C28x

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
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
        // Read here, not in the dense-registry branch: the base-resolution pass below uses the same
        // budget and runs on both paths.
        int maxBack         = Integer.getInteger("c28x.reg.maxBack", 512);

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
            println("No DENSE component registry found -- running only the registry-INDEPENDENT passes");
            println("(per-call-site base resolution, RAM single-slot hooks, PIE vectors, runtime-");
            println("dispatched roots). Each scans for its own evidence and needs no discovered table,");
            println("so together they also cover the sparse/inline case: an image whose task registry is");
            println("a struct array with the function pointer at a field offset exposes no dense pointer");
            println("run for discovery, but the call sites still name their base in the code and these");
            println("passes still root what the runtime dispatches. (Observed on an F28377D CPU1 image.)");
            println("If even these find nothing and the image IS dispatch-driven, the registry is");
            println("probably not materialized -- run EmulateStartup (Step 4c) first: a registry that");
            println("has never been written reads as all zeros.");

            // None of these passes consumes a discovered registry: base resolution, the strided
            // walk and hooks read the code, the PIE pass reads the flash vector initializer, and
            // rootRuntimeDispatched scans RAM for planted function-pointers with no static caller.
            // Running them here is what makes the sparse / inline-table (CPU1) case recover instead
            // of returning empty-handed after PIE.
            convergePasses(maxBack, window, !Boolean.getBoolean("c28x.reg.noCreateFns"), liveBefore);
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
        int slotRefs = 0, fieldRefs = 0, labels = 0, typed = 0;
        for (Table t : tables) {
            for (int i = 0; i < t.slots; i++) {
                long slot = t.base + i * 2, val = t.ptrs.get(i);
                if (!inFlash(val)) continue;
                if (addRef(wa(slot), wa(val), RefType.DATA)) slotRefs++;
                // A registry slot holding a function is a function-pointer global. Typing
                // it is what lets the store-tracking analyzer see writes to it (#61).
                if (!inFlash(slot) && fnAt(val) != null && typeFunctionPointer(slot)) typed++;
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
        println(String.format(
            "data refs: %d slot->descriptor, %d descriptor-field->handler, %d descriptor labels, "
            + "%d RAM slots typed as function pointers",
            slotRefs, fieldRefs, labels, typed));

        // ---- 4b..6. the passes that feed each other, plus what it all bought -------------------
        convergePasses(maxBack, window, createFns, liveBefore);
    }

    /**
     * Run the call-site and rooting passes to a fixpoint, then report the reachability delta.
     *
     * These passes are not independent: each creates FUNCTIONS the others then recognize. A word in
     * a dispatch table that was an unclaimed address before the vector pass ran is a function
     * afterwards, so the table walk that stopped at it will get further next time round. Running
     * the set once therefore under-reports, and by a lot — measured on a CPU2 image, a second round
     * found 2 more tables and 53 more edges, taking reachability 51.5% -> 56.1%.
     *
     * Every pass here only ever ADDS references, functions and entry points, and every one skips
     * work it has already done, so the loop is monotone and settles. It stops as soon as a round
     * changes nothing, and `c28x.reg.rounds` caps it regardless.
     *
     * The PIE pass runs only on the first round: its evidence is a flash initializer that no other
     * pass can change, so repeating it would just reprint the same table.
     */
    void convergePasses(int maxBack, int window, boolean createFns, int liveBefore) {
        int maxRounds = Integer.getInteger("c28x.reg.rounds", 4);
        int based = 0, strided = 0, hooks = 0, pie = 0, rooted = 0, rounds = 0;
        int[] mkT = new int[1];
        for (int round = 1; round <= maxRounds; round++) {
            rounds = round;
            int fnsBefore = fm.getFunctionCount();
            println("");
            if (round > 1) println("--- round " + round + " (the previous round created functions"
                + " the passes below can now recognize) ---");

            int n = 0;
            // Strided first, so base resolution can see the tables it accepted: a site whose base
            // resolves INTO one of them is walking that table through a saved cursor, and the whole
            // field is the honest answer rather than whichever record the cursor was left on.
            if (!Boolean.getBoolean("c28x.reg.noStrided")) {
                int k = resolveStridedTables(maxBack, createFns, mkT);
                println(String.format("strided-table edges: %d", k));
                strided += k; n += k;
            }
            if (!Boolean.getBoolean("c28x.reg.noBaseResolve")) {
                int k = resolveByBase(maxBack);
                println(String.format("computed calls resolved from a propagated base: %d", k));
                based += k; n += k;
            }
            if (!Boolean.getBoolean("c28x.reg.noHooks")) {
                int k = resolveRamHooks(window);
                println(String.format("RAM single-slot hooks resolved: %d", k));
                hooks += k; n += k;
            }
            // Vector pass BEFORE the inference pass: a handler rooted from the vector table is
            // rooted on evidence, so the inference pass never has to guess at it.
            if (round == 1 && !Boolean.getBoolean("c28x.reg.noPie")) {
                println("");
                pie = markPieVectors(Integer.getInteger("c28x.reg.minPieEntries", 64), createFns);
            }
            if (!Boolean.getBoolean("c28x.reg.noRootDispatched")) {
                println("");
                int k = rootRuntimeDispatched(createFns);
                println(String.format("runtime-dispatched entry points registered: %d", k));
                rooted += k; n += k;
            }
            // A round that added no edge, rooted nothing and created no function cannot make the
            // next one find anything either.
            if (n == 0 && fm.getFunctionCount() == fnsBefore) break;
            if (dry) break;              // nothing was written, so every round would be identical
        }

        int liveAfter = closureSize();
        int total = fm.getFunctionCount();
        println("");
        println(String.format("%d round(s): %d base, %d strided-table, %d hook edge(s); %d PIE +"
            + " %d runtime-dispatched root(s); %d function(s) created at table entries",
            rounds, based, strided, hooks, pie, rooted, mkT[0]));
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

    // ---------------------------------------------------------------------------------------
    // per-call-site base resolution
    // ---------------------------------------------------------------------------------------

    /** Where the last resolved load read its value from, so the slot can be typed (#61). */
    long lastSlot = -1;

    /** How far a value may travel through register copies before we stop believing it. */
    static final int MAX_DEPTH = 4;

    /** `*+XARn[0x4]` / `*+XARn[AR0]` — the only indexed forms decomposed by hand. */
    static final java.util.regex.Pattern INDEXED =
        java.util.regex.Pattern.compile("\\*\\+(XAR[0-7])\\[(0x[0-9a-fA-F]+|AR[01])\\]");

    /**
     * Resolve `LCR *XARn` by propagating the dispatched register back to one concrete value.
     *
     * This is the sparse/inline half of the registry problem. Where a dense registry lets the
     * script emit a MAY-call over every descriptor's field, a heterogeneous struct region offers
     * nothing to enumerate — but the dispatcher's own code still names the struct: the base is an
     * immediate (or a slot that holds one) and the field offset is an immediate a few instructions
     * earlier. One site, one address, one target.
     *
     * Sites whose base is a parameter or a runtime index do NOT resolve, and that is correct
     * rather than a shortfall: a generic dispatcher handed a different component on every call has
     * no single target, and picking its table's first element would be a confidently wrong edge.
     */
    int resolveByBase(int maxBack) {
        int sites = 0, resolved = 0, notFn = 0, added = 0, cursors = 0;
        for (Function f : fm.getFunctions(true)) {
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction in = ii.next();
                if (!in.getFlowType().isCall() || !in.getFlowType().isComputed()) continue;
                if (hasCallRef(in)) continue;                  // already resolved by someone
                Register reg = callThrough(in);
                if (reg == null) continue;
                sites++;
                lastSlot = -1;
                long tgt = regValue(reg.getName(), in, f, maxBack, 0);
                if (tgt < 0) continue;
                if (tgt == 0) continue;        // a null hook: installed at runtime, nothing to say
                resolved++;
                // A base that lands INSIDE a table the strided pass accepted is a cursor into it,
                // saved by one dispatcher and reloaded by another. The record it holds in a static
                // image is only where the cursor was initialized, so emitting that one target
                // would be precise about the wrong thing -- take the whole field instead. The
                // field comes from this site's own load, not from the table's.
                long[] tbl = lastSlot < 0 ? null : tableContaining(lastSlot);
                if (tbl != null) {
                    long fld = (lastSlot - tbl[0]) % tbl[1];
                    TableScan s = scanTable(tbl[0], tbl[1], fld, false, new int[1]);
                    if (s.targets.size() > 1) {
                        int n = emitTargets(in, s.targets);
                        cursors++; added += n;
                        println(String.format("  cursor %05x in %-20s -> table @%05x stride %d"
                            + " field +%d: %d target(s), %d edge(s)",
                            in.getAddress().getOffset() / 2, f.getName(), tbl[0], tbl[1], fld,
                            s.targets.size(), n));
                        continue;
                    }
                }
                // Exact function ENTRY, in flash or in an executable RAM block -- a ramfunc handler
                // is as real a target as a flash one. Measured: the three CPU2 sites that come back
                // unresolved point into D1 RAM that a materialize step DID populate; what is
                // missing is disassembly, because MaterializeSections only decodes at addresses
                // something already calls, and nothing called these until this pass ran. Reported
                // rather than disassembled into existence -- see the note in the image-setup guide.
                Function t = isCodeAddr(tgt) ? fm.getFunctionAt(wa(tgt)) : null;
                if (t == null) {
                    notFn++;
                    println(String.format("  base %05x in %-20s -> %05x is not a function entry"
                        + " -- skipped", in.getAddress().getOffset() / 2, f.getName(), tgt));
                    continue;
                }
                if (!addRef(in.getAddress(), wa(tgt), RefType.COMPUTED_CALL)) continue;
                added++;
                // Same reasoning as the registry slots and the hooks: a RAM word the code
                // provably calls through is a function-pointer global, so type it (#61).
                if (lastSlot >= 0 && !inFlash(lastSlot)) typeFunctionPointer(lastSlot);
                println(String.format("  base %05x in %-20s -> %s%s",
                    in.getAddress().getOffset() / 2, f.getName(), t.getName(),
                    lastSlot >= 0 ? String.format("   [via %05x]", lastSlot) : ""));
            }
        }
        println(String.format("  base resolution: %d unresolved computed call(s), %d propagated to a"
            + " single address, %d of those into an accepted table (a cursor), %d not a function entry",
            sites, resolved, cursors, notFn));
        return added;
    }

    boolean hasCallRef(Instruction in) {
        for (Reference r : rm.getReferencesFrom(in.getAddress()))
            if (r.getReferenceType().isCall()) return true;
        return false;
    }

    /** `LC *XAR7` bakes its register into the mnemonic display rather than an operand. */
    static final java.util.regex.Pattern CALL_REG =
        java.util.regex.Pattern.compile("\\*(XAR[0-7])(?![0-9A-Za-z])");

    /**
     * The register a computed call dispatches through.
     *
     * `LCR *XARn` carries it as an operand; `LC *XAR7` spells it in the display, so an
     * operand-only reading skips those sites silently. `XCALL *AL` is deliberately not matched:
     * its target is `0x3f0000 | AL`, not AL, so the register is not the address.
     */
    Register callThrough(Instruction call) {
        for (int i = 0; i < call.getNumOperands(); i++)
            for (Object o : call.getOpObjects(i)) if (o instanceof Register) return (Register) o;
        java.util.regex.Matcher m = CALL_REG.matcher(call.toString());
        return m.find() ? currentProgram.getRegister(m.group(1)) : null;
    }

    /** True when control can arrive at `in` other than by falling through its predecessor. */
    boolean isJoin(Instruction in) {
        for (Reference r : rm.getReferencesTo(in.getAddress())) {
            RefType t = r.getReferenceType();
            if (t.isJump() || t.isCall()) return true;
        }
        return false;
    }

    /**
     * The instruction that defines `reg` at `at`, or null.
     *
     * Straight-line only, and that is the whole safety argument for everything built on it: the
     * walk stops at the first instruction another path can branch to, so the definition it finds is
     * the one that reaches `at` under every execution — no merge of two candidate values can hide
     * behind it.
     */
    Instruction defOf(String reg, Instruction at, Function f, int budget) {
        Instruction cur = at;
        for (int k = 0; k < budget; k++) {
            if (isJoin(cur)) return null;
            Instruction p = cur.getPrevious();
            if (p == null || !f.getBody().contains(p.getAddress())) return null;
            Address ft = p.getFallThrough();
            if (ft == null || !ft.equals(cur.getAddress())) return null;
            if (writesReg(p, reg)) return p;
            cur = p;
        }
        return null;
    }

    /** The single value `reg` holds at `at`, or -1. */
    long regValue(String reg, Instruction at, Function f, int budget, int depth) {
        if (depth > MAX_DEPTH) return -1;
        Instruction p = defOf(reg, at, f, budget);
        if (p == null) return -1;
        // Only a MOVE defines a value we can read off. Arithmetic on a pointer register is how a
        // dispatcher indexes a table -- `MOVL XAR1,#0x9b506 ; ADDL @XAR1,ACC` walks one at runtime
        // -- and reading the ADDL as if it were a move hands back the table's FIRST element as
        // though it were the only target. Measured: exactly one confidently wrong edge on the first
        // image tried. Those walks are recovered whole by resolveStridedTables instead.
        String m = p.getMnemonicString();
        if (!m.equals("MOVL") && !m.equals("MOVB")) return -1;
        String[] ds = destSrc(p);
        // The write must be to the WHOLE register under one of the two spellings this module
        // renders (`XAR4` as an implicit destination, `@XAR4` as a loc32 operand). Anything else --
        // a 16-bit write to AR4, an unrecognized form -- is a clobber we cannot read, so the value
        // stops being provable here.
        if (ds == null) return -1;
        boolean narrow = reg.startsWith("AR") && ds[0].equals("X" + reg);      // MOVB XAR0,#imm
        if (!ds[0].equals(reg) && !ds[0].equals("@" + reg) && !narrow) return -1;
        long v = sourceValue(ds[1], p, f, budget, depth);
        return v < 0 || !narrow ? v : v & 0xFFFF;                              // ARn is XARn's low half
    }

    /** `MNEMONIC dst,src` split out of the rendered instruction, or null. */
    String[] destSrc(Instruction in) {
        String s = in.toString();
        int sp = s.indexOf(' ');
        if (sp < 0) return null;
        String ops = s.substring(sp + 1).trim();
        int comma = ops.indexOf(',');
        if (comma < 0) return null;
        return new String[]{ops.substring(0, comma).trim(), ops.substring(comma + 1).trim() };
    }

    /** Does `in` write `reg`, or any register overlapping it? */
    boolean writesReg(Instruction in, String reg) {
        for (Object o : in.getResultObjects()) {
            if (!(o instanceof Register)) continue;
            Register r = (Register) o;
            if (r.getName().equals(reg)) return true;
            for (Register q = r.getParentRegister(); q != null; q = q.getParentRegister())
                if (q.getName().equals(reg)) return true;
            List<Register> kids = r.getChildRegisters();
            if (kids != null) for (Register c : kids) if (c.getName().equals(reg)) return true;
        }
        return false;
    }

    /** The value of a rendered source operand at `p`: an immediate, a register, or a load. */
    long sourceValue(String src, Instruction p, Function f, int budget, int depth) {
        if (src.startsWith("#")) {
            try { return Long.decode(src.substring(1)); } catch (Exception e) { return -1; }
        }
        if (src.equals("ACC") || src.equals("@ACC")) return regValue("ACC", p, f, budget, depth + 1);
        if (src.matches("@?XAR[0-7]")) return regValue(src.replace("@", ""), p, f, budget, depth + 1);
        long slot = loadAddress(src, p, f, budget, depth);
        if (slot < 0) return -1;
        lastSlot = slot;                       // outermost load wins: it is assigned last
        return word32(slot);
    }

    /**
     * The address a load reads from.
     *
     * Where the address comes out of a REGISTER it is resolved here, by the same walk — never from
     * the reference Ghidra's constant propagator attached. That propagator keeps a value across
     * the very arithmetic that makes an address unprovable, so its reference on
     * `MOVL XAR7,*+XAR1[0x0]` names the first element of a table the dispatcher indexes at
     * runtime; believing it turns a MAY-call over N entries into a definite edge to entry 0.
     *
     * Where the address is a STATIC operand there is no register to prove and the reference is the
     * whole answer, so it is taken: `*(0:addr)` is absolute, and `@6bit` is DP-relative, which is
     * the DP analyzer's job rather than something to re-derive here.
     */
    long loadAddress(String src, Instruction p, Function f, int budget, int depth) {
        if (src.startsWith("*(0:") || src.matches("@0x[0-9a-fA-F]+|@\\d+")) return uniqueRef(p);
        if (src.matches("\\*XAR[0-7]")) return regValue(src.substring(1), p, f, budget, depth + 1);
        java.util.regex.Matcher m = INDEXED.matcher(src);
        if (!m.matches()) return -1;           // ++/--/SP/circular forms: not a fixed address
        long base = regValue(m.group(1), p, f, budget, depth + 1);
        if (base < 0) return -1;
        String idx = m.group(2);
        if (idx.startsWith("AR")) {
            long i = regValue(idx, p, f, budget, depth + 1);
            return i < 0 ? -1 : base + i;
        }
        try { return base + Long.decode(idx); } catch (Exception e) { return -1; }
    }

    // ---------------------------------------------------------------------------------------
    // strided dispatch tables, read out of the dispatcher
    // ---------------------------------------------------------------------------------------

    /** `MOV ACC,@AR6<<#0x1` / `LSL ACC,#0x2` — the index scale. */
    static final java.util.regex.Pattern SHIFT =
        java.util.regex.Pattern.compile(".*<<#?(0x[0-9a-fA-F]+|\\d+)");

    /** A pointer load feeding a computed call: `MOVL XARt,*+XARb[F]`. */
    static final class Load {
        String baseReg; long field; Instruction at;
        Load(String b, long f, Instruction a) { baseReg = b; field = f; at = a; }
    }

    /**
     * Recover the whole table behind `MOVL XARb,#base ; <scale> ; ADDL @XARb,ACC ; LCR *(XARb+F)`.
     *
     * This is the one dispatch shape base resolution deliberately refuses. The register is indexed
     * at runtime, so there is no single target — but every parameter of the walk is a literal in
     * the dispatcher's own instruction stream: the base is an immediate, the stride is the scale
     * applied to the index, and the field offset is the load's displacement. Nothing is carved by
     * guessing at a stride, which is the objection that keeps `discoverRuns` from being generalized:
     * here the code states the stride.
     *
     * Extent is the only thing the code does not always state, so it is read from the table itself:
     * walk records until one holds a word that is neither null nor code. Measured against the
     * bound a dispatcher DOES state (`CMPB AL,#0x12` guarding an 18-record table at 0x9b506), the
     * structural walk stops at exactly 18 — the 19th word is 0x01f400fa, plainly not a pointer.
     *
     * A record holding an address with an instruction already decoded at it, inside no function,
     * becomes a function: a table the code provably calls through is evidence, and that is the same
     * rule `targetsAt` applies to descriptor fields. An address with no instruction ends the table
     * rather than being disassembled into existence.
     *
     * The edges are MAY-calls, which is the honest shape for a loop over a table — the same thing
     * the descriptor pass emits, and for the same reason.
     */
    int resolveStridedTables(int maxBack, boolean createFns, int[] mk) {
        int minTargets = Integer.getInteger("c28x.reg.minTargets", 2);
        int sites = 0, walks = 0, tables = 0, added = 0, dataRefs = 0;
        for (Function f : fm.getFunctions(true)) {
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction in = ii.next();
                if (!in.getFlowType().isCall() || !in.getFlowType().isComputed()) continue;
                if (hasCallRef(in)) continue;
                Register reg = callThrough(in);
                if (reg == null) continue;
                sites++;
                Load ld = pointerLoad(reg.getName(), in, f, maxBack, 0);
                if (ld == null) continue;

                Indexed walk = indexedWalk(ld, f, maxBack);
                if (walk == null) continue;
                walks++;

                long stride = strideOf(walk.scale, f, maxBack);
                if (stride < 2) {
                    // Below 2 is not a record stride: a 32-bit function pointer occupies two
                    // words, so consecutive entries cannot be closer than that.
                    println(String.format("  %05x  strided walk on %s: index scale not recognized"
                        + " -- left alone", in.getAddress().getOffset() / 2, ld.baseReg));
                    continue;
                }
                List<Long> bases = walk.bases;
                if (bases == null || bases.isEmpty()) {
                    println(String.format("  %05x  strided walk on %s: base does not propagate"
                        + " -- left alone", in.getAddress().getOffset() / 2, ld.baseReg));
                    continue;
                }
                for (long base : bases) {
                    TableScan s = scanTable(base, stride, ld.field, createFns, mk);
                    if (s.targets.size() < minTargets) {
                        println(String.format("  %05x  table @%05x stride %d field +%d: only %d"
                            + " target(s) -- not accepted", in.getAddress().getOffset() / 2, base,
                            stride, ld.field, s.targets.size()));
                        continue;
                    }
                    tables++;
                    acceptedTables.add(new long[]{base, stride, s.records});
                    int n = emitTargets(in, s.targets);
                    added += n;
                    dataRefs += emitSlotRefs(base, stride, ld.field, s.records);
                    println(String.format("  %05x  table @%05x stride %d field +%d: %d records,"
                        + " %d target(s), %d edge(s)", in.getAddress().getOffset() / 2, base,
                        stride, ld.field, s.records, s.targets.size(), n));
                }
            }
        }
        println(String.format("  strided tables: %d unresolved computed call(s), %d indexed walk(s),"
            + " %d table(s) accepted, %d slot->handler data ref(s)", sites, walks, tables, dataRefs));
        return added;
    }

    /** Tables this run accepted: {base, stride, records}. Used to spot a cursor into one. */
    List<long[]> acceptedTables = new ArrayList<>();

    // A table record naming a RAM address with nothing decoded at it is NOT disassembled into a
    // function, and the measurement says leave it that way. Tried on the CPU2 image, gated on the
    // block already holding functions: 5 functions created, ZERO reachability (62.4% -> 62.2%,
    // diluted by its own new functions), because the dispatcher walking that table is itself
    // unreachable. The gate was also unsound -- SetupF28377D maps every SARAM bank executable, and
    // the GS bank holding the component structs qualified as "code" because something had already
    // created a function in it. Risk with no return; the strict rule stands.

    /** One field of one table, walked to its end. */
    static final class TableScan { List<Long> targets = new ArrayList<>(); int records; }

    /**
     * Read `field` out of every record of the table at `base`, stopping where the table does.
     *
     * A record holds a null (no handler installed for that index), a function entry, or an address
     * with an instruction already decoded at it and no owning function -- that last one is a
     * handler SeedFunctions missed, and a table the code provably calls through is enough evidence
     * to make it a function. Anything else ends the table: that is what bounds the walk on an image
     * whose dispatcher does not state a count.
     */
    TableScan scanTable(long base, long stride, long field, boolean createFns, int[] mk) {
        int maxTable = Integer.getInteger("c28x.reg.maxTable", 256);
        int maxGap   = Integer.getInteger("c28x.reg.maxGap", 16);
        TableScan s = new TableScan();
        int gap = 0;
        for (int i = 0; i < maxTable; i++) {
            long v = word32(base + i * stride + field);
            if (v == 0) { if (++gap > maxGap) break; continue; }
            gap = 0;
            boolean ok = isCodeAddr(v) && fm.getFunctionAt(wa(v)) != null;
            if (!ok && createFns && isCodeAddr(v) && getInstructionAt(wa(v)) != null
                    && fm.getFunctionContaining(wa(v)) == null && makeFunction(v)) {
                mk[0]++;
                ok = true;
            }
            if (!ok) break;
            s.targets.add(v);
            s.records = i + 1;
        }
        return s;
    }

    int emitTargets(Instruction site, List<Long> targets) {
        int n = 0;
        for (long v : targets) if (addRef(site.getAddress(), wa(v), RefType.COMPUTED_CALL)) n++;
        return n;
    }

    int emitSlotRefs(long base, long stride, long field, int records) {
        int n = 0;
        for (int i = 0; i < records; i++) {
            long slot = base + i * stride + field, v = word32(slot);
            if (v != 0 && isCodeAddr(v) && fm.getFunctionAt(wa(v)) != null
                    && addRef(wa(slot), wa(v), RefType.DATA)) n++;
        }
        return n;
    }

    /** The accepted table whose extent covers `slot`, or null. */
    long[] tableContaining(long slot) {
        for (long[] t : acceptedTables)
            if (slot >= t[0] && slot < t[0] + t[2] * t[1]) return t;
        return null;
    }

    /** A `base + index*stride` computation feeding a dispatch load. */
    static final class Indexed {
        Instruction scale;        // what scaled the index -- the stride is read off it
        List<Long> bases;         // every table base that can reach the add
    }

    /**
     * The indexed walk behind a dispatch load, in either operand order.
     *
     * A compiler emits `base + i*stride` two ways, and both occur — the second is by far the
     * commoner on the CPU2 image, at 18 of its sites against 3 for the first:
     *
     *   1. accumulate into the POINTER:  MOVL XAR1,#base ; MOV ACC,i<<k ; ADDL @XAR1,ACC
     *   2. accumulate into the ACC:      MOVL XAR1,#base ; MOV ACC,i<<k ; ADDL ACC,@XAR1 ;
     *                                    MOVL XAR4,@ACC
     *
     * Same table either way. Shape 2 also lets the base arrive in a register or a global rather
     * than as a literal at that instruction, which is why the base is resolved through
     * `baseOperand` instead of being read straight off an immediate.
     */
    Indexed indexedWalk(Load ld, Function f, int maxBack) {
        Instruction def = defOf(ld.baseReg, ld.at, f, maxBack);
        if (def == null) return null;
        String[] ds = destSrc(def);
        if (ds == null) return null;
        String m = def.getMnemonicString();
        boolean isAdd = m.equals("ADDL") || m.equals("ADDU") || m.equals("ADD");

        if (isAdd && ds[1].equals("ACC")
                && (ds[0].equals("@" + ld.baseReg) || ds[0].equals(ld.baseReg))) {
            Indexed w = new Indexed();
            w.scale = defOf("ACC", def, f, maxBack);
            // Every base that can reach the add, not just one: two tables sharing a dispatch tail
            // is a real shape (an `SB` into the middle of the walk), and each is a genuine MAY-call
            // destination. If ANY reaching path is unprovable the site is skipped.
            w.bases = basesFrom(ld.baseReg, def.getPrevious(), f, maxBack, 0, new HashSet<Address>());
            return w;
        }
        if (m.equals("MOVL") && (ds[1].equals("ACC") || ds[1].equals("@ACC"))) {
            Instruction add = defOf("ACC", def, f, maxBack);
            if (add == null) return null;
            String[] as = destSrc(add);
            String am = add.getMnemonicString();
            if (as == null || !as[0].equals("ACC")) return null;
            if (!am.equals("ADDL") && !am.equals("ADDU") && !am.equals("ADD")) return null;
            Indexed w = new Indexed();
            w.scale = defOf("ACC", add, f, maxBack);
            w.bases = baseOperand(as[1], add, f, maxBack);
            return w;
        }
        return null;
    }

    /** The table base an `ADDL ACC,<x>` adds in: a literal, a register, or a global holding one. */
    List<Long> baseOperand(String src, Instruction add, Function f, int maxBack) {
        if (src.startsWith("#")) {
            try { return new ArrayList<>(List.of(Long.decode(src.substring(1)))); }
            catch (Exception e) { return null; }
        }
        if (src.matches("@?XAR[0-7]"))
            return basesFrom(src.replace("@", ""), add.getPrevious(), f, maxBack, 0,
                new HashSet<Address>());
        if (src.startsWith("*(0:") || src.matches("@0x[0-9a-fA-F]+|@\\d+")) {
            long slot = uniqueRef(add);
            if (slot < 0) return null;
            long v = word32(slot);
            return v <= 0 ? null : new ArrayList<>(List.of(v));
        }
        return null;                   // *XARn++ and friends: not a fixed base
    }

    /** The `MOVL XARt,*+XARb[F]` that puts the pointer in `reg`, chased through register copies. */
    Load pointerLoad(String reg, Instruction at, Function f, int budget, int depth) {
        if (depth > MAX_DEPTH) return null;
        Instruction p = defOf(reg, at, f, budget);
        if (p == null || !p.getMnemonicString().equals("MOVL")) return null;
        String[] ds = destSrc(p);
        if (ds == null || (!ds[0].equals(reg) && !ds[0].equals("@" + reg))) return null;
        String src = ds[1];
        if (src.equals("ACC") || src.equals("@ACC"))
            return pointerLoad("ACC", p, f, budget, depth + 1);
        if (src.matches("@?XAR[0-7]"))
            return pointerLoad(src.replace("@", ""), p, f, budget, depth + 1);
        if (src.matches("\\*XAR[0-7]")) return new Load(src.substring(1), 0, p);
        java.util.regex.Matcher m = INDEXED.matcher(src);
        if (!m.matches()) return null;
        String idx = m.group(2);
        long field;
        if (idx.startsWith("AR")) {
            field = regValue(idx, p, f, budget, 1);
            if (field < 0) return null;
        }
        else {
            try { field = Long.decode(idx); } catch (Exception e) { return null; }
        }
        return new Load(m.group(1), field, p);
    }

    /**
     * The record stride the index was scaled by, in words, or -1.
     *
     * A shift is the compiler's usual scale; a multiply appears when the record size is not a power
     * of two (`MOVB ACC,#0xc ; MOVL @XT,ACC ; IMPYL ACC,XT,@ACC` — a 12-word record). An unscaled
     * index is stride 1. The cap rejects a shift that is plainly building a 32-bit value out of two
     * halves rather than indexing anything.
     */
    long strideOf(Instruction scale, Function f, int budget) {
        if (scale == null) return -1;
        String s = scale.toString();
        int sp = s.indexOf(' ');
        if (sp < 0) return -1;
        String[] ops = s.substring(sp + 1).trim().split(",");
        if (ops.length == 0 || !ops[0].trim().equals("ACC")) return -1;
        String m = scale.getMnemonicString();
        long stride = -1;
        if (m.startsWith("MPY") || m.startsWith("IMPY")) {
            for (int i = 1; i < ops.length && stride < 0; i++) {
                String o = ops[i].trim().replace("@", "");
                if (o.startsWith("#")) { try { stride = Long.decode(o.substring(1)); } catch (Exception e) { } }
                else if (o.matches("XT|T|ACC|XAR[0-7]|AR[0-7]|AL|AH")) {
                    long v = regValue(o, scale, f, budget, 1);
                    if (v > 0) stride = v;
                }
            }
        }
        else if (ops.length >= 2) {
            String src = ops[ops.length - 1].trim();
            java.util.regex.Matcher sh = SHIFT.matcher(m.equals("LSL") ? "<<" + src : src);
            if (sh.matches()) {
                try { stride = 1L << Long.decode(sh.group(1)); } catch (Exception e) { return -1; }
            }
            else if (m.equals("MOV") || m.equals("MOVU") || m.equals("MOVZ") || m.equals("MOVL")) {
                stride = 1;                     // an unscaled index: one word per record
            }
        }
        return stride >= 1 && stride <= 0x400 ? stride : -1;
    }

    /**
     * Every immediate `reg` can hold at `p` (inclusive), across the paths that reach it, or null
     * when any of them is unprovable.
     *
     * Straight-line while nothing branches in; at a join, each predecessor is resolved separately
     * and the results unioned, so a dispatch tail two `MOVL XARb,#table` sites share yields both
     * tables. Bounded in depth and guarded against revisiting a join, so a loop back-edge gives up
     * rather than spinning.
     */
    List<Long> basesFrom(String reg, Instruction p, Function f, int budget, int depth,
            Set<Address> seen) {
        if (depth > 2) return null;
        for (int k = 0; k < budget; k++) {
            if (p == null || !f.getBody().contains(p.getAddress())) return null;
            if (writesReg(p, reg)) {
                String[] ds = destSrc(p);
                String m = p.getMnemonicString();
                if (ds == null || (!m.equals("MOVL") && !m.equals("MOVB"))) return null;
                if (!ds[0].equals(reg) && !ds[0].equals("@" + reg)) return null;
                if (!ds[1].startsWith("#")) return null;
                try { return new ArrayList<>(List.of(Long.decode(ds[1].substring(1)))); }
                catch (Exception e) { return null; }
            }
            Instruction prev = p.getPrevious();
            boolean flows = prev != null && f.getBody().contains(prev.getAddress())
                && prev.getFallThrough() != null && prev.getFallThrough().equals(p.getAddress());
            List<Instruction> jumped = jumpPredecessors(p, f);
            if (!jumped.isEmpty()) {
                if (!seen.add(p.getAddress())) return null;
                LinkedHashSet<Long> out = new LinkedHashSet<>();
                for (Instruction q : jumped) {
                    List<Long> sub = basesFrom(reg, q, f, budget, depth + 1, seen);
                    if (sub == null) return null;
                    out.addAll(sub);
                }
                if (flows) {
                    List<Long> sub = basesFrom(reg, prev, f, budget, depth + 1, seen);
                    if (sub == null) return null;
                    out.addAll(sub);
                }
                return new ArrayList<>(out);
            }
            if (!flows) return null;
            p = prev;
        }
        return null;
    }

    /** Instructions inside `f` that jump to `in`. */
    List<Instruction> jumpPredecessors(Instruction in, Function f) {
        List<Instruction> out = new ArrayList<>();
        for (Reference r : rm.getReferencesTo(in.getAddress())) {
            if (!r.getReferenceType().isJump()) continue;
            Address from = r.getFromAddress();
            if (!f.getBody().contains(from)) continue;
            Instruction q = getInstructionAt(from);
            if (q != null) out.add(q);
        }
        return out;
    }

    /** The one address `p` references, or -1 when it references none or several. */
    long uniqueRef(Instruction p) {
        Address only = null;
        for (Reference r : rm.getReferencesFrom(p.getAddress())) {
            RefType t = r.getReferenceType();
            if (t.isFlow() || t.isCall() || t.isJump()) continue;
            if (only != null && !only.equals(r.getToAddress())) return -1;
            only = r.getToAddress();
        }
        return only == null ? -1 : only.getOffset() / 2;
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
                // The RAM slots the candidates were read out of, kept so a proven hook
                // can have its slot typed as a function pointer (#61).
                Set<Long> hookSlots = new LinkedHashSet<>();
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
                        if (fnAt(v) != null) { cands.add(v); hookSlots.add(slot); }
                    }
                }
                if (cands.size() != 1) continue;                            // ambiguous -> leave alone
                long tgt = cands.iterator().next();
                if (addRef(in.getAddress(), wa(tgt), RefType.COMPUTED_CALL)) {
                    done++;
                    // Same reasoning as the registry slots: the hook slot is a RAM
                    // function-pointer global, so type it for the store-tracking pass.
                    for (long slot : hookSlots) typeFunctionPointer(slot);
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

    /**
     * Type a proven RAM function-pointer slot as {@code pointer to FunctionDefinition}.
     *
     * <p>This is what makes the slot visible to TMS320C28xCodePointerAnalyzer, whose
     * only trigger is a store into data already typed that way. Without it that
     * analyzer has nothing to fire on and silently recovers nothing (#61).
     *
     * <p>Only RAM slots are typed. A flash slot is a constant, never a store
     * destination, so typing one buys nothing; the RAM slots ARE the globals that
     * code writes at runtime, which is exactly the set the store-tracking analyzer
     * exists to follow.
     *
     * <p>Applying a pointer type here is safe despite the wordsize=2 space: Ghidra
     * resolves the stored value through the space's addressable-unit size, so a
     * stored WORD address lands on the right word. Measured on a production image --
     * all 344 pointer-typed slots resolved to value*2, none to value-as-bytes. (The
     * older warning in MarkCodePointers.java's header says otherwise; it does not
     * hold on Ghidra 12.x.)
     */
    boolean typeFunctionPointer(long slotWord) {
        if (dry) return false;
        Address at = wa(slotWord);
        try {
            ghidra.program.model.data.DataTypeManager dtm = currentProgram.getDataTypeManager();
            if (fnPtrType == null) {
                ghidra.program.model.data.FunctionDefinitionDataType def =
                    new ghidra.program.model.data.FunctionDefinitionDataType(
                        new ghidra.program.model.data.CategoryPath("/C28x"), "code_ptr_target", dtm);
                fnPtrType = new ghidra.program.model.data.PointerDataType(def, 4, dtm);
                fnPtrType = dtm.resolve(fnPtrType, null);
            }
            Data existing = currentProgram.getListing().getDefinedDataAt(at);
            if (existing != null && fnPtrType.isEquivalent(existing.getDataType())) return false;
            currentProgram.getListing().clearCodeUnits(at, at.add(3), false);
            currentProgram.getListing().createData(at, fnPtrType);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    ghidra.program.model.data.DataType fnPtrType;

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
     * On C28x the PIE vector table itself is RAM (F28377D: 0x000D00 upward, one vector every 2
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
     * Corroborated against the firmware's own copy: the image's InitPieVectTable reads
     * `MOVL XAR4,#0xd00 ; MOVL XAR5,#0x9a94a ; MOV ACC,@0x1d ; LSL ACC,#1 ; LCR memcpyWords`,
     * i.e. base 0x9a94a and 0xe0 = 224 entries -- both exactly what this scan derives. Anchoring
     * on that memcpy instead would drop the "entry 0 must be _c_int00" requirement, at the cost
     * of depending on the copy routine having been identified.
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

        int rooted = 0, made = 0, unresolved = 0, named = 0;
        // Slot -> target AND target -> slots. The rooting loop below walks distinct
        // targets, which on its own throws away the slot index -- and the slot index
        // is the entire naming signal, since it is the slot that says which peripheral
        // raises the interrupt. Keeping both directions also makes the shared-default
        // case detectable: a target sitting in many slots has no single identity.
        PieProfile profile = loadPieProfile();
        Map<Long, List<Integer>> slotsByTarget = new LinkedHashMap<>();
        LinkedHashSet<Long> targets = new LinkedHashSet<>();
        for (int i = 0; i < bestLen; i++) {
            long v = word32(bestBase + i * 2);
            targets.add(v);
            slotsByTarget.computeIfAbsent(v, k -> new ArrayList<>()).add(i);
            if (!dry) addRef(wa(bestBase + i * 2), wa(v), RefType.DATA);
        }
        if (profile != null) profile = validateAlignment(profile, slotsByTarget, dflt);
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
                Function host = fm.getFunctionContaining(wa(v));
                if (host != null) {
                    // A vector pointing INTO a function is a handler whose entry was never split
                    // out -- two routines emitted back to back and seeded as one. Say so: the
                    // body is already reachable through its host, but the call graph credits the
                    // wrong function and the vector cannot be named.
                    println(String.format("  vector target %05x is inside %s at +%d -- a missed"
                        + " function boundary, not a vector; re-seed or split it to name this one",
                        v, host.getName(), v - host.getEntryPoint().getOffset() / 2));
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

            // Name it after its vector, when the vector identifies it unambiguously.
            // A target occupying more than one slot is the unused-interrupt handler
            // (or some other shared stub) and naming it after whichever slot came
            // first would be a plain lie, so those keep their FUN_ name.
            List<Integer> slots = slotsByTarget.get(v);
            String vectorName = null;
            if (profile != null && slots != null && slots.size() == 1) {
                vectorName = profile.name(slots.get(0));
            }
            if (vectorName != null && labelIfUnnamed(v, vectorName)) named++;

            println(String.format("  ISR %05x %-22s %s", v,
                vectorName != null ? vectorName : f.getName(),
                v == dflt ? "(default/unused-interrupt handler)"
                          : slots != null && slots.size() > 1
                            ? String.format("(shared by %d vectors)", slots.size())
                            : ""));
            if (dry) continue;
            currentProgram.getSymbolTable().addExternalEntryPoint(f.getEntryPoint());
            if (getPlateComment(f.getEntryPoint()) == null) {
                String vectorNote = "";
                if (profile != null && slots != null) {
                    StringBuilder note = new StringBuilder();
                    for (int slot : slots) {
                        String id = profile.name(slot);
                        if (id == null) continue;
                        String description = profile.description(slot);
                        note.append("\nVector ").append(slot).append(": ").append(id);
                        if (description != null && !description.isEmpty()) {
                            note.append("  -- ").append(description);
                        }
                    }
                    vectorNote = note.toString();
                }
                setPlateComment(f.getEntryPoint(),
                    "Interrupt handler, from the PIE vector table's flash initializer.\n"
                    + "The PIE vector table itself is RAM written at runtime by InitPieVectTable, so in a "
                    + "static image it is empty and this handler has no caller. Registered as an entry point."
                    + vectorNote);
            }
        }
        println(String.format(
            "  PIE: %d handlers rooted, %d named from %s, %d functions created, %d targets unresolved",
            rooted, named, profile == null ? "(no profile)" : profile.profileName, made, unresolved));
        return rooted;
    }

    /**
     * Refuse to name anything unless the table lines up with the profile.
     *
     * Every name here rests on one unchecked assumption: that table entry N is
     * profile slot N. When that is off by even one, every name is confidently
     * wrong -- which is strictly worse for a reverse-engineering tool than no name
     * at all, because a wrong peripheral name gets believed and acted on.
     *
     * The check exploits the fact that most of the table is reserved: a slot TI
     * marks RESERVED should never carry a real handler, so a live handler landing
     * on one means the alignment is wrong (or this run is not a PIE table). Entry 0
     * is exempt -- the boot ROM keeps boot variables in the first slots, and images
     * are observed putting the entry point there.
     *
     * This is a sanity check, not a proof: an alignment can be wrong and still put
     * every handler on a non-reserved slot. It is cheap and it catches the common
     * off-by-a-few case, and when it fires the pass still roots the handlers -- it
     * just leaves them under their FUN_ names.
     */
    PieProfile validateAlignment(PieProfile profile, Map<Long, List<Integer>> slotsByTarget,
            long dflt) {
        List<String> mismatched = new ArrayList<>();
        for (Map.Entry<Long, List<Integer>> e : slotsByTarget.entrySet()) {
            if (e.getKey() == dflt) continue;                  // the unused-interrupt fill
            // Only a real handler says anything about alignment. Two things here are not one:
            //
            //   * a target that is not a function ENTRY. Measured on an F28377D CPU1 image, one
            //     value sat in six slots and resolved to FUN_0009098d+93 -- an address inside a
            //     merged body, i.e. a second unused-interrupt stub whose entry SeedFunctions did
            //     not split out. Three of its slots are reserved, and reading those as live
            //     handlers condemned a table that is provably aligned: slot 0 held the reset
            //     vector and slots 1-12 the default fill, which is exactly the 13 reserved
            //     entries `struct PIE_VECT_TABLE` opens with (and `InitPieVectTable` skips the
            //     first 3 of them, "initialized by Boot ROM with boot variables"), while every
            //     other occupied slot named a peripheral this ECU plainly has -- TIMER2, NMI,
            //     ADCB1, EPWM2 as a D0-RAM ramfunc, IPC2, CANA0/CANB0.
            //   * a target occupying SEVERAL slots. That is a shared stub -- another fill value --
            //     which the naming code below already refuses to name for the same reason.
            if (e.getValue().size() > 1) continue;
            if (fm.getFunctionAt(wa(e.getKey())) == null) continue;
            for (int slot : e.getValue()) {
                if (slot == 0) continue;                       // boot-variable slot
                String name = profile.name(slot);
                if (name != null && name.contains("_RESERVED_")) {
                    mismatched.add(String.format("slot %d (%s) <- %05x", slot, name, e.getKey()));
                }
            }
        }
        if (mismatched.isEmpty()) return profile;
        println("  PIE profile does NOT line up with this table -- not naming anything:");
        for (String m : mismatched) println("    live handler on a reserved " + m);
        println("    (a handler on a reserved vector means entry N is not slot N here;"
            + " re-check the table base, or the device profile is for the wrong part)");
        return null;
    }

    /**
     * PIE vector identities for one device: slot index -> TI's vector name.
     *
     * The slot order is a hardware fact published as the member order of
     * `struct PIE_VECT_TABLE` in TI's `<device>_pievect.h`; `tools/generate_pie_profile.py`
     * turns that into the JSON read here, so nothing is hand-transcribed. The names
     * and descriptions stay TI-derived (BSD-3-Clause) -- see THIRD-PARTY.md.
     */
    static final class PieProfile {
        String profileName;
        final Map<Integer, String> names = new HashMap<>();
        final Map<Integer, String> descriptions = new HashMap<>();

        String name(int slot) { return names.get(slot); }
        String description(int slot) { return descriptions.get(slot); }
    }

    /**
     * Load the vector profile for this program's language, or null when there is none.
     *
     * Absent or unreadable profile is not an error: the pass then behaves exactly as it
     * did before profiles existed, rooting handlers under their FUN_ names. A device
     * this module has no profile for is the normal case, not a broken setup.
     */
    PieProfile loadPieProfile() {
        // Profiles are keyed by language variant, the same way the Setup scripts are.
        String id = currentProgram.getLanguageID().getIdAsString();
        String name = (id.endsWith(":f2812") ? "f2812" : "f2837xd") + ".json";

        List<java.io.File> candidates = new ArrayList<>();
        String override = System.getProperty("c28x.reg.pieProfile");
        if (override != null) candidates.add(new java.io.File(override));
        try {
            // The idiomatic location once the module is installed as an extension.
            candidates.add(ghidra.framework.Application.getModuleDataFile(
                "ghidra-tms320c28x", "device_profiles/" + name).getFile(false));
        }
        catch (Exception ignored) {
            // Not installed as a module, or no such data file -- the paths below cover
            // running straight out of a checkout and out of a flat script directory.
        }
        java.io.File scriptDir = getSourceFile().getParentFile().getFile(false);
        if (scriptDir != null) {
            candidates.add(new java.io.File(scriptDir.getParentFile(),
                "data/device_profiles/" + name));
            candidates.add(new java.io.File(scriptDir, "device_profiles/" + name));
        }

        java.io.File file = null;
        for (java.io.File candidate : candidates) {
            if (candidate != null && candidate.isFile()) { file = candidate; break; }
        }
        if (file == null) {
            println("  no PIE profile for " + name + " on any known path"
                + " -- handlers keep their FUN_ names");
            return null;
        }
        try (java.io.Reader reader = new java.io.InputStreamReader(
                new java.io.FileInputStream(file), java.nio.charset.StandardCharsets.UTF_8)) {
            com.google.gson.JsonObject root =
                com.google.gson.JsonParser.parseReader(reader).getAsJsonObject();
            PieProfile profile = new PieProfile();
            profile.profileName = root.get("profileName").getAsString();
            for (com.google.gson.JsonElement element : root.getAsJsonArray("vectors")) {
                com.google.gson.JsonObject vector = element.getAsJsonObject();
                int slot = vector.get("slot").getAsInt();
                profile.names.put(slot, vector.get("name").getAsString());
                if (vector.has("description")) {
                    profile.descriptions.put(slot, vector.get("description").getAsString());
                }
            }
            println(String.format("  PIE profile %s: %d vectors (%s)",
                profile.profileName, profile.names.size(), file.getName()));
            return profile;
        }
        catch (Exception e) {
            println("  PIE profile unreadable (" + e + ") -- handlers keep their FUN_ names");
            return null;
        }
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
     * and on F28377D the PIE vector table that would name it lives in RAM from 0x000D00 and
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
