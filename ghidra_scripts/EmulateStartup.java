// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Materialize a C28x image's RAM by EXECUTING its own startup code instead of reimplementing it.
//
// MaterializeSections and MaterializeCopyTable each re-implement one startup mechanism in Java:
// the memcpy-with-constant-args form, and the TI copy table (including a hand-written LZSS
// decoder). That works, but it only ever covers the mechanisms someone has already reversed --
// a new handler index, a different record layout, or the INLINED .cinit walk that TI emits
// straight into _c_int00 all need fresh Java. The firmware already contains a correct
// implementation of all of them. This script runs it.
//
// Now that SeedFunctions signal D recovers _c_int00, the startup path has an entry point, so the
// emulator can be pointed at it and left to copy flash into RAM exactly as the silicon would --
// cinit records, copy tables, compressed or raw, known handler or not.
//
// WHAT IT RUNS, AND WHERE IT STOPS. Execution starts at _c_int00 and stops when it reaches the
// application: _args_main / main / exit. Two things are deliberately NOT executed:
//
//   * __TI_auto_init -- despite the name this is the global-constructor / init-array runner (it
//     walks fn-ptr arrays and LCRs through them), not the copy-table walker. Running it means
//     executing arbitrary application code, which is neither needed for data init nor safe.
//   * indirect calls (LCR *XARn) -- the .pinit constructor loop. Same reasoning; re-enable with
//     -Dc28x.emu.enterIndirect=true.
//
// Everything else executes, including _system_pre_init (2 instructions) and the inlined .cinit
// PREAD loop, which is the mechanism no materializer currently implements.
//
// WHAT IT WRITES BACK. Ghidra's own write tracking (enableMemoryWriteTracking) records every
// address the emulated code stored to. Only writes landing in RAM blocks are applied to the
// program -- matched by block name, which SetupF28377D spells `*_RAM` / `*MSGRAM*` (M0/M1, LS0-5,
// D0/D1, GS0-15, the CPU<->CPU message RAMs). Writes to peripheral frames are startup poking the
// hardware, and writing those values into the MMIO blocks would invent state the silicon never
// holds, so they are counted and discarded. Flash is never written.
//
// WHY THIS MATTERS BEYOND THE BYTES. On a component/task-dispatch firmware the dispatcher calls
// through a function-pointer registry that .cinit fills in at runtime. Until those pointers exist
// in RAM there is no reference for Ghidra to follow, so genuinely live handlers look unreferenced
// and ReachabilityReport reports almost the whole image as unreachable. Replaying startup puts the
// pointers where the hardware would, which is what turns them into real references.
//
// DRY RUN BY DEFAULT -- it reports what it would change and touches nothing. Pass the script
// argument `apply` to write.
//
// Properties / args:
//   apply                    (script arg)          actually write (default: dry run)
//   c28x.emu.entry           (0xWORD, default auto) start address; auto = _c_int00 / entry point
//   c28x.emu.maxSteps        (int,  default 2000000) instruction budget
//   c28x.emu.enterIndirect   (bool, default false)  step INTO indirect calls (.pinit ctors)
//   c28x.emu.ramBlocks       (regex, default below) which blocks may be written back
//   c28x.emu.disasm          (bool, default true)   disassemble written regions that are called
//
// @category TMS320C28x
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.pcode.memstate.MemoryFaultHandler;
import java.util.*;

public class EmulateStartup extends GhidraScript {

    AddressSpace space;
    Address wa(long w) { return space.getAddress(w * 2); }

    // run_ghidra_script / the MCP bridge deliver -Dkey=value as getScriptArgs(), NOT as JVM system
    // properties, so the c28x.emu.* overrides silently no-op over MCP/headless. Promote any
    // -Dkey=value (or bare -Dkey -> "true") script arg to a real property first. The bare `apply`
    // arg is read separately below and is unaffected.
    // Clear first: system properties are JVM-global and survive between script runs in one Ghidra
    // session, so a flag passed once would stay set for every later run in that session.
    // Clear only what a PREVIOUS RUN OF THIS SCRIPT promoted, though -- not every c28x.emu.*
    // property. A blanket clear also destroys a genuine JVM -D, which is the only way to set
    // these on Windows: analyzeHeadless.bat truncates a script argument at its first '=', so
    // docs/C28X_IMAGE_SETUP.md tells you to pass them through JAVA_TOOL_OPTIONS instead. Wiping
    // those made every documented -Dc28x.emu.* override silently no-op there.
    private static final Set<String> PROMOTED = new HashSet<>();

    void promoteDashDArgs() {
        for (String k : PROMOTED) System.clearProperty(k);
        PROMOTED.clear();
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String a : args) {
            if (a == null || !a.startsWith("-D")) continue;
            String kv = a.substring(2);
            int eq = kv.indexOf('=');
            String k = eq > 0 ? kv.substring(0, eq) : kv;
            if (k.isEmpty()) continue;
            System.setProperty(k, eq > 0 ? kv.substring(eq + 1) : "true");
            PROMOTED.add(k);
        }
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();

        boolean apply = false;
        for (String a : getScriptArgs()) if (a.equalsIgnoreCase("apply")) apply = true;
        long maxSteps = Long.getLong("c28x.emu.maxSteps", 2000000L);
        int spinLimit = Integer.getInteger("c28x.emu.spinLimit", 200000);
        boolean enterIndirect = Boolean.getBoolean("c28x.emu.enterIndirect");
        String ramPat = System.getProperty("c28x.emu.ramBlocks", "(?i).*(RAM|MSGRAM).*");

        // --- entry ------------------------------------------------------------------------
        long entry = -1;
        String p = System.getProperty("c28x.emu.entry");
        if (p != null) entry = Long.decode(p.trim());
        if (entry < 0) {
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().toLowerCase().contains("c_int00")) { entry = f.getEntryPoint().getOffset() / 2; break; }
            }
        }
        if (entry < 0) {
            for (AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator(); it.hasNext(); ) {
                Address a = it.next();
                if (fm.getFunctionAt(a) != null) { entry = a.getOffset() / 2; break; }
            }
        }
        if (entry < 0) {
            println("no _c_int00 / entry point found. Run SeedFunctions first (signal D recovers it),");
            println("or pass -Dc28x.emu.entry=0xWORD.");
            return;
        }

        // --- where to stop, and what not to step into --------------------------------------
        TreeSet<Long> stopAt = new TreeSet<>(), skipCall = new TreeSet<>();
        for (Function f : fm.getFunctions(true)) {
            String n = f.getName();
            long w = f.getEntryPoint().getOffset() / 2;
            if (n.equals("main") || n.equals("_args_main") || n.equals("exit")) stopAt.add(w);
            if (n.equals("__TI_auto_init")) skipCall.add(w);
        }
        addWords(stopAt, System.getProperty("c28x.emu.stopAt"));
        addWords(skipCall, System.getProperty("c28x.emu.skip"));

        // No symbols? Derive the handoff from _c_int00's SHAPE, so this works on a program that
        // was analysed before signal D existed (where main is still some FUN_xxx). Same rule
        // SeedFunctions uses: the first call followed by `CMPB AL,#0 / SB join,EQ` is
        // _system_pre_init, and the call sitting AT that join target is the application handoff --
        // _args_main, then exit. Without this the run sails past the end of _c_int00 into whatever
        // function follows it in flash and faults there, long after the useful work is done.
        if (stopAt.isEmpty()) {
            long[] derived = deriveHandoff(entry);
            if (derived != null) {
                for (long d : derived) if (d >= 0) stopAt.add(d);
                println(String.format("derived the handoff from _c_int00's shape: %s "
                    + "(no main/_args_main/exit symbols in this program)", hexSet(stopAt)));
            }
            else {
                println("WARNING: no main/_args_main/exit symbol and the handoff could not be derived "
                    + "-- relying on the step budget, which will overrun the end of _c_int00. "
                    + "Pass -Dc28x.emu.stopAt=0xWORD, or re-run SeedFunctions to name the runtime.");
            }
        }

        println(String.format("entry _c_int00 @%05x | stop at %s | skip calls to %s",
            entry, hexSet(stopAt), hexSet(skipCall)));

        // --- emulate -------------------------------------------------------------------------
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        long steps = 0, skipped = 0, indirectSkipped = 0;
        String stopReason;
        try {
            // A flash-only dump has no RAM contents, and startup legitimately reads RAM it has
            // not written yet (a .cinit record's destination, a zeroed .bss). Faulting on that
            // would abort the replay, so uninitialized reads yield zeros -- which is what the
            // silicon's RAM holds after reset for our purposes.
            emu.setMemoryFaultHandler(new MemoryFaultHandler() {
                public boolean uninitializedRead(Address a, int size, byte[] buf, int bufOffset) { return true; }
                public boolean unknownAddress(Address a, boolean write) { return true; }
            });
            emu.enableMemoryWriteTracking(true);
            emu.writeRegister("PC", entry);
            // Seed SP inside M1 so the first pushes land somewhere mapped; _c_int00's own
            // `MOV @SP,#imm` overwrites this within a few instructions anyway.
            emu.writeRegister("SP", 0x500L);

            // Visit counts, so a run that does not reach the handoff can say WHERE it went
            // instead of only that it ran out of budget. A startup replay that overruns is
            // almost always parked in one tight loop -- a poll on a peripheral status bit the
            // emulator does not model will never fall through, and no budget rescues it.
            java.util.HashMap<Long, Integer> visits = new java.util.HashMap<>();

            while (true) {
                long pc = emu.readRegister("PC").longValue() & 0xFFFFFFFFL;
                if (stopAt.contains(pc)) { stopReason = "reached the application @" + Long.toHexString(pc); break; }
                if (steps >= maxSteps) { stopReason = "step budget (" + maxSteps + ") exhausted"; break; }

                // Spin guard. A startup that overruns is parked in one loop, and burning the
                // whole budget to say only "exhausted" wastes a minute and names nothing. A
                // count loop whose bound came out of RAM the replay has not written yet reads
                // 0, wraps to 0xFFFFFFFF and runs ~4 billion times -- so any single address
                // reached this often is stuck, not busy.
                int n = visits.merge(pc, 1, Integer::sum);
                if (n >= spinLimit) {
                    stopReason = "spinning at " + Long.toHexString(pc) + " (" + n
                        + " visits) -- loop bound never reached";
                    break;
                }

                // Decide whether to step OVER this instruction rather than into it.
                Instruction ins = insAt(pc);
                if (ins != null && ins.getFlowType().isCall()) {
                    Address[] flows = ins.getFlows();
                    boolean indirect = (flows == null || flows.length == 0);
                    long tgt = indirect ? -1 : flows[0].getOffset() / 2;
                    // Reaching the CALL to the application is the handoff -- stop here. Stepping
                    // over it instead would run off the end of _c_int00 into whatever function
                    // follows it in flash and fault there, long after the useful work was done.
                    if (!indirect && stopAt.contains(tgt)) {
                        stopReason = "startup handed off to the application (call @"
                            + Long.toHexString(pc) + " -> " + Long.toHexString(tgt) + ")";
                        break;
                    }
                    if ((indirect && !enterIndirect) || (!indirect && skipCall.contains(tgt))) {
                        emu.writeRegister("PC", pc + ins.getLength() / 2);
                        if (indirect) indirectSkipped++; else skipped++;
                        steps++;
                        continue;
                    }
                }
                if (!emu.step(monitor)) {
                    stopReason = "FAULT at " + Long.toHexString(pc) + ": " + emu.getLastError();
                    break;
                }
                steps++;
            }
            println(String.format("stopped: %s  (%d steps, %d direct calls stepped over, %d indirect)",
                stopReason, steps, skipped, indirectSkipped));

            if (!stopReason.startsWith("startup handed off") && !stopReason.startsWith("reached the")) {
                // Name the hot loop. The contiguous run of top addresses IS the spin, and the
                // instruction at its head is what to skip or stop at on the next run.
                java.util.List<java.util.Map.Entry<Long, Integer>> hot =
                    new ArrayList<>(visits.entrySet());
                hot.sort((x, y) -> y.getValue() - x.getValue());
                println("hottest addresses (a tight cluster here is the loop it never left):");
                for (int i = 0; i < Math.min(8, hot.size()); i++) {
                    long a = hot.get(i).getKey();
                    Instruction ins = insAt(a);
                    Function f = fm.getFunctionContaining(wa(a));
                    println(String.format("  %05x  x%-9d %-28s %s", a, hot.get(i).getValue(),
                        ins == null ? "?" : ins.toString(), f == null ? "" : f.getName()));
                }
                println("distinct addresses executed: " + visits.size());
                // Name the concrete remedy rather than leaving the reader to work it out: the
                // function containing the hot address is what to step over on the next run.
                if (!hot.isEmpty()) {
                    Function stuck = fm.getFunctionContaining(wa(hot.get(0).getKey()));
                    if (stuck != null) {
                        println("to step over it:  -Dc28x.emu.skip=0x"
                            + Long.toHexString(stuck.getEntryPoint().getOffset() / 2)
                            + "   (" + stuck.getName() + ")");
                    }
                }
            }

            // --- harvest ------------------------------------------------------------------
            AddressSetView written = emu.getTrackedMemoryWriteSet();
            if (written == null || written.isEmpty()) {
                println("no memory writes recorded -- nothing to materialize.");
                return;
            }
            // Split the write set into RAM (keep) and everything else (report + discard).
            AddressSet keep = new AddressSet();
            long otherWords = 0;
            for (AddressRange r : written) {
                MemoryBlock b = mem.getBlock(r.getMinAddress());
                boolean isRam = b != null && b.getName().matches(ramPat) && !b.getName().matches("(?i).*ROM.*");
                if (isRam) keep.add(r); else otherWords += r.getLength() / 2;
            }
            println(String.format("writes: %d words into RAM, %d words elsewhere (peripheral/MMIO -- discarded)",
                keep.getNumAddresses() / 2, otherWords));

            ArrayList<long[]> regions = new ArrayList<>();      // {startWord, words}
            for (AddressRange r : keep) {
                long s = r.getMinAddress().getOffset() / 2, n = r.getLength() / 2;
                regions.add(new long[]{s, n});
                MemoryBlock b = mem.getBlock(r.getMinAddress());
                println(String.format("  %05x..%05x  %5d words  %s", s, s + n - 1, n,
                    b == null ? "?" : b.getName()));
            }
            // A replay that never reached the handoff has NOT finished initializing RAM. At best
            // the state is mid-.cinit; at worst the run is spinning on a peripheral the emulator
            // does not model, and the recorded write set is the same few regions rewritten
            // thousands of times. Materializing that is far worse than materializing nothing,
            // because the garbage then feeds disassembly and the reference graph: measured on a
            // gen32 DIR image, applying a budget-exhausted replay wrote 666,662 words (more than
            // the device HAS of RAM) and took reachability from 81% to 8.2%.
            boolean cleanStop = stopReason.startsWith("startup handed off")
                    || stopReason.startsWith("reached the application");
            if (!cleanStop) {
                println("\nWARNING: the replay did not reach the application handoff.");
                println("  " + stopReason);
                println("  The write set above is a PARTIAL or runaway startup state, not the RAM"
                        + " image the firmware actually reaches.");
            }
            if (!apply) {
                println("\nDRY RUN -- nothing written. Re-run with the script argument `apply` to materialize.");
                return;
            }
            if (!Boolean.getBoolean("c28x.emu.applyIncomplete") && !cleanStop) {
                println("\nREFUSING TO APPLY -- nothing written.");
                println("  Raise the budget with -Dc28x.emu.maxSteps, name the handoff with");
                println("  -Dc28x.emu.stopAt=0xWORD, or step over what blocks it with");
                println("  -Dc28x.emu.skip=0xWORD. To materialize the partial state anyway, pass");
                println("  -Dc28x.emu.applyIncomplete=true.");
                return;
            }

            // --- apply --------------------------------------------------------------------
            int wroteRegions = 0;
            long wroteWords = 0;
            // A write run routinely SPANS BANKS: LS0..LS5, D0 and D1 are separate 2K blocks
            // (SetupF28377D splits them per SPRS880P Table 7-1), and a .cinit run like
            // 0x9300..0xba34 covers six of them. Initializing only the block at the region START
            // and then setBytes()-ing the whole run throws MemoryAccessException on the first byte
            // of the next, still-uninitialized bank -- which aborted the entire script, losing
            // every remaining region AND the code-binding pass below. Walk block by block, and
            // keep going when one bank cannot be written.
            for (long[] rg : regions) {
                long w = rg[0], end = rg[0] + rg[1];      // [w, end) in words
                boolean any = false;
                while (w < end) {
                    Address s = wa(w);
                    MemoryBlock b = mem.getBlock(s);
                    if (b == null) {
                        // Unmapped hole -- skip to the next mapped block rather than word by word.
                        long next = Long.MAX_VALUE;
                        for (MemoryBlock ob : mem.getBlocks()) {
                            long os = ob.getStart().getOffset() / 2;
                            if (os > w && os < next) next = os;
                        }
                        if (next == Long.MAX_VALUE) break;
                        w = Math.min(next, end);
                        continue;
                    }
                    long blockEnd = b.getEnd().getOffset() / 2 + 1;
                    long chunk = Math.min(end, blockEnd) - w;
                    if (!b.isInitialized()) {
                        try { mem.convertToInitialized(b, (byte) 0); }
                        catch (Exception e) {
                            println("  cannot initialize " + b.getName() + ": " + e);
                            w += chunk;
                            continue;
                        }
                    }
                    byte[] buf = emu.readMemory(s, (int) (chunk * 2));
                    try { currentProgram.getListing().clearCodeUnits(s, wa(w + chunk - 1), false); }
                    catch (Exception e) { }
                    try {
                        mem.setBytes(s, buf);
                        wroteWords += chunk;
                        any = true;
                    } catch (Exception e) {
                        println(String.format("  cannot write %05x..%05x in %s: %s",
                                w, w + chunk - 1, b.getName(), e.getMessage()));
                    }
                    w += chunk;
                }
                if (any) wroteRegions++;
            }
            println(String.format("materialized %d region(s), %d words", wroteRegions, wroteWords));

            // --- bind code that is actually called ---------------------------------------
            // Same rule MaterializeCopyTable uses: a written region holds CODE iff something
            // calls/jumps into it. Data regions (a .cinit-initialized struct, a float pool) must
            // stay data or they decode to halt_baddata.
            if (Boolean.parseBoolean(System.getProperty("c28x.emu.disasm", "true"))) {
                ReferenceManager rm = currentProgram.getReferenceManager();
                int made = 0, codeRegions = 0;
                for (long[] rg : regions) {
                    TreeSet<Long> targets = new TreeSet<>();
                    AddressIterator it = rm.getReferenceDestinationIterator(
                        new AddressSet(wa(rg[0]), wa(rg[0] + rg[1] - 1)), true);
                    while (it.hasNext()) {
                        Address d = it.next();
                        for (Reference r : rm.getReferencesTo(d)) {
                            RefType t = r.getReferenceType();
                            if (t.isCall() || t.isJump()) { targets.add(d.getOffset()); break; }
                        }
                    }
                    if (targets.isEmpty()) continue;
                    codeRegions++;
                    for (long off : targets)
                        new DisassembleCommand(space.getAddress(off), null, true).applyTo(currentProgram, monitor);
                    for (long off : targets) {
                        Address a = space.getAddress(off);
                        if (fm.getFunctionAt(a) == null && new CreateFunctionCmd(a).applyTo(currentProgram)) made++;
                    }
                }
                println(String.format("bound %d function(s) across %d called region(s)", made, codeRegions));
            }
            println("NOTE: run FinalizeRamfuncs after analysis settles, then re-run ReachabilityReport.");
        }
        finally {
            emu.dispose();
        }
    }

    /**
     * Find the application handoff by walking _c_int00 linearly (the startup code is laid out in
     * address order). Returns {_args_main, exit} as word addresses, or null if the shape does not
     * match -- in which case we say so rather than guessing.
     */
    long[] deriveHandoff(long entryWord) {
        ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(currentProgram);
        java.util.ArrayList<Instruction> ins = new java.util.ArrayList<>();
        long p = entryWord;
        for (int n = 0; n < 200; n++) {
            Instruction i;
            try { i = pd.disassemble(wa(p)); } catch (Exception e) { break; }
            if (i == null) break;
            ins.add(i);
            String m = i.getMnemonicString();
            if (m.equals("LRETR") || m.equals("LRET") || m.equals("IRET")) break;
            p += i.getLength() / 2;
        }
        long join = -1;
        for (int k = 0; k < ins.size(); k++) {
            Instruction i = ins.get(k);
            if (!i.getMnemonicString().equals("LCR")) continue;
            if (join < 0 && k + 2 < ins.size()
                    && ins.get(k + 1).getMnemonicString().equals("CMPB")
                    && ins.get(k + 2).getMnemonicString().equals("SB")) {
                join = flowWord(ins.get(k + 2));           // _system_pre_init's early-out target
                continue;
            }
            if (join >= 0 && i.getAddress().getOffset() / 2 == join) {
                long argsMain = flowWord(i);
                long exitFn = (k + 1 < ins.size() && ins.get(k + 1).getMnemonicString().equals("LCR"))
                    ? flowWord(ins.get(k + 1)) : -1;
                return new long[]{argsMain, exitFn};
            }
        }
        return null;
    }

    /** First flow target of an instruction as a WORD address, or -1. */
    long flowWord(Instruction i) {
        Address[] f = i.getFlows();
        if (f == null || f.length == 0) return -1;
        return f[0].getOffset() / 2;
    }

    /** Instruction at a word address: the listing's if present, else a read-only decode. */
    Instruction insAt(long word) {
        Address a = wa(word);
        Instruction i = currentProgram.getListing().getInstructionAt(a);
        if (i != null) return i;
        try { return new ghidra.app.util.PseudoDisassembler(currentProgram).disassemble(a); }
        catch (Exception e) { return null; }
    }

    void addWords(TreeSet<Long> set, String csv) {
        if (csv == null || csv.trim().isEmpty()) return;
        for (String s : csv.split(",")) if (!s.trim().isEmpty()) set.add(Long.decode(s.trim()));
    }

    String hexSet(TreeSet<Long> s) {
        if (s.isEmpty()) return "(none)";
        StringBuilder sb = new StringBuilder();
        for (long v : s) sb.append(sb.length() == 0 ? "" : ",").append(Long.toHexString(v));
        return sb.toString();
    }
}
