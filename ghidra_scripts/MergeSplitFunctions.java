// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Reunite functions that seeding cut in two.
//
// THE PROBLEM. SeedFunctions signal B seeds on a PROLOGUE run -- consecutive callee-saved pushes
// (`MOVL *SP++,XARn`, `MOV32 *SP++,RnH`). That signature is genuine, but it is not exclusive to a
// function's first instruction: a compiler emits the same pushes MID-function when it needs another
// callee-saved register partway through a body, and TI's does so constantly. At seed time nothing
// can tell the two apart -- no code has been decoded, so there is no "previous instruction" to ask.
// The seed lands inside a live function and splits it. The half with the prologue keeps the name and
// the callers; the half with the epilogue keeps the LRETR and inherits NOTHING, because a
// fall-through is not a reference. It then reads as dead code, and so does everything only it calls.
//
// Measured on an F28377D CPU2 image: 107 such splits stranded 377 of 826 unreachable functions --
// including a 1371-word body and the component framework's own registry-walk loop, whose 69
// recovered dispatch edges were all hanging off an entry nothing could reach.
//
// THE SIGNAL, and why it is safe. Compiled code enters a function by CALLING it. So an entry that
// (a) nothing references, by call, jump or data, and (b) whose address appears nowhere in the image
// as a 32-bit value -- no table can hold a pointer to it -- and (c) sits exactly on the fall-through
// of the instruction before it, is not an entry at all. It is the middle of the function before it.
// Requirement (d) makes it conclusive: that preceding function contains NO return instruction
// anywhere in its body, so it cannot be a complete function -- its epilogue is on the other side of
// the cut. All four held on 105 of 107 sites on the image above and 89 of 89 on a CPU1 image; the
// exceptions are refused, not repaired.
//
// This runs LATE, after disassembly and function bodies have settled (post-FinalizeRamfuncs), for
// the same reason the seeder cannot do it: the evidence is the decoded fall-through.
//
// A user-renamed function is never merged away -- only DEFAULT-named (FUN_/SUB_) splits are, so a
// name you applied to the far half survives, and re-running after one changes nothing. Every merge
// leaves an Analysis bookmark at the seam.
//
// Properties (-Dname=value):
//   c28x.split.dryRun       (bool, default false) report only; make no changes
//   c28x.split.rounds       (int,  default 4)     fixpoint cap (a split can chain into another)
//   c28x.split.allowOwnerRet(bool, default false) drop requirement (d) -- looser, less certain
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.HashSet;

public class MergeSplitFunctions extends GhidraScript {

    // run_ghidra_script / the MCP bridge deliver -Dkey=value as getScriptArgs(), not as JVM system
    // properties. Clear first: properties are JVM-global and survive between runs in one session.
    void promoteDashDArgs() {
        for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
            if (k.startsWith("c28x.split.")) System.clearProperty(k);
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

    long w(Address a) { return a.getOffset() / 2; }

    /** Every 32-bit little-endian value present in initialized memory, at any word alignment. */
    HashSet<Long> imageValues() {
        HashSet<Long> vals = new HashSet<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            Address a = b.getStart();
            long lo = w(a), hi = w(b.getEnd());
            for (long x = lo; x + 1 <= hi; x++) {
                try {
                    vals.add((currentProgram.getMemory().getShort(a.getNewAddress(x * 2)) & 0xFFFFL)
                        | ((currentProgram.getMemory().getShort(a.getNewAddress(x * 2 + 2))
                            & 0xFFFFL) << 16));
                } catch (Exception e) { /* unreadable word: nothing to record */ }
            }
        }
        return vals;
    }

    boolean hasReturn(Function f) {
        for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true))
            if (i.getFlowType().isTerminal()) return true;
        return false;
    }

    boolean defaultNamed(Function f) {
        String n = f.getName();
        return n.startsWith("FUN_") || n.startsWith("SUB_") || n.startsWith("thunk_FUN_");
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        boolean dry = Boolean.getBoolean("c28x.split.dryRun");
        boolean allowRet = Boolean.getBoolean("c28x.split.allowOwnerRet");
        int rounds = Integer.getInteger("c28x.split.rounds", 4);
        var fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        HashSet<Long> vals = imageValues();
        println("32-bit values present in the image: " + vals.size());

        int merged = 0, refused = 0;
        HashSet<Long> refusedAt = new HashSet<>();
        for (int round = 1; round <= rounds; round++) {
            ArrayList<Function> cands = new ArrayList<>();
            for (Function f : fm.getFunctions(true)) cands.add(f);
            int inRound = 0;
            for (Function f : cands) {
                if (monitor.isCancelled()) break;
                Address entry = f.getEntryPoint();
                if (fm.getFunctionAt(entry) == null) continue;      // merged away earlier this round
                if (!defaultNamed(f)) continue;
                if (rm.getReferenceCountTo(entry) > 0) continue;    // (a) something points at it
                if (vals.contains(w(entry))) continue;              // (b) a table could hold it

                Instruction prev = getInstructionBefore(entry);
                if (prev == null) continue;
                Address ft = prev.getFallThrough();
                if (ft == null || !ft.equals(entry)) continue;      // (c) not entered by fall-through

                Function owner = fm.getFunctionContaining(prev.getAddress());
                if (owner == null || owner.getEntryPoint().equals(entry)) continue;
                if (owner.getBody().intersects(f.getBody())) continue;
                if (!allowRet && hasReturn(owner)) {                // (d) owner looks complete
                    if (refusedAt.add(w(entry))) {
                        refused++;
                        println(String.format("  refused %05x <- %05x %s: the owner already returns"
                            + " somewhere, so it may be a whole function", w(entry),
                            w(owner.getEntryPoint()), owner.getName()));
                    }
                    continue;
                }

                println(String.format("%s %05x (%d words) into %05x %s", dry ? "would merge" : "merge",
                    w(entry), f.getBody().getNumAddresses() / 2, w(owner.getEntryPoint()),
                    owner.getName()));
                if (dry) { merged++; inRound++; continue; }

                AddressSetView body = new AddressSet(owner.getBody()).union(f.getBody());
                fm.removeFunction(entry);
                try {
                    owner.setBody(body);
                } catch (Exception e) {
                    // put the split back rather than leaving the half orphaned with no function
                    println("  FAILED to extend " + owner.getName() + ": " + e.getMessage()
                        + " -- restoring " + String.format("%05x", w(entry)));
                    new ghidra.app.cmd.function.CreateFunctionCmd(entry)
                        .applyTo(currentProgram, monitor);
                    continue;
                }
                if (owner.hasNoReturn() && hasReturn(owner)) owner.setNoReturn(false);
                currentProgram.getBookmarkManager().setBookmark(entry, "Analysis",
                    "c28x-merged-split", "seeded mid-function; merged back into "
                        + owner.getName());
                merged++;
                inRound++;
            }
            println("round " + round + ": " + inRound + " merge(s)");
            if (inRound == 0 || dry) break;
        }

        println("");
        println(merged + " split function(s) " + (dry ? "would be merged" : "merged")
            + ", " + refused + " refused");
        if (merged > 0 && !dry)
            println("re-run ReachabilityReport: everything those halves called is now reachable"
                + " through the function that actually contains them.");
    }
}
