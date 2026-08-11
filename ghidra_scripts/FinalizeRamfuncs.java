// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Finalize materialized ramfuncs. Run AFTER MaterializeSections + auto-analysis have settled — both
// fixes below depend on background analysis having disassembled the RAM and applied its (bad) marks,
// which a script on the Swing/EDT thread cannot force (analyzeChanges throws there).
//
// (1) REBUILD STUBBED BODIES. MaterializeSections binds each ramfunc into a function immediately
//     after disassembling its entry, but background analysis has not yet decoded every fall-through,
//     so ~half the ramfuncs get a 1-word body while the rest of their instructions sit loose. Once
//     analysis has decoded them, delete+recreate each stub so CreateFunctionCmd binds the FULL body
//     (verified: 0x9669 1->0x47, 0xb779 1->0x23, 0x9856 1->0x16 — exactly the ground-truth sizes).
//     Only DEFAULT-named (FUN_xxx) stubs are touched; a user-renamed function is never disturbed.
//
// (1b) CLEAR STALE FLOW-ERROR BOOKMARKS. The import-time auto-analysis runs the disassembler BEFORE
//     these scripts materialize the RAM, so it drops a "Disassembly not permitted within uninitialized
//     memory block" (or "Could not follow disassembly flow into non-existing memory") error bookmark
//     at every call/branch into RAM-resident code. Once MaterializeSections has filled that RAM those
//     marks are STALE — the target now holds real bytes. This pass clears each whose flow target(s) are
//     now initialized ("uninitialized" marks) / mapped ("non-existing" marks); GENUINE cases (target
//     still uninitialized/unmapped) and missing-opcode marks ("Unable to resolve constructor") are LEFT
//     so real gaps (e.g. the SAT64/0x56xx SLEIGH backlog) stay visible. Runs always, honours dryRun.
//
// (2) UNDO FALSE NO-RETURN + REPAIR FLASH — now a BELT-AND-SUSPENDERS fallback. The module's
//     tms320c28x.pspec disables the two culprit analyzers BY DEFAULT (enableNoReturnAnalysis=false,
//     enableSharedReturnAnalysis=false), so on a normal import this pass finds nothing to repair (a
//     no-op that leaves the analysis options untouched). Its one real job is a ONE-TIME MIGRATION of a
//     program that already carries the truncation — one imported before the pspec change (its stored
//     options still have the analyzers on), or where they were manually re-enabled. It scans for the
//     damage first and only when it finds some does it disable BOTH analyzers again (so the repair
//     holds) and then repair. Background: "Non-Returning Functions - Discovered" flags a ramfunc
//     non-returning (its call-site heuristic misfires while the flash fall-through is not yet laid
//     down) and "Shared Return Calls" re-stamps CALL_RETURN on the same LCRs, deleting the flash
//     fall-through into `??` data (~94 sites for two ramfuncs on dir_26_65_2). Repair = for every
//     function that actually RETURNS (emits a RETURN p-code op) — RAM ramfunc OR FLASH function, since
//     a stale flag can ride in via a merge onto either — clear the false flag + the CALL_RETURN
//     overrides on its callers and re-disassemble the truncated flash. A post-hoc script cannot beat
//     the analyzers while they are LIVE (they re-fire and oscillate) — the pspec opt-out is the real
//     fix; with the analyzers off, this repair holds. It's an analyzer artifact; the LCR/LRETR SLEIGH
//     is correct (emits call/return).
//
// (3) REPAIR DISASSEMBLY CONFLICTS. A multi-word instruction whose trailing operand word is ALSO a
//     valid standalone opcode can be truncated when an errant flow decodes that operand word first —
//     Ghidra leaves "Failed to disassemble at A due to conflicting instruction at B". Common in the
//     FPU float code (MOV32 mem32 operand words). Clear [A,B] and re-disassemble A so it reclaims the
//     operand word. Because (2)'s fall-through re-disassembly can CREATE such conflicts, (2) and (3)
//     run together in a LOOP until neither changes anything. Happens on fresh imports too (ordering).
//
// Passes (2)+(3) cover BOTH RAM and flash (function entry no longer restricted to RAM), additive and
// idempotent; a normal import with no damage is a near no-op.
//
// Properties (-Dname=value):
//   c28x.finalize.dryRun  (bool, default false) report what would change; make no edits
//   c28x.finalize.stubMax (int,  default 1)     rebuild functions whose body is <= this many words
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.List;

public class FinalizeRamfuncs extends GhidraScript {
    MemoryBlock imageBlk;

    @Override
    public void run() throws Exception {
        boolean dryRun = Boolean.getBoolean("c28x.finalize.dryRun");
        long stubMax = Integer.getInteger("c28x.finalize.stubMax", 1);
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        // Flash image = largest initialized block; ramfuncs live in the OTHER (RAM) blocks.
        long bestLen = -1;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; imageBlk = b; }
        }
        if (imageBlk == null) { println("no initialized block"); return; }

        // (No-return + conflict detection has moved into the looped pass 2 below — the two repairs
        // interact, so they are detected and applied iteratively rather than scanned once up front.)

        // --- pass 1: rebuild stubbed RAM function bodies -----------------------------------------
        // Collect first (mutating the function set mid-iteration is unsafe); then delete ALL stubs,
        // then recreate — deleting all first stops an earlier recreate from absorbing a still-stubbed
        // neighbour's entry.
        List<Address> stubs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            Address e = f.getEntryPoint();
            if (imageBlk.contains(e)) continue;
            if (f.getSymbol() != null && f.getSymbol().getSource() != SourceType.DEFAULT) continue;  // keep user names
            long words = f.getBody().getMaxAddress().getOffset() / 2 - e.getOffset() / 2 + 1;
            if (words <= stubMax) stubs.add(e);
        }
        int rebuilt = 0;
        if (!dryRun) {
            for (Address e : stubs) if (fm.getFunctionAt(e) != null) new DeleteFunctionCmd(e).applyTo(currentProgram);
            for (Address e : stubs) {
                new CreateFunctionCmd(e).applyTo(currentProgram, monitor);
                Function nf = fm.getFunctionAt(e);
                if (nf != null && nf.getBody().getMaxAddress().getOffset() / 2 - e.getOffset() / 2 + 1 > stubMax) rebuilt++;
            }
        }
        println(String.format("pass 1 (stub bodies): %d stub(s) %s", stubs.size(),
            dryRun ? "would be rebuilt" : ("-> " + rebuilt + " rebuilt to full bodies")));

        // --- pass 1b: clear stale flow-error bookmarks left by pre-materialization auto-analysis ----
        clearStaleFlowBookmarks(dryRun);

        // --- pass 2: repair no-return truncation + disassembly conflicts (looped; they interact) --
        // Two analyzer artifacts, both cleaned up here. On a normal fresh import the pspec keeps the
        // no-return analyzers off so there is no truncation, and this is a near no-op; conflicts can
        // still arise from disassembly ordering. Repairing a no-return fall-through re-disassembles
        // flash that may flow into an operand word already mis-decoded as a standalone instruction —
        // creating a NEW conflict — so the two repairs run in a loop until neither changes anything.
        if (dryRun) {
            println(String.format("pass 2 (dryRun): %d falsely-non-returning function(s), %d disassembly "
                + "conflict(s) would be repaired", detectFalseNoReturn().size(), countConflictBookmarks()));
            return;
        }
        boolean analyzersOff = false;
        int totFlags = 0, totSites = 0, totConf = 0;
        for (int iter = 0; iter < 8; iter++) {
            List<Address> falseNR = detectFalseNoReturn();
            if (falseNR.isEmpty() && countConflictBookmarks() == 0) break;
            if (!analyzersOff) {   // disable the two culprit analyzers once, before repairing, so a
                setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
                setAnalysisOption(currentProgram, "Shared Return Calls", "false");   // later re-analyze can't re-truncate
                analyzersOff = true;
            }
            int[] nr = repairNoReturn(falseNR);   // {flagsCleared, callSitesRepaired}
            int conf = repairConflicts();
            totFlags += nr[0]; totSites += nr[1]; totConf += conf;
            if (nr[0] == 0 && nr[1] == 0 && conf == 0) break;   // converged
        }
        // repairs can materialize code that resolves earlier "uninitialized"/"non-existing" marks
        if (totFlags + totSites + totConf > 0) clearStaleFlowBookmarks(false);
        println(String.format("pass 2 (repair): %d false no-return flag(s), %d truncated call site(s), "
            + "%d disassembly conflict(s) repaired", totFlags, totSites, totConf));
    }

    // Functions currently flagged non-returning that actually emit a RETURN — the false-no-return set.
    // RAM ramfuncs OR flash functions (a stale flag can ride in via a merge onto either; the original
    // analyzer misfire targets freshly-materialized RAM). Gated on hasNoReturn() so the expensive body
    // scan runs only for the few flagged functions.
    List<Address> detectFalseNoReturn() {
        List<Address> out = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true))
            if (f.hasNoReturn() && functionReturns(f)) out.add(f.getEntryPoint());
        return out;
    }

    // Clear each false no-return flag and un-truncate its callers: drop the CALL_RETURN flow override
    // and re-disassemble the deleted fall-through. Returns {flagsCleared, callSitesRepaired}.
    int[] repairNoReturn(List<Address> falseNR) {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        int flags = 0, sites = 0;
        for (Address entry : falseNR) {
            Function f = fm.getFunctionAt(entry);
            if (f == null) continue;
            try { f.setNoReturn(false); flags++; } catch (Exception e) {}
            for (var ri = rm.getReferencesTo(entry); ri.hasNext(); ) {
                Reference r = ri.next();
                if (!r.getReferenceType().isCall()) continue;
                Instruction ci = listing.getInstructionAt(r.getFromAddress());
                if (ci == null || ci.getFlowOverride() != FlowOverride.CALL_RETURN) continue;
                ci.setFlowOverride(FlowOverride.NONE);
                Address ft = ci.getMaxAddress().add(1);               // the truncated fall-through
                if (listing.getInstructionAt(ft) == null) {
                    try { listing.clearCodeUnits(ft, ft, false); } catch (Exception e) {}
                    new DisassembleCommand(ft, null, true).applyTo(currentProgram, monitor);
                }
                sites++;
            }
        }
        return new int[]{flags, sites};
    }

    int countConflictBookmarks() {
        int n = 0;
        for (var it = currentProgram.getBookmarkManager().getBookmarksIterator(); it.hasNext(); ) {
            Bookmark b = it.next();
            if ("Error".equalsIgnoreCase(b.getTypeString()) && b.getComment() != null
                && b.getComment().contains("conflicting instruction")) n++;
        }
        return n;
    }

    // Repair "Failed to disassemble at A due to conflicting instruction at B" marks: a multi-word
    // instruction at A whose trailing operand word (== B) was already mis-decoded as a standalone
    // instruction (its bytes are ALSO a valid opcode). Clear [A, endof(B)] and re-disassemble A; if A
    // now spans past B it absorbed the operand word — keep it and drop the mark. Otherwise restore B's
    // decode and leave the mark (don't leave the region worse than we found it).
    int repairConflicts() {
        Listing listing = currentProgram.getListing();
        BookmarkManager bm = currentProgram.getBookmarkManager();
        var sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        List<Bookmark> conflicts = new ArrayList<>();
        for (var it = bm.getBookmarksIterator(); it.hasNext(); ) {
            Bookmark b = it.next();
            if ("Error".equalsIgnoreCase(b.getTypeString()) && b.getComment() != null
                && b.getComment().contains("conflicting instruction")) conflicts.add(b);
        }
        int fixed = 0;
        for (Bookmark b : conflicts) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("([0-9a-fA-F]{8})").matcher(b.getComment());
            List<Long> hx = new ArrayList<>();
            while (m.find()) hx.add(Long.parseLong(m.group(1), 16));
            Address A = b.getAddress();
            Address B = hx.size() >= 2 ? sp.getAddress(hx.get(1) * 2) : null;   // getOffset = word*2
            Address clearEnd = B;
            Instruction bi = (B != null) ? listing.getInstructionAt(B) : null;
            if (bi != null) clearEnd = bi.getMaxAddress();
            if (clearEnd == null) clearEnd = A.add(2);
            // The "conflicting instruction at B" can end BEFORE the mark A (adjacent/reversed), which
            // would make clearCodeUnits(A, clearEnd) throw start>end. Such a conflict is malformed/
            // spurious (A does not actually overlap B) -- skip it and leave the mark for the cleanup pass.
            if (clearEnd.getOffset() < A.getOffset()) continue;
            listing.clearCodeUnits(A, clearEnd, false);
            new DisassembleCommand(A, null, true).applyTo(currentProgram, monitor);
            Instruction i1 = listing.getInstructionAt(A);
            boolean good = i1 != null && !i1.getMnemonicString().equals("??")
                && (B == null || i1.getMaxAddress().getOffset() >= B.getOffset());
            if (good) { bm.removeBookmark(b); fixed++; }
            else if (B != null && listing.getInstructionAt(B) == null) {
                new DisassembleCommand(B, null, true).applyTo(currentProgram, monitor);  // restore, leave mark
            }
        }
        return fixed;
    }

    // Clear stale "uninitialized memory block" / "non-existing memory" flow-error bookmarks whose
    // target has since been materialized (initialized / mapped). Genuine cases and missing-opcode
    // ("Unable to resolve constructor") marks are left untouched. See header note (1b).
    void clearStaleFlowBookmarks(boolean dryRun) {
        AddressSetView ini = currentProgram.getMemory().getAllInitializedAddressSet();
        BookmarkManager bm = currentProgram.getBookmarkManager();
        Listing listing = currentProgram.getListing();
        List<Bookmark> stale = new ArrayList<>();
        int genuine = 0;
        for (var it = bm.getBookmarksIterator(); it.hasNext(); ) {
            Bookmark b = it.next();
            if (!"Error".equalsIgnoreCase(b.getTypeString())) continue;
            String c = b.getComment() == null ? "" : b.getComment();
            boolean uninit = c.contains("uninitialized memory block");
            boolean nonExist = c.contains("non-existing memory");
            if (!uninit && !nonExist) continue;              // keep missing-opcode / other marks
            Address a = b.getAddress();
            Instruction ins = listing.getInstructionAt(a);
            Address[] targets = (ins != null && ins.getFlows() != null && ins.getFlows().length > 0)
                ? ins.getFlows() : new Address[]{a};
            boolean allResolved = true;
            for (Address t : targets) {
                boolean resolved = uninit ? ini.contains(t) : (currentProgram.getMemory().getBlock(t) != null);
                if (!resolved) { allResolved = false; break; }
            }
            if (allResolved) stale.add(b); else genuine++;
        }
        if (!dryRun) for (Bookmark b : stale) bm.removeBookmark(b);
        println(String.format("pass 1b (stale bookmarks): %d stale flow-error mark(s) %s, %d genuine left",
            stale.size(), dryRun ? "would be cleared" : "cleared", genuine));
    }

    // Does the function body emit a RETURN p-code op (LRETR/LRET/IRET)?
    boolean functionReturns(Function f) {
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true))
            for (PcodeOp op : ins.getPcode())
                if (op.getOpcode() == PcodeOp.RETURN) return true;
        return false;
    }
}
