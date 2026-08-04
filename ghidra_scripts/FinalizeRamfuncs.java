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
//     RAM-resident function that actually RETURNS (emits a RETURN p-code op), clear the false flag +
//     the CALL_RETURN overrides on its callers and re-disassemble the truncated flash. A post-hoc
//     script cannot beat the analyzers while they are LIVE (they re-fire and oscillate) — the pspec
//     opt-out is the real fix; with the analyzers off, this one-time repair holds. It's an analyzer
//     artifact; the LCR/LRETR SLEIGH is correct (emits call/return).
//
// Both passes are RAM-scoped (function entry outside the flash image block), additive and idempotent.
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

        // Detect pre-existing no-return truncation (present only on a program imported BEFORE the pspec
        // disabled the two analyzers, or where they were manually re-enabled — a normal import has
        // none). Scan BEFORE any edit so we can decide whether to touch the analyzer options at all,
        // and collect by ADDRESS: pass 1 may delete+recreate a RAM stub, invalidating cached handles.
        List<Address> truncCallers = new ArrayList<>();   // flash LCR sites: CALL_RETURN -> a returning ramfunc
        List<Address> falseNoReturn = new ArrayList<>();  // ramfunc entries that RETURN yet are marked non-returning
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            if (imageBlk.contains(entry)) continue;
            if (!functionReturns(f)) continue;            // genuinely non-returning ramfunc — leave it
            if (f.hasNoReturn()) falseNoReturn.add(entry);
            for (var ri = rm.getReferencesTo(entry); ri.hasNext(); ) {
                Reference r = ri.next();
                if (!r.getReferenceType().isCall()) continue;
                Instruction ci = listing.getInstructionAt(r.getFromAddress());
                if (ci != null && ci.getFlowOverride() == FlowOverride.CALL_RETURN) truncCallers.add(r.getFromAddress());
            }
        }
        boolean damage = !truncCallers.isEmpty() || !falseNoReturn.isEmpty();

        // Touch the analyzer options ONLY when there is damage to repair: disable BOTH now (before
        // pass 1's rebuild can re-trigger them) so the repair holds. A normal import has no damage, so
        // this leaves the analysis options exactly as the user set them (the pspec keeps them off).
        if (damage && !dryRun) {
            setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
            setAnalysisOption(currentProgram, "Shared Return Calls", "false");
        }

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

        // --- pass 2: one-time repair of the pre-existing no-return truncation found above ---------
        // A no-op on a normal import (the pspec keeps the analyzers off, so `damage` is false). When
        // damage IS present, the analyzers were disabled above, so clearing the overrides + re-
        // disassembling the fall-through HOLDS — they will not re-fire and re-truncate.
        if (!damage) {
            println("pass 2 (no-return): nothing to repair (analyzers disabled by pspec — expected on a normal import)");
            return;
        }
        if (dryRun) {
            println(String.format("pass 2 (no-return): would clear %d false no-return mark(s) + repair %d "
                + "truncated flash call site(s)", falseNoReturn.size(), truncCallers.size()));
            return;
        }
        for (Address entry : falseNoReturn) {
            Function f = fm.getFunctionAt(entry);
            if (f != null) { try { f.setNoReturn(false); } catch (Exception e) {} }
        }
        int sites = 0;
        for (Address from : truncCallers) {
            Instruction ci = listing.getInstructionAt(from);
            if (ci == null || ci.getFlowOverride() != FlowOverride.CALL_RETURN) continue;
            ci.setFlowOverride(FlowOverride.NONE);
            Address ft = ci.getMaxAddress().add(1);                // the truncated fall-through
            if (listing.getInstructionAt(ft) == null) {
                try { listing.clearCodeUnits(ft, ft, false); } catch (Exception e) {}
                new DisassembleCommand(ft, null, true).applyTo(currentProgram, monitor);
            }
            sites++;
        }
        println(String.format("pass 2 (no-return): cleared %d false no-return mark(s), repaired %d truncated "
            + "flash call site(s)", falseNoReturn.size(), sites));
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
