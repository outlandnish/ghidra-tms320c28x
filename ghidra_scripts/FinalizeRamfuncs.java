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
// (2) UNDO FALSE NO-RETURN + REPAIR FLASH. Two heuristic analyzers falsely truncate the flash callers
//     of the ramfuncs: "Non-Returning Functions - Discovered" flags a ramfunc non-returning (its
//     call-site heuristic misfires while the body is uninitialized RAM) and "Shared Return Calls"
//     re-stamps CALL_RETURN on the same LCRs (reads the data-looking fall-through as a tail call),
//     deleting the flash fall-through into `??` data (~94 sites for two ramfuncs on dir_26_65_2).
//     This pass disables BOTH (they re-fire and undo the clear otherwise), then for every RAM-
//     resident function that actually RETURNS (emits a RETURN p-code op) clears the false flag +
//     the CALL_RETURN overrides on its callers and re-disassembles the truncated flash. It's an
//     analyzer artifact; the LCR/LRETR SLEIGH is correct (they emit call/return p-code).
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

        // Disable the two heuristics FIRST — before pass 1's rebuild can trigger analysis that would
        // re-truncate — or the pass-2 clear does not stick. "Non-Returning Functions - Discovered"
        // flags the ramfunc non-returning; "Shared Return Calls" independently re-stamps CALL_RETURN
        // on the same LCRs. Disabling only one is not enough. Named/"Known" siblings are unaffected.
        if (!dryRun) {
            setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
            setAnalysisOption(currentProgram, "Shared Return Calls", "false");
        }

        // Flash image = largest initialized block; ramfuncs live in the OTHER (RAM) blocks.
        long bestLen = -1;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; imageBlk = b; }
        }
        if (imageBlk == null) { println("no initialized block"); return; }

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

        // --- pass 2: undo false no-return + repair truncated flash callers (analyzers off above) --
        int fns = 0, sites = 0;
        for (Function f : fm.getFunctions(true)) {
            Address entry = f.getEntryPoint();
            if (imageBlk.contains(entry)) continue;
            if (!functionReturns(f)) continue;          // genuinely non-returning ramfunc — leave it
            int siteN = 0;
            for (var ri = rm.getReferencesTo(entry); ri.hasNext(); ) {
                Reference r = ri.next();
                if (!r.getReferenceType().isCall()) continue;
                Instruction ci = listing.getInstructionAt(r.getFromAddress());
                if (ci == null || ci.getFlowOverride() != FlowOverride.CALL_RETURN) continue;
                if (!dryRun) {
                    ci.setFlowOverride(FlowOverride.NONE);
                    Address ft = ci.getMaxAddress().add(1);            // the truncated fall-through
                    if (listing.getInstructionAt(ft) == null) {
                        try { listing.clearCodeUnits(ft, ft, false); } catch (Exception e) {}
                        new DisassembleCommand(ft, null, true).applyTo(currentProgram, monitor);
                    }
                }
                siteN++;
            }
            if (siteN > 0 || f.hasNoReturn()) {
                if (!dryRun && f.hasNoReturn()) { try { f.setNoReturn(false); } catch (Exception e) {} }
                if (siteN > 0) { fns++; sites += siteN; }
            }
        }
        println(String.format("pass 2 (no-return): %d returning ramfunc(s) had truncated callers; %d flash "
            + "call site(s) %s", fns, sites, dryRun ? "would be re-disassembled" : "re-disassembled"));
    }

    // Does the function body emit a RETURN p-code op (LRETR/LRET/IRET)?
    boolean functionReturns(Function f) {
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true))
            for (PcodeOp op : ins.getPcode())
                if (op.getOpcode() == PcodeOp.RETURN) return true;
        return false;
    }
}
