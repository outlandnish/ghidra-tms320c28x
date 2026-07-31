// Fix return flow for functions called via the FFC XAR7,#target calling convention.
//
// Background
// ----------
// The C28x has two calling conventions:
//   LCR #fn  -- saves return address in RPC; callee returns with LRETR.
//   FFC XAR7,#fn -- saves inst_next in XAR7; callee returns with LB *XAR7.
//
// The SLEIGH spec models "LB *XAR7" as `goto [XAR7]` (BRANCHIND) rather than
// `return [XAR7]` because the same opcode (0x7620) is also used for switch-table
// dispatch — e.g. MOVL XAR7,#table; ADDB XAR7,AR0; LB *XAR7. SLEIGH has no
// context to distinguish the two roles.
//
// This script does the context-sensitive fixup that SLEIGH cannot:
//   1. Find every "FFC XAR7,#target" call site and collect its target address.
//   2. For each target function, walk its body and apply FlowOverride.RETURN to
//      every LB *XAR7 instruction found there.
//   3. Re-create the function so Ghidra picks up the corrected exit edges.
//
// Run this AFTER SeedFunctions (or after auto-analysis has created functions).
// Safe to re-run; FlowOverride is idempotent.
//
// @category TMS320C28x

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.util.*;

public class FixFfcReturns extends GhidraScript {

    // LB *XAR7 is a single 16-bit word 0x7620.
    // C28x is little-endian, so in memory: byte[0]=0x20, byte[1]=0x76.
    static final int LB_XAR7_LO = 0x20;
    static final int LB_XAR7_HI = 0x76;

    @Override
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        var fnMgr   = currentProgram.getFunctionManager();

        // --- Step 1: collect every function address reached via FFC -----------
        // FFC emits a CALL p-code to a constant address, so inst.getFlows()
        // returns the absolute 22-bit target directly.
        Set<Address> ffcTargets = new LinkedHashSet<>();
        for (Instruction inst : listing.getInstructions(true)) {
            if (!inst.getMnemonicString().equals("FFC")) continue;
            Address[] flows = inst.getFlows();
            if (flows != null) Collections.addAll(ffcTargets, flows);
        }
        println("FFC XAR7,#target call sites found: " + ffcTargets.size() + " unique targets");

        // --- Step 2: override LB *XAR7 → RETURN in each FFC-called function --
        int lbFixed = 0, fnFixed = 0, noFn = 0;
        for (Address target : ffcTargets) {
            Function fn = fnMgr.getFunctionAt(target);
            if (fn == null) {
                println("  WARN: no function at " + target + " — run SeedFunctions first");
                noFn++;
                continue;
            }
            int count = 0;
            for (Instruction inst : listing.getInstructions(fn.getBody(), true)) {
                if (isLbXar7(inst)) {
                    inst.setFlowOverride(FlowOverride.RETURN);
                    count++;
                }
            }
            if (count > 0) {
                lbFixed += count;
                fnFixed++;
                // Rebuild function body with corrected exit edges.
                new CreateFunctionCmd(target).applyTo(currentProgram, monitor);
                println(String.format("  fixed %-12s  (%s)  — %d LB *XAR7 overridden",
                        target, fn.getName(), count));
            }
        }

        println(String.format(
            "Done: %d function(s) fixed, %d LB *XAR7 instruction(s) overridden, %d target(s) had no function",
            fnFixed, lbFixed, noFn));
    }

    // Detect LB *XAR7 by opcode bytes rather than mnemonic string, to avoid
    // any ambiguity in how Ghidra surfaces the literal-string operand "*XAR7".
    boolean isLbXar7(Instruction inst) {
        if (inst.getLength() != 2) return false;
        byte[] buf = new byte[2];
        try {
            currentProgram.getMemory().getBytes(inst.getAddress(), buf);
        } catch (Exception e) {
            return false;
        }
        return (buf[0] & 0xFF) == LB_XAR7_LO && (buf[1] & 0xFF) == LB_XAR7_HI;
    }
}
