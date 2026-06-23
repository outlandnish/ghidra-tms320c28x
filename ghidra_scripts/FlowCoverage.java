// Flow-accurate coverage: walk instructions by their REAL length (not every word
// offset), so the operand/immediate words of multi-word instructions aren't
// miscounted as "undecoded". Starts a linear sweep at the block start and steps by
// each decoded instruction's length; on a decode failure, steps one word and
// records the stuck opcode. This gives a far truer instruction-coverage number than
// the every-offset CoverageSweep.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import java.util.*;

public class FlowCoverage extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address a = blk.getStart();
        Address end = blk.getEnd();
        long insns = 0, decoded = 0, failWords = 0;
        Map<Integer,Integer> miss = new HashMap<>();
        while (a.compareTo(end) < 0) {
            disassemble(a);
            Instruction insn = getInstructionAt(a);
            if (insn != null) {
                decoded++; insns++;
                int len = insn.getLength();            // bytes; step by real length
                a = a.add(Math.max(len, 2));
            } else {
                failWords++;
                try {
                    int lo = getByte(a) & 0xff, hi = getByte(a.add(1)) & 0xff;
                    miss.merge(lo | (hi<<8), 1, Integer::sum);
                } catch (Exception e) {}
                try { clearListing(a, a.add(1)); } catch (Exception e) {}
                a = a.add(2);                          // step one word past the failure
            }
        }
        long totalSteps = decoded + failWords;
        println("=== FLOW COVERAGE (steps by real instruction length) ===");
        println("decoded instructions: " + decoded);
        println("failed word-steps:    " + failWords);
        println(String.format("instruction decode rate: %.1f%%", 100.0*decoded/totalSteps));
        println("=== TOP 20 STUCK OPCODES (word : count) ===");
        miss.entrySet().stream().sorted((x,y)->y.getValue()-x.getValue()).limit(20)
            .forEach(e -> println(String.format("  0x%04x : %d", e.getKey(), e.getValue())));
        println("=== END ===");
    }
}
