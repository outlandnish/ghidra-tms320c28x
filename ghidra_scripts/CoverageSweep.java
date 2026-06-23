// Coverage sweep: attempt to disassemble at EVERY word offset independently and
// report how many decode vs fail, plus a histogram of the top undecoded opcode
// words. Used to measure instruction-set coverage against real firmware and to
// prioritize which constructors to write next.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import java.util.*;

public class CoverageSweep extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address a = blk.getStart();
        Address end = blk.getEnd();
        long total = 0, ok = 0;
        Map<Integer,Integer> missHist = new HashMap<>();
        while (a.compareTo(end) < 0) {
            total++;
            disassemble(a);
            Instruction insn = getInstructionAt(a);
            if (insn != null) {
                ok++;
            } else {
                // read the 16-bit word so we can histogram the unknown opcode
                try {
                    int lo = getByte(a) & 0xff;
                    int hi = getByte(a.add(1)) & 0xff;
                    int word = lo | (hi << 8);
                    missHist.merge(word, 1, Integer::sum);
                } catch (Exception e) {}
            }
            // clear so the next offset is tried fresh (independent decode)
            try { clearListing(a, a.add(1)); } catch (Exception e) {}
            a = a.add(2);  // step one 16-bit word
        }
        println("=== COVERAGE ===");
        println("words tried: " + total);
        println("decoded:     " + ok + String.format(" (%.1f%%)", 100.0*ok/total));
        println("undecoded:   " + (total-ok));
        println("=== TOP 25 UNDECODED OPCODE WORDS (word : count) ===");
        missHist.entrySet().stream()
            .sorted((x,y)->y.getValue()-x.getValue())
            .limit(25)
            .forEach(e -> println(String.format("  0x%04x : %d", e.getKey(), e.getValue())));
        println("=== END ===");
    }
}
