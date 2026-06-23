// TI parity dump: linearly disassemble the (small) imported .text bin and print
//   <wordaddr>\t<MNEMONIC>
// for each instruction-start word (wordaddr = byteOffset/2, matching dis2000's word
// addresses). Multi-word instructions advance by their full length, exactly like a
// linear sweep, so the start words align with dis2000's mnemonic-bearing lines.
//
// Unlike DumpAll.java this does NOT require a large block — it sweeps the first
// initialized block whatever its size, so it works on the 364-byte TI test objects.
// Output goes to a file (override with -Dc28x.parity.out=<path>).
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DumpParity extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address a = blk.getStart(), end = blk.getEnd();
        StringBuilder out = new StringBuilder();
        while (a.compareTo(end) < 0) {
            if (getInstructionAt(a) == null) disassemble(a);
            Instruction ins = getInstructionAt(a);
            // word address = byte offset / 2 (wordsize=2 ram space)
            long word = a.getOffset() / 2;
            if (ins != null) {
                // mnemonic only (first token of toString) keeps the diff robust to
                // operand-formatting differences vs dis2000.
                String txt = ins.toString();
                out.append(String.format("%08x\t%s\n", word, txt));
                a = a.add(ins.getLength());
            } else {
                out.append(String.format("%08x\t<UNDEF>\n", word));
                a = a.add(2);
            }
        }
        String outPath = System.getProperty(
            "c28x.parity.out",
            System.getProperty("java.io.tmpdir") + "/c28x_parity.txt");
        java.io.PrintWriter pw = new java.io.PrintWriter(outPath);
        pw.print(out); pw.close();
        println("RESULT: wrote parity dump to " + outPath);
    }
}
