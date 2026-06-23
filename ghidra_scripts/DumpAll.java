// Dump our SLEIGH disassembly of the whole image in a dis2000-comparable format:
//   <addr8>\t<hexword>\t<MNEMONIC operands>
// Disassembles linearly at every word (like dis2000 does on a flat .text), so the
// two outputs align address-for-address for diffing. Used to validate our spec
// against TI's dis2000 ground truth.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DumpAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock blk = null;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks())
            if (b.isInitialized() && b.getSize() > 100000) { blk = b; break; }
        Address a = blk.getStart(), end = blk.getEnd();
        StringBuilder out = new StringBuilder();
        while (a.compareTo(end) < 0) {
            if (getInstructionAt(a) == null) disassemble(a);
            Instruction ins = getInstructionAt(a);
            if (ins != null) {
                int w = (getByte(a)&0xff) | ((getByte(a.add(1))&0xff)<<8);
                out.append(String.format("%08x\t%04x\t%s\n",
                    a.getOffset(), w, ins.toString()));
                a = a.add(ins.getLength());
            } else {
                a = a.add(2);
            }
            if (out.length() > 4000000) break;   // cap
        }
        // write to a temp file (override with -Dc28x.dump.out=<path>)
        String outPath = System.getProperty(
            "c28x.dump.out",
            System.getProperty("java.io.tmpdir") + "/c28x_disasm.txt");
        java.io.PrintWriter pw = new java.io.PrintWriter(outPath);
        pw.print(out); pw.close();
        println("RESULT: wrote " + out.length() + " chars of SLEIGH disasm");
    }
}
