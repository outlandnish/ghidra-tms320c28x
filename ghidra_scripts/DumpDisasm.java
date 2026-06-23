// Headless test helper: disassemble the whole program linearly and print each
// instruction as "<wordaddr>\t<bytes>\t<mnemonic+operands>". Compared against
// tests/*.expected.txt by run_disasm_test.sh.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DumpDisasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Disassemble from the start of the first initialized block.
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address start = blk.getStart();
        disassemble(start);

        Instruction insn = getInstructionAt(start);
        println("=== DISASM BEGIN ===");
        while (insn != null) {
            Address a = insn.getAddress();
            StringBuilder bytes = new StringBuilder();
            try {
                for (byte b : insn.getBytes()) bytes.append(String.format("%02x", b & 0xff));
            } catch (Exception e) { bytes.append("??"); }
            println(a.toString() + "\t" + bytes + "\t" + insn.toString());
            insn = insn.getNext();
        }
        println("=== DISASM END ===");
    }
}
