// After setup + disassembly, find references to the CANA/CANB register blocks and
// print the instructions that touch them. This is the end-to-end proof that the
// module + peripheral labels surface CAN access for RE.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class FindCanRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Disassemble the whole image first (no entry point in raw bin), so refs form.
        AddressSet whole = new AddressSet(currentProgram.getMemory());
        disassemble(currentProgram.getMemory().getBlocks()[0].getStart());

        long[] bases = { 0x048000L, 0x04A000L };
        ReferenceManager rm = currentProgram.getReferenceManager();
        int found = 0;
        println("=== references into CANA/CANB register space ===");
        for (long base : bases) {
            for (long off = 0; off < 0x200 && found < 60; off += 2) {
                Address t = toAddr(base + off);
                for (Reference r : rm.getReferencesTo(t)) {
                    Address from = r.getFromAddress();
                    Instruction ins = getInstructionAt(from);
                    String txt = (ins != null) ? ins.toString() : "(data)";
                    println(String.format("  %s -> %s : %s",
                        from, getSymbolAt(t) != null ? getSymbolAt(t).getName() : t.toString(), txt));
                    found++;
                }
            }
        }
        println("total CAN refs found: " + found);
        println("=== END ===");
    }
}
