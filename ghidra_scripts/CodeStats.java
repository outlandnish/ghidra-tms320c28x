// Report instruction/data byte counts AFTER auto-analysis has followed real control
// flow from entry points. This is the meaningful coverage number: of the bytes Ghidra
// decided are CODE, how many decoded into instructions vs fell back to undefined.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class CodeStats extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing l = currentProgram.getListing();
        long insnCount = 0, insnBytes = 0;
        InstructionIterator it = l.getInstructions(true);
        while (it.hasNext()) { Instruction i = it.next(); insnCount++; insnBytes += i.getLength(); }

        long dataBytes = 0, undefBytes = 0;
        DataIterator di = l.getDefinedData(true);
        while (di.hasNext()) { Data d = di.next(); dataBytes += d.getLength(); }

        // count functions
        long funcs = 0;
        FunctionIterator fi = l.getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcs++; }

        long total = currentProgram.getMemory().getNumInitializedAddresses();
        println("=== POST-ANALYSIS CODE STATS ===");
        println("functions found:      " + funcs);
        println("instructions:         " + insnCount + "  (" + insnBytes + " addr units)");
        println("defined data:         " + dataBytes + " addr units");
        println("total init addrs:     " + total);
        println(String.format("instruction share of image: %.1f%%", 100.0*insnBytes/total));
        println("=== END ===");
    }
}
