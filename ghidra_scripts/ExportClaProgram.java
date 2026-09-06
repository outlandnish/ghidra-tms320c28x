// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Lift the CLA's program RAM out of a C28x image so it can be analysed as its own program.
//
// WHY. The CLA is an independent processor sharing the device's memory map: it fetches from
// whichever LSx banks MemCfgRegs.LSxMSEL/LSxCLAPGM hand it, and its instruction set has no
// encoding in common with the C28x. Ghidra binds one language per program, so CLA code cannot
// be disassembled inside the C28x program however it is marked -- it has to be imported
// separately, with `TMS320C28x:LE:32:cla`. This script finds it and writes it out.
//
// HOW IT FINDS IT. A materialized LS bank that holds CLA code has a signature no other bank
// has: it is initialized and mostly non-zero, and it contains ZERO C28x instructions and zero
// functions, because nothing in the C28x image ever calls into it. (Measured on an F28377D
// CPU2 image: LS0 1579 non-zero words and LS1 1432, both with no instructions at all, while
// LS2-LS5 and D0/D1 each hold hundreds of decoded C28x functions.) Banks are reported with
// that evidence rather than guessed at, and the CLA task entry points confirm it: MVECT1-8
// are written by the C28x at startup, so the values land in the listing as references into
// the bank.
//
// WHAT IT WRITES. One flat .bin of the chosen word range plus the import recipe: base word
// address, language id, and every task entry it could recover from Cla1Regs. Import that .bin
// at that base with that language, then run SetupClaProgram.java in the new program.
//
// Properties (-Dname=value):
//   c28x.cla.out    (path, REQUIRED)  where to write the .bin
//   c28x.cla.range  (csv,  default "") explicit "loWord,hiWord" instead of the detected banks
//   c28x.cla.minNz  (int,  default 64) non-zero words a bank needs before it counts as used
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.TreeSet;

public class ExportClaProgram extends GhidraScript {

    // Cla1Regs (SPRUHM8K 6.8.2): MVECT1-8 at +0x00..+0x07 of the 0x1400 frame.
    static final long CLA1_REGS = 0x1400L;

    // Promote -Dkey=value script args to real system properties, as the other scripts do.
    //
    // ON WINDOWS HEADLESS, PASS THESE VIA JAVA_TOOL_OPTIONS, NOT AS SCRIPT ARGS.
    // analyzeHeadless.bat drops everything after the `=` in a script argument, so
    // `-Dc28x.cla.out=C:\x.bin` arrives as the bare flag `-Dc28x.cla.out` and would be
    // promoted to the string "true" -- which is how a path option ends up trying to open a
    // file literally named `true`. (A valueless flag like a dryRun switch survives, which is
    // why this is easy to miss.) So the namespace is cleared only when an argument actually
    // carries a value: with none, a property already set by the JVM (JAVA_TOOL_OPTIONS, or
    // -D on a non-Windows invocation) is left alone rather than wiped.
    void promoteDashDArgs() {
        String[] args = getScriptArgs();
        if (args == null) return;
        boolean valued = false;
        for (String a : args)
            if (a != null && a.startsWith("-Dc28x.cla.") && a.indexOf('=') > 0) valued = true;
        if (valued)
            for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
                if (k.startsWith("c28x.cla.")) System.clearProperty(k);
        for (String a : args) {
            if (a == null || !a.startsWith("-D")) continue;
            String kv = a.substring(2);
            int eq = kv.indexOf('=');
            if (eq > 0) System.setProperty(kv.substring(0, eq), kv.substring(eq + 1));
        }
    }

    long w(Address a) { return a.getOffset() / 2; }
    Address wa(long word) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(word * 2);
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        String out = System.getProperty("c28x.cla.out");
        if (out == null) { println("set -Dc28x.cla.out=<path to write the .bin>"); return; }
        int minNz = Integer.getInteger("c28x.cla.minNz", 64);
        var fm = currentProgram.getFunctionManager();
        var mem = currentProgram.getMemory();

        // --- where the C28x writes MVECT1-8 --------------------------------------------
        // Report the sites even when the values are computed: seeing `MOV @0x1,AR6` three
        // instructions after `MOVL XAR6,#0x8366` is how the task entry is read off by hand.
        TreeSet<Long> vectWriters = new TreeSet<>();
        AddressSet vect = new AddressSet(wa(CLA1_REGS), wa(CLA1_REGS + 8).subtract(1));
        for (AddressIterator it = currentProgram.getReferenceManager()
                .getReferenceDestinationIterator(vect, true); it.hasNext(); ) {
            Address d = it.next();
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d)) {
                if (!r.getFromAddress().isMemoryAddress()) continue;
                var in = getInstructionContaining(r.getFromAddress());
                if (in == null) continue;
                vectWriters.add(w(r.getFromAddress()));
                println(String.format("MVECT%d written at %05x: %s", w(d) - CLA1_REGS + 1,
                    w(r.getFromAddress()), in.toString()));
            }
        }

        // --- which LS banks hold CLA code ----------------------------------------------
        ArrayList<MemoryBlock> claBanks = new ArrayList<>();
        println("");
        println("LS bank survey (a CLA program bank is initialized, non-empty, and holds NO C28x code):");
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.getName().startsWith("LS")) continue;
            long lo = w(b.getStart()), hi = w(b.getEnd());
            int fns = 0, insn = 0, nz = 0;
            for (Function f : fm.getFunctions(true)) if (b.contains(f.getEntryPoint())) fns++;
            for (long a = lo; a <= hi; a++) {
                if (getInstructionAt(wa(a)) != null) insn++;
                try { if (mem.getShort(wa(a)) != 0) nz++; } catch (Exception e) { /* unreadable */ }
            }
            boolean isCla = b.isInitialized() && fns == 0 && insn == 0 && nz >= minNz;
            println(String.format("  %-10s %05x-%05x init=%-5s fns=%-4d insn=%-5d nonzero=%-5d  %s",
                b.getName(), lo, hi, b.isInitialized(), fns, insn, nz,
                isCla ? "<== CLA program" : ""));
            if (isCla) claBanks.add(b);
        }

        // --- pick the range -------------------------------------------------------------
        long lo, hi;
        String explicit = System.getProperty("c28x.cla.range", "").trim();
        if (!explicit.isEmpty()) {
            String[] p = explicit.split(",");
            lo = Long.decode(p[0].trim());
            hi = Long.decode(p[1].trim());
        } else if (claBanks.isEmpty()) {
            println("");
            println("No LS bank matches the CLA-program signature. Either this image does not use");
            println("the CLA, or its program RAM was never materialized -- run MaterializeSections /");
            println("MaterializeCopyTable / EmulateStartup first, then re-run. Pass");
            println("-Dc28x.cla.range=lo,hi to export a range anyway.");
            return;
        } else {
            lo = w(claBanks.get(0).getStart());
            hi = w(claBanks.get(claBanks.size() - 1).getEnd());
        }

        // --- task entries: code references that land INSIDE the CLA banks ---------------
        // Only these banks, and only from an instruction: a reference from anywhere else is
        // C28x code talking to C28x code and says nothing about where a CLA task starts.
        TreeSet<Long> tasks = new TreeSet<>();
        for (MemoryBlock b : claBanks) {
            for (AddressIterator it = currentProgram.getReferenceManager()
                    .getReferenceDestinationIterator(new AddressSet(b.getStart(), b.getEnd()), true);
                    it.hasNext(); ) {
                Address d = it.next();
                for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d)) {
                    if (!r.getFromAddress().isMemoryAddress()) continue;
                    if (getInstructionContaining(r.getFromAddress()) == null) continue;
                    if (fm.getFunctionContaining(r.getFromAddress()) == null) continue;
                    tasks.add(w(d));
                }
            }
        }

        byte[] buf = new byte[(int) ((hi - lo + 1) * 2)];
        for (long a = lo; a <= hi; a++) {
            int v = mem.getShort(wa(a)) & 0xFFFF;
            int i = (int) ((a - lo) * 2);
            buf[i] = (byte) (v & 0xFF);
            buf[i + 1] = (byte) ((v >> 8) & 0xFF);
        }
        try (FileOutputStream f = new FileOutputStream(out)) { f.write(buf); }

        println("");
        println(String.format("wrote %d words (%05x..%05x) -> %s", hi - lo + 1, lo, hi, out));
        println("");
        println("Import it with:");
        println("  -import " + out + " -processor TMS320C28x:LE:32:cla");
        println(String.format("  then set the image base to word 0x%x", lo));
        if (tasks.isEmpty()) {
            println("");
            println("No task entry recovered: the MVECT writes are computed at run time in this");
            println("image. Seed by hand -- a CLA task begins after a run of MNOP padding");
            println("(7fa0 0000), which is what the linker leaves between tasks.");
        } else {
            StringBuilder sb = new StringBuilder();
            for (long t : tasks) sb.append(sb.length() == 0 ? "" : ",").append(String.format("0x%x", t));
            println("");
            println("Task entries referenced from code: " + sb);
            println("  pass them to SetupClaProgram.java as -Dc28x.cla.tasks=" + sb);
        }
    }
}
