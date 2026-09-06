// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Prepare a CLA program imported with `TMS320C28x:LE:32:cla` (see ExportClaProgram.java).
//
// Three jobs, in order:
//
// (1) MAP WHAT THE CLA CAN REACH. The CLA sees only the low 64K of the device map
//     (SPRUHM8K 6.7.2) and the imported .bin covers just its program RAM, so every data
//     reference points outside the image. Mapping the message RAMs, the LSx/Dx data banks
//     and the peripheral frames the CLA is allowed to touch (ADC results, ePWM, CMPSS, DAC,
//     eCAP/eQEP, SDFM, XBAR) turns those into named, resolvable addresses -- which is the
//     difference between reading `MMOV32 MR0,0xb00` and reading `MMOV32 MR0,ADCARESULT`.
//
// (2) ROOT THE TASKS. A CLA program has no reset vector: the C28x writes Cla1Regs.MVECT1-8
//     with the eight task entry points at startup, and nothing else calls them.
//     ExportClaProgram prints the entries it can see from the C28x side; pass them in with
//     -Dc28x.cla.tasks and each becomes a disassembled, named function (Cla1Task<n>).
//
// (3) FIND THE REST STRUCTURALLY. Code after the END of a task is a new entry: the first
//     non-MNOP instruction following an MSTOP (or an MRCNDD and its three delay slots) is
//     where the next task or subroutine begins. That recovers the subroutines MCCNDD calls,
//     which never appear in MVECT at all.
//
//     Do NOT use "follows a run of MNOPs" for this. MNOP is the CLA's pipeline filler and
//     appears in pairs and triples all through ordinary code -- on a real F28377D CPU2 CLA
//     image that rule proposed 210 entry points where there are a couple of dozen.
//
// Properties (-Dname=value). On Windows headless pass these via JAVA_TOOL_OPTIONS:
// analyzeHeadless.bat drops everything after the `=` in a script argument.
//   c28x.cla.tasks   (csv,  default "")   task entry word addresses from ExportClaProgram
//   c28x.cla.noSplit (bool, default false) skip job (3)
//
// @category TMS320C28x
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.TreeSet;

public class SetupClaProgram extends GhidraScript {

    static final long MNOP_LSW = 0x0000L, MNOP_MSW = 0x7FA0L;
    static final int MSTOP_MSW = 0x7F80, MRCNDD_MSW = 0x79A0;

    // Everything in the low 64K the CLA is permitted to read or write (SPRUHM8K 6.3, and
    // SPRS880P Table 7-5 for the frame bounds). {startWord, endWordInclusive, name}.
    private static final Object[][] CLA_VISIBLE = {
        {0x000B00L, 0x000B1FL, "ADCARESULT"}, {0x000B20L, 0x000B3FL, "ADCBRESULT"},
        {0x000B40L, 0x000B5FL, "ADCCRESULT"}, {0x000B60L, 0x000B7FL, "ADCDRESULT"},
        {0x001400L, 0x00147FL, "CLA1_REGS"},
        {0x001480L, 0x0014FFL, "CLA1_TO_CPU_MSGRAM"},
        {0x001500L, 0x00157FL, "CPU_TO_CLA1_MSGRAM"},
        {0x004000L, 0x0043FFL, "EPWM"},      {0x005000L, 0x0051FFL, "ECAP"},
        {0x005100L, 0x00517FL, "EQEP"},      {0x005C00L, 0x005C7FL, "CMPSS"},
        {0x005C00L, 0x005C7FL, "DAC"},       {0x005E00L, 0x005EFFL, "SDFM"},
        {0x007400L, 0x00743FL, "XBAR"},
    };

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

    int word(long a) throws Exception { return currentProgram.getMemory().getShort(wa(a)) & 0xFFFF; }

    boolean isMnop(long a) throws Exception {
        return word(a) == MNOP_LSW && word(a + 1) == MNOP_MSW;
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        Memory mem = currentProgram.getMemory();

        // (1) map what the CLA can reach ------------------------------------------------
        int mapped = 0;
        for (Object[] p : CLA_VISIBLE) {
            long lo = (Long) p[0], hi = (Long) p[1];
            String name = (String) p[2];
            if (mem.getBlock(wa(lo)) != null) continue;
            MemoryBlock b = mem.createUninitializedBlock(name, wa(lo), (hi - lo + 1) * 2, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(true);
            createLabel(wa(lo), name, true, SourceType.USER_DEFINED);
            mapped++;
        }
        MemoryBlock prog = null;
        for (MemoryBlock b : mem.getBlocks()) if (b.isInitialized()) { prog = b; break; }
        if (prog == null) { println("no initialized block -- import the CLA .bin first"); return; }
        long lo = w(prog.getStart()), hi = w(prog.getEnd());

        // The CLA's DATA lives in whichever LSx/Dx banks LSxMSEL gave it, and that register is
        // configured from a table on the C28x side which the exported program does not carry.
        // So map the whole 0x8000-0xBFFF window that the program itself does not cover, as
        // uninitialized RAM: every data reference then lands somewhere nameable instead of
        // dangling. (Measured on an F28377D CPU2 CLA: 287 of 456 references pointed here.)
        for (long a = 0x8000L; a <= 0xBFFFL; ) {
            if (mem.getBlock(wa(a)) != null) { a++; continue; }
            long end = a;
            while (end + 1 <= 0xBFFFL && mem.getBlock(wa(end + 1)) == null) end++;
            MemoryBlock b = mem.createUninitializedBlock(
                String.format("CLA_DATA_%04x", a), wa(a), (end - a + 1) * 2, false);
            b.setRead(true); b.setWrite(true);
            mapped++;
            a = end + 1;
        }
        println("mapped " + mapped + " CLA-visible region(s)");
        println(String.format("CLA program RAM: %05x..%05x (%d words)", lo, hi, hi - lo + 1));

        // (2) root the tasks the C28x named ---------------------------------------------
        TreeSet<Long> entries = new TreeSet<>();
        String csv = System.getProperty("c28x.cla.tasks", "").trim();
        if (!csv.isEmpty())
            for (String s : csv.split(","))
                if (!s.trim().isEmpty()) entries.add(Long.decode(s.trim()));
        int nTask = 0;
        for (long e : entries) {
            if (e < lo || e > hi) { println(String.format("  task %05x is outside the image", e)); continue; }
            if (isMnop(e)) continue;               // padding, not an entry
            if (make(e)) {
                Function f = getFunctionAt(wa(e));
                if (f != null && f.getName().startsWith("FUN_"))
                    f.setName("Cla1Task_" + Long.toHexString(e), SourceType.ANALYSIS);
                nTask++;
            }
        }
        println("rooted " + nTask + " task entr(y|ies) from MVECT");

        // (3) the rest: whatever follows the end of a task --------------------------------
        int nSplit = 0;
        if (!Boolean.getBoolean("c28x.cla.noSplit")) {
            for (long a = lo; a + 1 <= hi; a += 2) {
                int msw = word(a + 1);
                long next;
                if (msw == MSTOP_MSW && word(a) == 0) next = a + 2;
                else if ((msw & 0xFFF0) == MRCNDD_MSW && word(a) == 0) next = a + 8;  // 3 delay slots
                else continue;
                while (next + 1 <= hi && isMnop(next)) next += 2;                     // skip padding
                if (next + 1 > hi) continue;
                if (word(next) == 0 && word(next + 1) == 0) continue;                 // trailing fill
                if (make(next)) nSplit++;
            }
        }
        println("recovered " + nSplit + " further entr(y|ies) after a task end");

        int fns = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) fns++;
        println("CLA functions now: " + fns);
    }

    /** Disassemble from `a` and bind a function there. Returns true if one now exists. */
    boolean make(long a) throws Exception {
        Address addr = wa(a);
        if (getFunctionAt(addr) != null) return true;
        if (getInstructionAt(addr) == null) disassemble(addr);
        if (getInstructionAt(addr) == null) return false;
        new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        return getFunctionAt(addr) != null;
    }
}
