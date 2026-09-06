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

    // Frames in the low 64K the CLA can reach: the two message RAMs, its own control
    // registers, and the peripherals on the secondary VBUS32 it owns by default
    // (SPRUHM8K 6.2.3 -- CpuSysRegs.SECMSEL[VBUS32_x] hands the bus to the CLA at reset).
    // Bounds are TI's own frame origins and lengths from F2837xD_Headers_nonBIOS_cpuN.cmd,
    // coalesced per peripheral family. Deliberately COARSE: these exist so a data reference
    // lands somewhere named at all. The precise per-register names come from syncing with
    // the C28x program, which has SetupF28377D's full table -- see SyncClaLabels.java.
    // {startWord, endWordInclusive, name}.
    private static final Object[][] CLA_VISIBLE = {
        {0x000B00L, 0x000B7FL, "ADC_RESULTS"},        // ADCA/B/C/D result frames, 0x20 each
        // The CLA reads AND WRITES PIECTRL/PIEIER1 in this firmware -- two read-modify-write
        // pairs at 0xCE0 and 0xCE2. Found by asking which addresses the decoded CLA code
        // referenced that nothing had mapped, not by working down TI's frame list.
        {0x000CE0L, 0x000CF9L, "PIE_CTRL"},
        {0x001400L, 0x00147FL, "CLA1_REGS"},
        // WHICH MESSAGE RAM IS WHICH, settled from both programs rather than from the
        // header's naming convention. SPRUHM8K 3.11.1.5: the CLA may write only the "CLA to
        // CPU" block, the CPU only the "CPU to CLA" block, and both may read both. Counted:
        //          CLA writes  CLA reads   CPU writes  CPU reads
        //   0x1480     36          14          0           35
        //   0x1500      0           3         11            4
        // A perfect mirror, and no counterexample either way.
        {0x001480L, 0x0014FFL, "CLA1_TO_CPU_MSGRAM"},
        {0x001500L, 0x00157FL, "CPU_TO_CLA1_MSGRAM"},
        {0x004000L, 0x004BFFL, "EPWM"},               // EPWM1-12, 0x100 each
        {0x005000L, 0x0050BFL, "ECAP"},               // ECAP1-6,  0x20 each
        {0x005100L, 0x0051A1L, "EQEP"},               // EQEP1-3 at 0x5100/0x5140/0x5180
        {0x005C00L, 0x005C27L, "DAC"},                // DACA/B/C at 0x5C00/0x5C10/0x5C20
        {0x005C80L, 0x005D7FL, "CMPSS"},              // CMPSS1-8, 0x20 each
        {0x005E00L, 0x005EFFL, "SDFM"},               // SDFM1-2,  0x80 each
        {0x007400L, 0x0075FFL, "ADC_CONFIG"},         // ADCA-D config, 0x80 each
        {0x007900L, 0x007945L, "XBAR_IN"},            // INPUTXBAR / XBAR / SYNCSOC
        {0x007A00L, 0x007ABFL, "XBAR_OUT"},           // EPWMXBAR / CLBXBAR / OUTPUTXBAR
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
            // ANALYSIS, not USER_DEFINED: these are coarse region labels standing in until a
            // better name arrives. SyncClaLabels ranks USER_DEFINED above ANALYSIS, so
            // SetupF28377D's precise register names (ADCA_RESULT_ADCRESULT0) replace this
            // block-start `ADCARESULT` on the first sync instead of colliding with it.
            createLabel(wa(lo), name, true, SourceType.ANALYSIS);
            mapped++;
        }
        MemoryBlock prog = null;
        for (MemoryBlock b : mem.getBlocks()) if (b.isInitialized()) { prog = b; break; }
        if (prog == null) { println("no initialized block -- import the CLA .bin first"); return; }
        long lo = w(prog.getStart()), hi = w(prog.getEnd());

        // Catch-all for the rest of the CLA's reach. Its DATA lives in whichever LSx/Dx banks
        // LSxMSEL gave it, and that register is configured from a table on the C28x side the
        // exported program does not carry -- and a firmware can reach further still (this one
        // loads from 0xF874, which the C28x map calls GS RAM). Rather than chase each region,
        // fill every gap in the CLA's whole 16-bit address space, so NO data reference can
        // dangle whatever the image does. The named frames above still take precedence, and
        // SyncClaLabels brings the precise names over from the C28x program.
        // (Measured on an F28377D CPU2 CLA: 287 of 456 references land in this fill.)
        for (long a = 0x0000L; a <= 0xFFFFL; ) {
            if (mem.getBlock(wa(a)) != null) { a++; continue; }
            long end = a;
            while (end + 1 <= 0xFFFFL && mem.getBlock(wa(end + 1)) == null) end++;
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
