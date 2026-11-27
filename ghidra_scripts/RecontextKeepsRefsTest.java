// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Regression test for TMS320C28xContextRedisassembly: an analyzer that re-decodes an
// instruction under a new context bit must keep what was attached to it.
//
// Builds, in a fresh block:
//
//   9400  SPM -1
//   9401  ADDL ACC,P << PM      + a USER_DEFINED and an ANALYSIS data reference
//   9402  ADDL ACC,P << PM      + a fall-through override to 9404 (skipping the NOP)
//   9403  NOP
//   9404  LRETR
//
// then runs TMS320C28xPmShiftAnalyzer on it. The SPM proves PM = -1 on both ADDLs, so the
// analyzer clears each one and decodes it again with pm_shift=1. Before the helper, the
// clear deleted both references and the override, and the re-decode did not bring them back.
// Checks: pm_shift=1 on both, both references back with their source type, and the
// override back on 9402. 9401 has no override, so it goes through the analyzer's batched
// re-disassembly. 9402 has one, so the helper decodes it at once.
//
// Run headless (any TMS320C28x program works; the test builds its own block). Needs the
// module jar installed (tests/build_modifier):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin -processor TMS320C28x:LE:32:default \
//       -postScript RecontextKeepsRefsTest.java -noanalysis
//@category C28x.Test
import java.math.BigInteger;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.TMS320C28xPmShiftAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class RecontextKeepsRefsTest extends GhidraScript {

    private static final long CODE = 0x9400L, DATA = 0xC300L;   // word addresses
    private static final int[] WORDS = { 0xFF6A, 0x10AC, 0x10AC, 0x7700, 0x0006 };

    private AddressSpace sp;
    private int failures = 0;

    @Override
    public void run() throws Exception {
        sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();
        mem.createInitializedBlock("rk_code", wa(CODE), WORDS.length * 2, (byte) 0, monitor, false);
        mem.createInitializedBlock("rk_data", wa(DATA), 0x10 * 2, (byte) 0, monitor, false);
        for (int i = 0; i < WORDS.length; i++) {
            mem.setByte(wa(CODE + i), (byte) WORDS[i]);
            mem.setByte(wa(CODE + i).add(1), (byte) (WORDS[i] >> 8));
        }
        disassemble(wa(CODE));
        createFunction(wa(CODE), "recontext_probe");

        var refs = currentProgram.getReferenceManager();
        refs.addMemoryReference(wa(CODE + 1), wa(DATA), RefType.READ, SourceType.USER_DEFINED, -1);
        refs.addMemoryReference(wa(CODE + 1), wa(DATA + 1), RefType.READ, SourceType.ANALYSIS, -1);
        Instruction ft = getInstructionAt(wa(CODE + 2));
        ft.setFallThrough(wa(CODE + 4));
        expect("setup: override took", ft.isFallThroughOverridden() ? 1 : 0, 1);

        Register pmShift = currentProgram.getProgramContext().getRegister("pm_shift");
        expect("setup: pm_shift=0 before", ctx(pmShift, CODE + 1), 0);

        MessageLog log = new MessageLog();
        new TMS320C28xPmShiftAnalyzer().added(currentProgram,
            new AddressSet(wa(CODE), wa(CODE + WORDS.length - 1)), monitor, log);
        AutoAnalysisManager.getAnalysisManager(currentProgram).startAnalysis(monitor);
        if (log.hasMessages()) {
            println("RecontextKeepsRefsTest.java> analyzer log: " + log);
        }

        for (long w : new long[] { CODE + 1, CODE + 2 }) {
            Instruction ins = getInstructionAt(wa(w));
            expect("instruction back at 0x" + Long.toHexString(w), ins != null ? 1 : 0, 1);
            expect("pm_shift=1 at 0x" + Long.toHexString(w), ctx(pmShift, w), 1);
        }
        expectRef(CODE + 1, DATA, SourceType.USER_DEFINED);
        expectRef(CODE + 1, DATA + 1, SourceType.ANALYSIS);
        Instruction after = getInstructionAt(wa(CODE + 2));
        if (after != null) {
            expect("fall-through override kept", after.isFallThroughOverridden() ? 1 : 0, 1);
            Address f = after.getFallThrough();
            expect("fall-through target", f == null ? -1 : f.getOffset() / 2, CODE + 4);
        }

        println("RecontextKeepsRefsTest.java> " + (failures == 0
            ? "PASS: re-contexted instructions keep user/analysis refs and overrides (8 checks)"
            : "FAIL: " + failures + " check(s) failed"));
    }

    private long ctx(Register r, long word) {
        BigInteger v = currentProgram.getProgramContext().getValue(r, wa(word), false);
        return v == null ? 0 : v.longValue();
    }

    private void expectRef(long from, long to, SourceType source) {
        for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(wa(from))) {
            if (r.getToAddress().equals(wa(to))) {
                expect(String.format("ref 0x%x->0x%x source", from, to),
                    r.getSource() == source ? 1 : 0, 1);
                return;
            }
        }
        println(String.format("RecontextKeepsRefsTest.java> FAIL: ref 0x%x->0x%x (%s) lost",
            from, to, source));
        failures++;
    }

    private Address wa(long word) {
        return sp.getAddress(word * 2);
    }

    private void expect(String what, long got, long want) {
        if (got == want) {
            return;
        }
        println(String.format("RecontextKeepsRefsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
}
