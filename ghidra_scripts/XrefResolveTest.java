// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Regression test for ResolveComputedPointerXrefs.java.
//
// Builds one function in fresh memory blocks, runs the script next to this file on it, and
// checks the references it leaves behind. The code (bytes from cl2000 -v28, verified with
// dis2000) covers each outcome the script can reach:
//
//   9000  MOVL XAR4,#0xC100
//   9002  MOV  AL,*+XAR4[2]      READ       -> C102
//   9003  MOV  *+XAR4[3],AL      WRITE      -> C103
//   9004  AND  *+XAR4[4],#1      READ_WRITE -> C104
//   9006  MOVL XAR5,#0x8100
//   9008  MOV  AL,*XAR5          none: below the default minWord (0xC000)
//   9009  SB   900C,EQ
//   900A  MOVL XAR4,#0xC200
//   900C  MOV  AL,*+XAR4[1]      none: XAR4 is C100 or C200 depending on the path
//   900D  NOP x17
//   901E  MOV  AL,*+XAR4[5]      none: same, but past SymbolicPropogator's 16-instruction
//                                replay window, so only one path's value is ever recorded here
//   901F  LRETR
//
// Also checks that the default dry run writes nothing and that a second `apply` adds nothing.
//
// Run headless (any TMS320C28x program works; the test builds its own blocks):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin -processor TMS320C28x:LE:32:default \
//       -scriptPath <dir with both scripts> -postScript XrefResolveTest.java -noanalysis
//@category C28x.Test
import java.util.ArrayList;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class XrefResolveTest extends GhidraScript {

    private static final long CODE = 0x9000L, DATA = 0xC100L, LOW = 0x8100L;   // word addresses
    private static final int[] WORDS = {
        0x8f00, 0xc100, 0x92d4, 0x96dc, 0x18e4, 0x0001, 0x8f40, 0x8100,
        0x92c5, 0x6103, 0x8f00, 0xc200, 0x92cc,
        0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700,
        0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700, 0x7700,
        0x92ec, 0x0006 };

    private AddressSpace sp;
    private int failures = 0;

    @Override
    public void run() throws Exception {
        sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();
        mem.createInitializedBlock("xr_code", wa(CODE), 0x20 * 2, (byte) 0, monitor, false);
        mem.createInitializedBlock("xr_data", wa(DATA), 0x200 * 2, (byte) 0, monitor, false);
        mem.createInitializedBlock("xr_low", wa(LOW), 0x10 * 2, (byte) 0, monitor, false);
        for (int i = 0; i < WORDS.length; i++) {
            mem.setByte(wa(CODE + i), (byte) WORDS[i]);
            mem.setByte(wa(CODE + i).add(1), (byte) (WORDS[i] >> 8));
        }
        disassemble(wa(CODE));
        createFunction(wa(CODE), "xref_probe");
        String func = "c28x.xref.func=0x" + Long.toHexString(CODE);

        runSibling(new String[] { func });
        expect("dry run writes nothing", probeRefs().size(), 0);

        runSibling(new String[] { "apply", func });
        expectRef(0x9002, 0xC102, RefType.READ);
        expectRef(0x9003, 0xC103, RefType.WRITE);
        expectRef(0x9004, 0xC104, RefType.READ_WRITE);
        expectNone(0x9008, "below minWord");
        expectNone(0x900C, "base differs across paths");
        expectNone(0x901E, "base differs across paths, far from the join");
        int after = probeRefs().size();
        expect("apply adds exactly 3", after, 3);

        runSibling(new String[] { "apply", func });
        expect("second apply is a no-op", probeRefs().size(), after);

        if (failures == 0) println("XrefResolveTest.java> PASS: computed-pointer xrefs (9 checks)");
        else println("XrefResolveTest.java> FAIL: " + failures + " check(s) failed");
    }

    private Address wa(long w) { return sp.getAddress(w * 2); }

    /**
     * runScript(name) takes the FIRST match on the script path, and the per-user ghidra_scripts
     * directory is searched before -scriptPath -- a stale personal copy of the script would be
     * the one tested. Load the copy that sits next to this test instead.
     */
    private void runSibling(String[] args) throws Exception {
        ResourceFile src = new ResourceFile(getSourceFile().getParentFile(), "ResolveComputedPointerXrefs.java");
        GhidraScript s = GhidraScriptUtil.getProvider(src).getScriptInstance(src, writer);
        s.setScriptArgs(args);
        s.execute(state, getControls());
    }

    /** References from the probe function into the two data blocks. */
    private List<Reference> probeRefs() {
        List<Reference> out = new ArrayList<>();
        for (int i = 0; i < WORDS.length; i++)
            for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(wa(CODE + i))) {
                long to = r.getToAddress().getOffset() / 2;
                if ((to >= DATA && to < DATA + 0x200) || (to >= LOW && to < LOW + 0x10)) out.add(r);
            }
        return out;
    }

    private void expectRef(long from, long to, RefType type) {
        for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(wa(from)))
            if (r.getToAddress().equals(wa(to))) {
                if (r.getReferenceType() != type) fail(String.format("%04x -> %04x is %s, want %s",
                    from, to, r.getReferenceType(), type));
                return;
            }
        fail(String.format("no reference %04x -> %04x", from, to));
    }

    private void expectNone(long from, String why) {
        for (Reference r : probeRefs())
            if (r.getFromAddress().equals(wa(from)))
                fail(String.format("%04x -> %s should have no reference (%s)", from, r.getToAddress(), why));
    }

    private void expect(String what, int got, int want) {
        if (got != want) fail(String.format("%s: got %d, want %d", what, got, want));
    }

    private void fail(String msg) {
        println("XrefResolveTest.java> FAIL: " + msg);
        failures++;
    }
}
