// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the lifetime of the V (overflow) flag.
//
// SPRU430F gives nearly every arithmetic op the same V row: "if an overflow occurs, V is set;
// otherwise V is not affected". V is sticky. What clears it is a conditional instruction that
// TESTS it ("if the V flag is tested by the condition, then V is cleared" -- B, SB, BF, XB,
// XCALL, XRETC, MOVL/MOV/MOVB ...,COND), CMP64, and SAT/SAT64. Every constructor used to
// overwrite V with this instruction's overflow, which erases an overflow an earlier op
// recorded. The case that needs sticky V is TI's 64-bit compare,
// `CMP64 ; SUBUL P ; SUBBL ACC ; CMP64 ; SB ...,GT`, where CMP64 reads the V the subtract chain
// left to correct the sign.
//
// Because V now outlives the op that set it, OVC accounting and OVM saturation must use the
// instruction's OWN overflow, not V; the "stale V" cases below pin that.
//
// Also covers the two conditional stores whose COND field was misread (MOVL loc32,ACC,COND
// took it from the loc32 byte; MOV loc16,AX,COND never decoded it and always stored), and
// MIN/MAX/MAXL/MAXCUL, which set V but cannot clear it, and ADDL/SUBL/SUBRL loc32,ACC, which
// set no flags at all.
//
// Run headless (any TMS320C28x program works; the test writes its own code into the emulator):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuVFlagTest.java -noanalysis
//@category C28x.Test
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuVFlagTest extends GhidraScript {

    private static final long CODE = 0x9000L;   // word address; the emulator creates the memory
    private static final long DATA = 0x9800L;   // word address of the *+XAR4[0] operand
    private static final int XAR4_0 = 0xC4;     // loc16/loc32: *+XAR4[0]
    private static final int EQ = 0x1, NEQ = 0x0, NOV = 0xA, OV = 0xB;

    private AddressSpace sp;
    private EmulatorHelper emu;
    private int failures = 0, cases = 0;
    private long next = CODE;                   // each case gets its own address: the emulator caches decodes

    @Override
    public void run() throws Exception {
        sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        emu = new EmulatorHelper(currentProgram);
        try {
            // --- sticky V: an op that does not overflow leaves V alone -----------------------
            c("ADDB AL,#1 keeps V=1", w(0x9C01), in("ACC", 0x10, "V", 1), out("AL", 0x11, "V", 1));
            c("ADDB AL,#1 keeps V=0", w(0x9C01), in("ACC", 0x10, "V", 0), out("AL", 0x11, "V", 0));
            c("ADDB AL,#1 still sets V", w(0x9C01), in("ACC", 0x7FFF, "V", 0), out("AL", 0x8000, "V", 1));
            c("NEG AL keeps V=1", w(0xFF5C), in("ACC", 3, "V", 1), out("AL", 0xFFFD, "V", 1));
            // --- OVC / OVM act on THIS op's overflow, not a stale V ---------------------------
            c("ADDB ACC,#1: stale V does not bump OVC", w(0x0901),
              in("ACC", 0, "V", 1, "OVM", 0, "OVC", 0), out("ACC", 1, "V", 1, "OVC", 0));
            c("ADDB ACC,#1: real overflow bumps OVC", w(0x0901),
              in("ACC", 0x7FFFFFFFL, "V", 0, "OVM", 0, "OVC", 0), out("ACC", 0x80000000L, "V", 1, "OVC", 1));
            c("ABS ACC: stale V does not saturate", w(0xFF56),
              in("ACC", 0xFFFFFFFBL, "V", 1, "OVM", 1), out("ACC", 5, "V", 1));
            // --- testing V clears it ----------------------------------------------------------
            c("SB OV, V=1: taken, clears V", w(0x6B04), in("V", 1), outPc(4, "V", 0));
            c("SB NOV, V=1: not taken, clears V", w(0x6A04), in("V", 1), outPc(1, "V", 0));
            c("SB NOV, V=0: taken", w(0x6A04), in("V", 0), outPc(4, "V", 0));
            c("SB EQ does not touch V", w(0x6104), in("V", 1, "Z", 1), outPc(4, "V", 1));
            // --- CMP64: N from ACC[31] corrected by V, then V cleared ---------------------------
            c("CMP64: overflowed positive reads negative", w(0x565E),
              in("ACC", 0x7FFFFFFFL, "P", 0, "V", 1), out("N", 1, "Z", 0, "V", 0));
            c("CMP64: negative, no overflow", w(0x565E),
              in("ACC", 0x80000000L, "P", 0, "V", 0), out("N", 1, "Z", 0, "V", 0));
            c("CMP64: zero", w(0x565E), in("ACC", 0, "P", 0, "V", 0), out("N", 0, "Z", 1, "V", 0));
            c("CMP64: low half non-zero", w(0x565E), in("ACC", 0, "P", 1, "V", 0), out("N", 0, "Z", 0));
            // --- MOVL loc32,ACC,COND: COND is word2 bits 8..11 ----------------------------------
            c("MOVL ACC,EQ with Z=1 stores", w(0x5648, EQ << 8 | XAR4_0),
              in("ACC", 0x12345678L, "Z", 1, "mem32", 0), out("mem32", 0x12345678L));
            c("MOVL ACC,EQ with Z=0 does not", w(0x5648, EQ << 8 | XAR4_0),
              in("ACC", 0x12345678L, "Z", 0, "mem32", 0), out("mem32", 0));
            c("MOVL ACC,OV stores and clears V", w(0x5648, OV << 8 | XAR4_0),
              in("ACC", 0x12345678L, "V", 1, "mem32", 0), out("mem32", 0x12345678L, "V", 0));
            // --- MOV loc16,AX,COND: was an unconditional store ----------------------------------
            c("MOV AL,NEQ with Z=0 stores", w(0x562A, NEQ << 8 | XAR4_0),
              in("ACC", 0x1234, "Z", 0, "mem16", 0), out("mem16", 0x1234));
            c("MOV AL,NEQ with Z=1 does not", w(0x562A, NEQ << 8 | XAR4_0),
              in("ACC", 0x1234, "Z", 1, "mem16", 0), out("mem16", 0));
            // --- MIN / MAX family: V set on a load, never cleared --------------------------------
            c("MAX AL loads: V, N set", w(0x5672, XAR4_0),
              in("ACC", 1, "V", 0, "mem16", 5), out("AL", 5, "V", 1, "N", 1, "Z", 0));
            c("MAX AL keeps: V left alone", w(0x5672, XAR4_0),
              in("ACC", 7, "V", 0, "mem16", 5), out("AL", 7, "V", 0, "N", 0, "Z", 0));
            c("MIN AL loads: V set", w(0x5674, XAR4_0),
              in("ACC", 7, "V", 0, "mem16", 5), out("AL", 5, "V", 1, "N", 0));
            c("MAXL ACC loads: V set", w(0x5661, XAR4_0),
              in("ACC", 1, "V", 0, "mem32", 5), out("ACC", 5, "V", 1));
            c("MAXCUL P, N=0 Z=1 P<[loc32]: V set", w(0x5651, XAR4_0),
              in("P", 1, "N", 0, "Z", 1, "V", 0, "mem32", 5), out("P", 5, "V", 1));
            c("MAXCUL P, N=1 Z=0: loads, V untouched", w(0x5651, XAR4_0),
              in("P", 1, "N", 1, "Z", 0, "V", 0, "mem32", 5), out("P", 5, "V", 0));
            // --- ADDL/SUBL/SUBRL loc32,ACC: were flag-silent. Flags from the stored result ------
            c("ADDL [m],ACC: 5+3", w(0x5601, XAR4_0), in("ACC", 3, "mem32", 5, "N", 1, "Z", 1, "C", 1),
              out("mem32", 8, "ACC", 3, "N", 0, "Z", 0, "C", 0, "V", 0, "OVC", 0));
            c("ADDL [m],ACC: carry to zero", w(0x5601, XAR4_0), in("ACC", 1, "mem32", 0xFFFFFFFFL),
              out("mem32", 0, "N", 0, "Z", 1, "C", 1, "V", 0));
            c("ADDL [m],ACC: positive overflow", w(0x5601, XAR4_0), in("ACC", 1, "mem32", 0x7FFFFFFFL),
              out("mem32", 0x80000000L, "N", 1, "C", 0, "V", 1, "OVC", 1));
            c("ADDL [m],ACC: stale V kept, OVC untouched", w(0x5601, XAR4_0), in("ACC", 1, "mem32", 1, "V", 1),
              out("mem32", 2, "V", 1, "OVC", 0));
            c("SUBL [m],ACC: 5-3, no borrow", w(0x5641, XAR4_0), in("ACC", 3, "mem32", 5),
              out("mem32", 2, "ACC", 3, "N", 0, "Z", 0, "C", 1, "V", 0));
            c("SUBL [m],ACC: 3-5 borrows", w(0x5641, XAR4_0), in("ACC", 5, "mem32", 3, "C", 1),
              out("mem32", 0xFFFFFFFEL, "N", 1, "C", 0, "V", 0));
            c("SUBL [m],ACC: negative overflow", w(0x5641, XAR4_0), in("ACC", 1, "mem32", 0x80000000L),
              out("mem32", 0x7FFFFFFFL, "N", 0, "C", 1, "V", 1));
            c("SUBRL [m],ACC: 5-3", w(0x5649, XAR4_0), in("ACC", 5, "mem32", 3),
              out("mem32", 2, "ACC", 5, "N", 0, "C", 1, "V", 0));
            c("SUBRL [m],ACC: 3-5 borrows", w(0x5649, XAR4_0), in("ACC", 3, "mem32", 5, "C", 1),
              out("mem32", 0xFFFFFFFEL, "N", 1, "C", 0));
            c("SUBRL [m],ACC: equal -> zero", w(0x5649, XAR4_0), in("ACC", 7, "mem32", 7),
              out("mem32", 0, "Z", 1, "C", 1));

            if (failures == 0) println("EmuVFlagTest.java> PASS: V lifetime (" + cases + " cases)");
            else println("EmuVFlagTest.java> FAIL: " + failures + " check(s) failed");
        } finally {
            emu.dispose();
        }
    }

    private static long[] w(long... words) { return words; }

    private static Map<String, Long> in(Object... kv) {
        Map<String, Long> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], ((Number) kv[i + 1]).longValue());
        return m;
    }

    private static Map<String, Long> out(Object... kv) { return in(kv); }

    /** Expected PC as an offset from the instruction, plus other expectations. */
    private static Map<String, Long> outPc(long pcOff, Object... kv) {
        Map<String, Long> m = in(kv);
        m.put("pc+", pcOff);
        return m;
    }

    private void c(String what, long[] words, Map<String, Long> setup, Map<String, Long> want) throws Exception {
        cases++;
        long at = next;
        next += words.length + 1;
        for (int i = 0; i < words.length; i++) emu.writeMemoryValue(sp.getAddress((at + i) * 2), 2, words[i]);
        // Neutral baseline, then the case's inputs.
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        for (String f : new String[] { "N", "Z", "C", "V", "OVM", "OVC", "SXM" }) emu.writeRegister(f, 0);
        emu.writeRegister("XAR4", DATA);
        emu.writeMemoryValue(sp.getAddress(DATA * 2), 4, 0xA5A5A5A5L);
        for (Map.Entry<String, Long> e : setup.entrySet()) {
            if (e.getKey().equals("mem16")) emu.writeMemoryValue(sp.getAddress(DATA * 2), 2, e.getValue());
            else if (e.getKey().equals("mem32")) emu.writeMemoryValue(sp.getAddress(DATA * 2), 4, e.getValue());
            else emu.writeRegister(e.getKey(), e.getValue());
        }
        emu.writeRegister("PC", at);
        if (!emu.step(monitor)) {
            println("EmuVFlagTest.java> FAIL (" + what + "): " + emu.getLastError());
            failures++;
            return;
        }
        for (Map.Entry<String, Long> e : want.entrySet()) {
            String k = e.getKey();
            long got;
            if (k.equals("pc+")) got = emu.readRegister("PC").longValue() - at;
            else if (k.equals("mem16")) got = emu.readMemoryByte(sp.getAddress(DATA * 2)) & 0xFF
                    | (emu.readMemoryByte(sp.getAddress(DATA * 2 + 1)) & 0xFF) << 8;
            else if (k.equals("mem32")) got = le(emu.readMemory(sp.getAddress(DATA * 2), 4));
            else got = emu.readRegister(k).longValue();
            if (got != e.getValue()) {
                println(String.format("EmuVFlagTest.java> FAIL: %s [%s] -- expected 0x%x, got 0x%x",
                    what, k, e.getValue(), got));
                failures++;
            }
        }
    }

    private static long le(byte[] b) {
        long v = 0;
        for (int i = b.length - 1; i >= 0; i--) v = v << 8 | (b[i] & 0xFF);
        return v;
    }
}
