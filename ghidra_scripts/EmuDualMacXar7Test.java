// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the core semantics added alongside tests/mac_xar7 (SPRU430F):
//
//   MOV PM,AX            PM = decoded AX(2:0): raw 0 -> +1, 1 -> 0, 5 -> -4 (AMODE=0),
//                        7 -> -6; AX(15:3) ignored. Had no constructor.
//   MAC P,loc16,*XAR7[++]  ACC += P; T = [loc16]; P = T * Prog[*XAR7]; ++ steps XAR7 by 1.
//                        Had no constructor.
//   Dual-memory XAR7 conflicts (MAC / IMACL / DMAC / QMACL): the program side reads XAR7 as
//                        it was BEFORE the loc operand ran, and a *XAR7++ program operand does
//                        not step XAR7 when the loc mode already moves it ("loc16/loc32 field
//                        priority"). Each case's operands are laid out so the old order --
//                        loc first, then the program read at the moved XAR7, then its own
//                        step -- reads a different word and leaves XAR7 somewhere else.
//   @AH/@AL destinations: MOVB loc16,#8bit,COND (only when the condition holds), MOVU loc16,OVC
//                        and MOV loc16,OVC set N/Z.
//   MAC P,loc16,*pma     now loads T, as its step 2 says.
//
// Host-driven, so any TMS320C28x program will do as the import target:
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuDualMacXar7Test.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuDualMacXar7Test extends GhidraScript {

    private static final long CODE = 0xc300L;
    private static final long X = 0x9100L;      // XAR7 at entry for the conflict cases
    private static final long D = 0x9000L;      // XAR4 data operand

    private int failures = 0;
    private int cases = 0;
    private long cursor = CODE;
    private AddressSpace space;

    @Override
    public void run() throws Exception {
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            movPm(emu);
            mac(emu);
            conflicts(emu);
            axFlags(emu);
            macPmaLoadsT(emu);
            if (failures == 0) {
                println("EmuDualMacXar7Test.java> PASS: MOV PM,AX, MAC *XAR7, XAR7 loc priority,"
                    + " @AX N/Z, MAC *pma T load (" + cases + " cases)");
            } else {
                println("EmuDualMacXar7Test.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // --- MOV PM,AX ---------------------------------------------------------------------
    private void movPm(EmulatorHelper emu) throws Exception {
        long[][] v = {          // AL value, expected signed PM
            {0x0000, 1}, {0x0001, 0}, {0x0002, -1}, {0x0005, -4}, {0x0007, -6},
            {0xFFF9, 0},        // upper bits ignored: AX(2:0) = 1
        };
        emu.writeRegister("AMODE", 0);
        for (long[] c : v) {
            cases++;
            emu.writeRegister("AL", c[0]);
            emu.writeRegister("PM", 0x55);
            if (!step(emu, "MOV PM,AL=0x" + Long.toHexString(c[0]), 0x5638)) {
                continue;
            }
            expect("MOV PM,AL=0x" + Long.toHexString(c[0]) + " [PM]",
                (byte) emu.readRegister("PM").longValue(), c[1]);
        }
        cases++;
        emu.writeRegister("AH", 0x0006);
        if (step(emu, "MOV PM,AH", 0x5639)) {
            expect("MOV PM,AH=6 [PM]", (byte) emu.readRegister("PM").longValue(), -5);
        }
    }

    // --- MAC P,*XAR4++,*XAR7 / MAC P,*XAR4,*XAR7++ -------------------------------------
    private void mac(EmulatorHelper emu) throws Exception {
        cases++;
        String what = "MAC P,*XAR4++,*XAR7";
        setWord(emu, D, 3);
        setWord(emu, X, 0xFFFC);                   // -4
        emu.writeRegister("ACC", 10);
        emu.writeRegister("P", 5);
        emu.writeRegister("XAR4", D);
        emu.writeRegister("XAR7", X);
        if (step(emu, what, 0x5607, 0xC784)) {
            expect(what + " [ACC]", u32(emu, "ACC"), 15);
            expect(what + " [T]", emu.readRegister("T").longValue() & 0xFFFF, 3);
            expect(what + " [P]", u32(emu, "P"), 0xFFFFFFF4L);
            expect(what + " [XAR4]", u32(emu, "XAR4"), D + 1);
            expect(what + " [XAR7]", u32(emu, "XAR7"), X);
        }
        cases++;
        what = "MAC P,*XAR4,*XAR7++";
        emu.writeRegister("XAR4", D);
        emu.writeRegister("XAR7", X);
        if (step(emu, what, 0x5607, 0x87C4)) {
            expect(what + " [XAR4]", u32(emu, "XAR4"), D);
            expect(what + " [XAR7]", u32(emu, "XAR7"), X + 1);
        }
    }

    // --- loc operand that also moves XAR7 ------------------------------------------------
    private void conflicts(EmulatorHelper emu) throws Exception {
        // Distinct words around X so each read is identifiable:
        //   X-2 / X-1 = 2, X = 7 (low half of the 32-bit cell at X), X+1 = 0, X+2 = 11
        setWord(emu, X - 2, 2);
        setWord(emu, X - 1, 0);
        setWord(emu, X, 7);
        setWord(emu, X + 1, 0);
        setWord(emu, X + 2, 11);

        // MAC P,*XAR7++,*XAR7: data reads X (7), program reads X (7), XAR7 = X+1 (loc only).
        cases++;
        String what = "MAC P,*XAR7++,*XAR7";
        if (macRun(emu, what, 0x87C7)) {
            expect(what + " [T]", emu.readRegister("T").longValue() & 0xFFFF, 7);
            expect(what + " [P]", u32(emu, "P"), 49);
            expect(what + " [XAR7]", u32(emu, "XAR7"), X + 1);
        }

        // MAC P,*--XAR7,*XAR7++: data reads X-1 (5), program reads X (7), XAR7 = X-1.
        setWord(emu, X - 1, 5);
        cases++;
        what = "MAC P,*--XAR7,*XAR7++";
        if (macRun(emu, what, 0x878F)) {
            expect(what + " [T]", emu.readRegister("T").longValue() & 0xFFFF, 5);     // data: X-1
            expect(what + " [P]", u32(emu, "P"), 35);                                 // prog: X (7)
            expect(what + " [XAR7]", u32(emu, "XAR7"), X - 1);                        // loc wins
        }
        setWord(emu, X - 1, 0);

        // MAC P,*XAR7,*XAR7++ (dis2000 prints the loc as *+XAR7[0], 0xC7): no conflict,
        // the program side steps.
        cases++;
        what = "MAC P,*XAR7,*XAR7++";
        if (macRun(emu, what, 0x87C7)) {
            expect(what + " [XAR7]", u32(emu, "XAR7"), X + 1);
        }

        // IMACL P,*XAR7++,*XAR7++: loc32 reads the cell at X (7), program reads X (7),
        // XAR7 = X+2 once -- not X+4, and the program side does not read X+2 (11).
        cases++;
        what = "IMACL P,*XAR7++,*XAR7++";
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        emu.writeRegister("XAR7", X);
        if (step(emu, what, 0x564D, 0x8787)) {
            expect(what + " [P]", u32(emu, "P"), 49);
            expect(what + " [XAR7]", u32(emu, "XAR7"), X + 2);
        }

        // QMACL P,*XAR7++,*XAR7 keeps the HIGH 32 bits of the product, so it needs a large
        // operand: the cell at X+2 = 0x40000000, read by both sides.
        cases++;
        what = "QMACL P,*XAR7++,*XAR7";
        setWord(emu, X + 2, 0);
        setWord(emu, X + 3, 0x4000);               // cell X+2 = 0x40000000
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        emu.writeRegister("XAR7", X + 2);
        if (step(emu, what, 0x564F, 0xC787)) {
            // data and program both read the cell at X+2: 2^30 * 2^30 = 2^60 -> high = 2^28
            expect(what + " [P]", u32(emu, "P"), 0x10000000L);
            expect(what + " [XAR7]", u32(emu, "XAR7"), X + 4);
        }

        // DMAC ACC:P,*--XAR7,*XAR7++: loc32 reads the cell at X-2 (hi 0, lo 2), program reads
        // the cell at X (hi 0, lo 7); XAR7 = X-2, the program side does not step.
        cases++;
        what = "DMAC ACC:P,*--XAR7,*XAR7++";
        setWord(emu, X - 2, 2);
        setWord(emu, X - 1, 0);
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        emu.writeRegister("XAR7", X);
        if (step(emu, what, 0x564B, 0x878F)) {
            expect(what + " [P]", u32(emu, "P"), 14);       // lo*lo = 2*7
            expect(what + " [XAR7]", u32(emu, "XAR7"), X - 2);
        }
    }

    private boolean macRun(EmulatorHelper emu, String what, int w2) throws Exception {
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        emu.writeRegister("T", 0xDEAD);
        emu.writeRegister("XAR7", X);
        return step(emu, what, 0x5607, w2);
    }

    // --- @AH / @AL destinations set N/Z ------------------------------------------------
    private void axFlags(EmulatorHelper emu) throws Exception {
        // MOVB @AL,#0x80,EQ with Z=1: taken, AL=0x80 -> N=0 Z=0.
        cases++;
        String what = "MOVB @AL,#0x80,EQ (taken)";
        emu.writeRegister("AL", 0x1234);
        flags(emu, 1, 1);
        if (step(emu, what, 0x56B1, 0x80A9)) {
            expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xFFFF, 0x80);
            expect(what + " [N]", emu.readRegister("N").longValue(), 0);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 0);
        }
        // Same with Z=0: not taken, AL and flags untouched (N stays 1).
        cases++;
        what = "MOVB @AL,#0x80,EQ (not taken)";
        emu.writeRegister("AL", 0x1234);
        flags(emu, 1, 0);
        if (step(emu, what, 0x56B1, 0x80A9)) {
            expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xFFFF, 0x1234);
            expect(what + " [N]", emu.readRegister("N").longValue(), 1);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 0);
        }
        // MOVB @AH,#0,UNC: AH=0 -> Z=1.
        cases++;
        what = "MOVB @AH,#0,UNC";
        emu.writeRegister("AH", 0x8000);
        flags(emu, 1, 0);
        if (step(emu, what, 0x56BF, 0x00A8)) {
            expect(what + " [AH]", emu.readRegister("AH").longValue() & 0xFFFF, 0);
            expect(what + " [N]", emu.readRegister("N").longValue(), 0);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 1);
        }
        // MOVU @AL,OVC with OVC=0 -> Z=1; with OVC=5 -> AL=5, Z=0.
        cases++;
        what = "MOVU @AL,OVC (OVC=0)";
        emu.writeRegister("OVC", 0);
        flags(emu, 1, 0);
        if (step(emu, what, 0x5628, 0x00A9)) {
            expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xFFFF, 0);
            expect(what + " [N]", emu.readRegister("N").longValue(), 0);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 1);
        }
        cases++;
        what = "MOVU @AL,OVC (OVC=5)";
        emu.writeRegister("OVC", 5);
        flags(emu, 1, 1);
        if (step(emu, what, 0x5628, 0x00A9)) {
            expect(what + " [AL]", emu.readRegister("AL").longValue() & 0xFFFF, 5);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 0);
        }
        // MOV @AH,OVC with OVC=0x20 -> AH=0x8000 -> N=1.
        cases++;
        what = "MOV @AH,OVC (OVC=0x20)";
        emu.writeRegister("OVC", 0x20);
        flags(emu, 0, 1);
        if (step(emu, what, 0x5629, 0x00A8)) {
            expect(what + " [AH]", emu.readRegister("AH").longValue() & 0xFFFF, 0x8000);
            expect(what + " [N]", emu.readRegister("N").longValue(), 1);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 0);
        }
        // Negative control: a memory destination leaves N/Z alone.
        cases++;
        what = "MOVU *XAR4,OVC (memory: flags untouched)";
        emu.writeRegister("OVC", 0);
        emu.writeRegister("XAR4", D);
        flags(emu, 1, 0);
        if (step(emu, what, 0x5628, 0x00C4)) {
            expect(what + " [N]", emu.readRegister("N").longValue(), 1);
            expect(what + " [Z]", emu.readRegister("Z").longValue(), 0);
        }
    }

    // --- MAC P,*XAR4,0:pma loads T -------------------------------------------------------
    private void macPmaLoadsT(EmulatorHelper emu) throws Exception {
        cases++;
        String what = "MAC P,*XAR4,*0x9100";
        setWord(emu, D, 6);
        setWord(emu, X, 9);
        emu.writeRegister("XAR4", D);
        emu.writeRegister("T", 0xDEAD);
        emu.writeRegister("ACC", 0);
        emu.writeRegister("P", 0);
        if (step(emu, what, 0x14C4, (int) X)) {
            expect(what + " [T]", emu.readRegister("T").longValue() & 0xFFFF, 6);
            expect(what + " [P]", u32(emu, "P"), 54);
        }
    }

    // --- helpers -------------------------------------------------------------------------
    private boolean step(EmulatorHelper emu, String what, int... words) throws Exception {
        long here = cursor;
        cursor += words.length;
        for (int i = 0; i < words.length; i++) {
            emu.writeMemoryValue(space.getAddress((here + i) * 2), 2, words[i] & 0xFFFFL);
        }
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) {
            fail(what, emu.getLastError());
            return false;
        }
        return true;
    }

    private void flags(EmulatorHelper emu, long n, long z) throws Exception {
        emu.writeRegister("N", n);
        emu.writeRegister("Z", z);
    }

    private void setWord(EmulatorHelper emu, long word, long v) throws Exception {
        emu.writeMemoryValue(space.getAddress(word * 2), 2, v & 0xFFFFL);
    }

    private static long u32(EmulatorHelper emu, String r) {
        return emu.readRegister(r).longValue() & 0xFFFFFFFFL;
    }

    private void expect(String what, long got, long want) {
        if (got == want) {
            return;
        }
        println(String.format("EmuDualMacXar7Test.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }

    private void fail(String what, String msg) {
        println("EmuDualMacXar7Test.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
