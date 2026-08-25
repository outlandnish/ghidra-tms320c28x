// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation semantics test for the store-side loc16,AX ALU trio:
//
//   ADD  loc16, AX   0111 001A LLLL LLLL   [loc16] = [loc16] + AX
//   SUB  loc16, AX   0111 010A LLLL LLLL   [loc16] = [loc16] - AX
//   SUBR loc16, AX   1110 101A LLLL LLLL   [loc16] = AX - [loc16]
//
// SUB and SUBR are each other's mirror image and sit adjacent in the source, so a
// copy/paste swap between them produces a language that disassembles identically,
// passes fw parity, and silently inverts the sign of every result -- exactly the
// failure in issue #56, where SUB carried SUBR's body (and no flags at all). Only
// emulation can see it, hence this test rather than a listing fixture.
//
// The direction cases use asymmetric operands (0x0042 / 0x0072) so that a swap
// changes the answer; the flag cases pin C/V/N/Z, which #56's SUB never wrote.
// Note C28x carry polarity: on subtract, C is SET when there is NO borrow.
//
// Host-driven (writes bytes into emulator memory, then steps), so any TMS320C28x
// program works as the import target:
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuAluStoreTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuAluStoreTest extends GhidraScript {

    private static final long BASE = 0xc010L;   // word address of the instruction under test

    private int fails = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // --- SUB @AR6, AL : [loc16] = [loc16] - AX (issue #56 regression) ---------
        // 0x42 - 0x72 = -0x30 -> 0xFFD0.  A reversed SUB gives 0x0030 instead.
        check(sp, "SUB borrow",   0x74A6, 0x0042, 0x0072, 0xFFD0, /*C*/0, /*V*/0, /*N*/1, /*Z*/0);
        // 0x72 - 0x42 = 0x30, no borrow -> C set.
        check(sp, "SUB no-borrow", 0x74A6, 0x0072, 0x0042, 0x0030, 1, 0, 0, 0);
        // Equal operands -> zero, no borrow.
        check(sp, "SUB zero",      0x74A6, 0x1234, 0x1234, 0x0000, 1, 0, 0, 1);
        // Signed overflow: 0x8000 (min) - 0x0001 crosses the negative limit -> V set.
        check(sp, "SUB overflow",  0x74A6, 0x8000, 0x0001, 0x7FFF, 1, 1, 0, 0);
        // AH form (A bit = 1) uses the same body.
        check(sp, "SUB @AR6,AH",   0x75A6, 0x0042, 0x0072, 0xFFD0, 0, 0, 1, 0, /*useAH*/true);

        // --- SUBR @AR6, AL : [loc16] = AX - [loc16] (the mirror; must NOT change) --
        check(sp, "SUBR",          0xEAA6, 0x0042, 0x0072, 0x0030, 1, 0, 0, 0);

        // --- ADD @AR6, AL : [loc16] = [loc16] + AX (sibling the fix was modeled on)-
        check(sp, "ADD",           0x72A6, 0x0042, 0x0072, 0x00B4, 0, 0, 0, 0);

        if (fails == 0) {
            println("PASS: all store-side loc16,AX ALU assertions");
            return;
        }
        println("FAIL: " + fails + " store-side loc16,AX sub-case(s)");
        throw new AssertionError(fails + " store-side loc16,AX assertion(s) failed");
    }

    private void check(AddressSpace sp, String name, int word, int ar6, int ax,
                       int wantAr6, int wantC, int wantV, int wantN, int wantZ) throws Exception {
        check(sp, name, word, ar6, ax, wantAr6, wantC, wantV, wantN, wantZ, false);
    }

    /**
     * Emulate one `<op> @AR6, AX` instruction and compare AR6 plus the four status
     * flags against the SPRU430F-specified result.
     */
    private void check(AddressSpace sp, String name, int word, int ar6, int ax,
                       int wantAr6, int wantC, int wantV, int wantN, int wantZ,
                       boolean useAH) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            emu.writeMemoryValue(sp.getAddress(BASE * 2), 2, word);
            emu.writeRegister("AR6", ar6);
            emu.writeRegister(useAH ? "AH" : "AL", ax);
            emu.writeRegister("PC", BASE);
            // Start from the opposite of every expectation, so a flag the constructor
            // never writes reads back wrong instead of accidentally matching.
            emu.writeRegister("C", 1 - wantC);
            emu.writeRegister("V", 1 - wantV);
            emu.writeRegister("N", 1 - wantN);
            emu.writeRegister("Z", 1 - wantZ);

            if (!emu.step(monitor)) {
                println(name + " FAIL: emu.step: " + emu.getLastError());
                fails++;
                return;
            }

            long got = emu.readRegister("AR6").longValue() & 0xFFFFL;
            long c = emu.readRegister("C").longValue() & 1;
            long v = emu.readRegister("V").longValue() & 1;
            long n = emu.readRegister("N").longValue() & 1;
            long z = emu.readRegister("Z").longValue() & 1;

            if (got == wantAr6 && c == wantC && v == wantV && n == wantN && z == wantZ) {
                println(name + " PASS: AR6=0x" + hex(got) + " " + flags(c, v, n, z));
                return;
            }
            println(name + " FAIL: expected AR6=0x" + hex(wantAr6) + " "
                + flags(wantC, wantV, wantN, wantZ)
                + ", got AR6=0x" + hex(got) + " " + flags(c, v, n, z));
            fails++;
        } finally {
            emu.dispose();
        }
    }

    private static String hex(long v) {
        return String.format("%04x", v & 0xFFFFL);
    }

    private static String flags(long c, long v, long n, long z) {
        return "C=" + c + " V=" + v + " N=" + n + " Z=" + z;
    }
}
