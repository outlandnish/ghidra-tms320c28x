// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the joined ACC_P[64] register overlay and the nine 64-bit
// ACC:P constructors rewritten to use it (ZAPA, ASR64/LSR64/LSL64 in both the
// #shcount and ,T forms, NEG64, CMP64) plus ZALR.
//
// WHY THIS EXISTS
// ---------------
// ACC:P is defined by SPRU430F as ACC = high 32, P = low 32. Ghidra's register
// space is little-endian, so the LOW half of a joined value must sit at the LOWER
// offset: P@0x00, ACC@0x04, ACC_P@0x00 size 8. Get that backwards and every one of
// these instructions still DISASSEMBLES perfectly -- the mnemonic and operands come
// from the pattern, not the semantics -- while the 64-bit shifts silently operate on
// (P << 32) | ACC. Nothing in run_disasm_test.ps1 or run_fw_parity.ps1 can see it.
// This test can: it reads the halves back after each op.
//
// The first sub-case (`overlay`) probes the layout directly with no instruction at
// all, so a failure there localizes the problem to the `define register` lines in
// tms320c28x.slaspec rather than to any one constructor.
//
// Host-driven (writes opcode words into emulator memory, then steps), so the import
// target is irrelevant -- any TMS320C28x program works.
//
// Run headless:
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuAccPTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

import java.math.BigInteger;

public class EmuAccPTest extends GhidraScript {

    private static final BigInteger M64 = new BigInteger("ffffffffffffffff", 16);
    private int fails = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        overlay();
        shiftImm(sp);
        shiftByT(sp);
        neg64(sp);
        zapa(sp);
        cmp64(sp);
        zalr(sp);

        println("EmuAccPTest.java> " + (fails == 0 ? "PASS" : "FAIL (" + fails + " checks)"));
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /** New emulator with `words` laid down at word address `base` and PC there. */
    private EmulatorHelper at(AddressSpace sp, long base, int... words) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        for (int i = 0; i < words.length; i++) {
            // wordsize=2: a word address is 2 byte-offsets.
            emu.writeMemoryValue(sp.getAddress((base + i) * 2), 2, words[i] & 0xFFFFL);
        }
        emu.writeRegister("PC", base);
        return emu;
    }

    /** Single-step one instruction; records a failure and returns false if it faults. */
    private boolean step1(EmulatorHelper emu, String what) throws Exception {
        if (!emu.step(monitor)) {
            fail(what + ": emu.step failed: " + emu.getLastError());
            return false;
        }
        return true;
    }

    private BigInteger u64(EmulatorHelper emu, String reg) {
        return emu.readRegister(reg).and(M64);
    }

    private long u32(EmulatorHelper emu, String reg) {
        return emu.readRegister(reg).longValue() & 0xFFFFFFFFL;
    }

    private void chk32(String what, long got, long want) {
        if (got == want) {
            println("  ok   " + what + " = 0x" + Long.toHexString(got));
        } else {
            fail(what + ": expected 0x" + Long.toHexString(want) + ", got 0x" + Long.toHexString(got));
        }
    }

    private void chk64(String what, BigInteger got, String wantHex) {
        BigInteger want = new BigInteger(wantHex, 16);
        if (got.equals(want)) {
            println("  ok   " + what + " = 0x" + got.toString(16));
        } else {
            fail(what + ": expected 0x" + wantHex + ", got 0x" + got.toString(16));
        }
    }

    private void fail(String msg) {
        println("  FAIL " + msg);
        fails++;
    }

    /** Set the ACC:P pair through the two 32-bit halves. */
    private void seed(EmulatorHelper emu, long acc, long p) {
        emu.writeRegister("ACC", acc);
        emu.writeRegister("P", p);
    }

    /** Assert the ACC:P pair through the two 32-bit halves. */
    private void expect(EmulatorHelper emu, String what, long acc, long p) {
        chk32(what + " ACC", u32(emu, "ACC"), acc);
        chk32(what + " P", u32(emu, "P"), p);
    }

    // -----------------------------------------------------------------------
    // 1. the overlay itself -- no instruction involved
    // -----------------------------------------------------------------------

    private void overlay() throws Exception {
        println("=== overlay (register layout only) ===");
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ACC is the HIGH 32 bits of ACC_P, P the LOW 32.
            seed(emu, 0x11223344L, 0xAABBCCDDL);
            chk64("ACC_P after ACC=0x11223344 P=0xaabbccdd", u64(emu, "ACC_P"), "11223344aabbccdd");

            // ...and the other direction.
            emu.writeRegister("ACC_P", new BigInteger("0123456789abcdef", 16));
            expect(emu, "halves after ACC_P=0x0123456789abcdef", 0x01234567L, 0x89ABCDEFL);

            // Halves inside each 32-bit register keep the usual LE convention.
            chk32("AH", emu.readRegister("AH").longValue() & 0xFFFFL, 0x0123L);
            chk32("AL", emu.readRegister("AL").longValue() & 0xFFFFL, 0x4567L);
            chk32("PH", emu.readRegister("PH").longValue() & 0xFFFFL, 0x89ABL);
            chk32("PL", emu.readRegister("PL").longValue() & 0xFFFFL, 0xCDEFL);
        } finally {
            emu.dispose();
        }
    }

    // -----------------------------------------------------------------------
    // 2. ASR64 / LSR64 / LSL64 ACC:P,#shcount   (shcount = SHFT + 1)
    // -----------------------------------------------------------------------

    private void shiftImm(AddressSpace sp) throws Exception {
        println("=== ASR64/LSR64/LSL64 ACC:P,#4 ===");

        // LSL64 ACC:P,#4  -- 0x56a3 (op_hi8=0x56, loc_hi4=0b1010, SHFT=3 -> shcount 4).
        // 0x11223344_aabbccdd << 4 = 0x1223344a_abbccdd0
        EmulatorHelper e = at(sp, 0xc030L, 0x56A3);
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            if (step1(e, "LSL64 #4")) expect(e, "LSL64 #4", 0x1223344AL, 0xABBCCDD0L);
        } finally { e.dispose(); }

        // LSR64 ACC:P,#4  -- 0x5693.  >> 4 = 0x01122334_4aabbccd
        e = at(sp, 0xc040L, 0x5693);
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            if (step1(e, "LSR64 #4")) expect(e, "LSR64 #4", 0x01122334L, 0x4AABBCCDL);
        } finally { e.dispose(); }

        // ASR64 ACC:P,#4  -- 0x5683, negative input so the sign fill is visible.
        // 0x91223344_aabbccdd s>> 4 = 0xf9122334_4aabbccd
        e = at(sp, 0xc050L, 0x5683);
        try {
            seed(e, 0x91223344L, 0xAABBCCDDL);
            if (step1(e, "ASR64 #4")) expect(e, "ASR64 #4", 0xF9122334L, 0x4AABBCCDL);
        } finally { e.dispose(); }

        // ASR64 on a POSITIVE value must NOT sign-fill -- this is the check that
        // separates "sign bit read from ACC" (correct) from "read from P" (swapped).
        e = at(sp, 0xc058L, 0x5683);
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            if (step1(e, "ASR64 #4 (positive)")) expect(e, "ASR64 #4 (positive)", 0x01122334L, 0x4AABBCCDL);
        } finally { e.dispose(); }
    }

    // -----------------------------------------------------------------------
    // 3. ASR64 / LSR64 / LSL64 ACC:P,T   (shift count = T[5:0])
    // -----------------------------------------------------------------------

    private void shiftByT(AddressSpace sp) throws Exception {
        println("=== ASR64/LSR64/LSL64 ACC:P,T (T=4) ===");

        EmulatorHelper e = at(sp, 0xc060L, 0x5652);   // LSL64 ACC:P,T
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            e.writeRegister("T", 4L);
            if (step1(e, "LSL64 T")) expect(e, "LSL64 T", 0x1223344AL, 0xABBCCDD0L);
        } finally { e.dispose(); }

        e = at(sp, 0xc068L, 0x565B);                  // LSR64 ACC:P,T
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            e.writeRegister("T", 4L);
            if (step1(e, "LSR64 T")) expect(e, "LSR64 T", 0x01122334L, 0x4AABBCCDL);
        } finally { e.dispose(); }

        e = at(sp, 0xc070L, 0x562C);                  // ASR64 ACC:P,T
        try {
            seed(e, 0x91223344L, 0xAABBCCDDL);
            e.writeRegister("T", 4L);
            if (step1(e, "ASR64 T")) expect(e, "ASR64 T", 0xF9122334L, 0x4AABBCCDL);
        } finally { e.dispose(); }
    }

    // -----------------------------------------------------------------------
    // 4. NEG64 ACC:P  (0x5658)
    // -----------------------------------------------------------------------

    private void neg64(AddressSpace sp) throws Exception {
        println("=== NEG64 ACC:P ===");

        // -1 == 0xffffffff_ffffffff.  A borrow has to cross the ACC/P seam here, so a
        // swapped layout gives 0x00000000_ffffffff-ish garbage instead.
        EmulatorHelper e = at(sp, 0xc078L, 0x5658);
        try {
            seed(e, 0x00000000L, 0x00000001L);
            if (step1(e, "NEG64 (1)")) {
                expect(e, "NEG64 (1)", 0xFFFFFFFFL, 0xFFFFFFFFL);
                chk32("NEG64 (1) N", emu8(e, "N"), 1);
                chk32("NEG64 (1) Z", emu8(e, "Z"), 0);
            }
        } finally { e.dispose(); }

        e = at(sp, 0xc080L, 0x5658);
        try {
            seed(e, 0x00000000L, 0x00000000L);
            if (step1(e, "NEG64 (0)")) {
                expect(e, "NEG64 (0)", 0x00000000L, 0x00000000L);
                chk32("NEG64 (0) Z", emu8(e, "Z"), 1);
            }
        } finally { e.dispose(); }
    }

    // -----------------------------------------------------------------------
    // 5. ZAPA  (0x5633)
    // -----------------------------------------------------------------------

    private void zapa(AddressSpace sp) throws Exception {
        println("=== ZAPA ===");
        EmulatorHelper e = at(sp, 0xc088L, 0x5633);
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            if (step1(e, "ZAPA")) expect(e, "ZAPA", 0L, 0L);
        } finally { e.dispose(); }
    }

    // -----------------------------------------------------------------------
    // 6. CMP64 ACC:P  (0x565e) -- sets N/Z from the 64-bit pair
    // -----------------------------------------------------------------------

    private void cmp64(AddressSpace sp) throws Exception {
        println("=== CMP64 ACC:P ===");

        // Sign comes from ACC's MSB (bit 63 of the pair). If ACC and P were swapped,
        // this reads P's MSB (0) and N comes out 0.
        EmulatorHelper e = at(sp, 0xc090L, 0x565E);
        try {
            seed(e, 0x80000000L, 0x00000000L);
            if (step1(e, "CMP64 (negative)")) {
                chk32("CMP64 (negative) N", emu8(e, "N"), 1);
                chk32("CMP64 (negative) Z", emu8(e, "Z"), 0);
            }
        } finally { e.dispose(); }

        // Z must consider BOTH halves: ACC=0 but P!=0 is NOT zero.
        e = at(sp, 0xc098L, 0x565E);
        try {
            seed(e, 0x00000000L, 0x00000001L);
            if (step1(e, "CMP64 (P-only)")) {
                chk32("CMP64 (P-only) N", emu8(e, "N"), 0);
                chk32("CMP64 (P-only) Z", emu8(e, "Z"), 0);
            }
        } finally { e.dispose(); }

        e = at(sp, 0xc0a0L, 0x565E);
        try {
            seed(e, 0x00000000L, 0x00000000L);
            if (step1(e, "CMP64 (zero)")) {
                chk32("CMP64 (zero) N", emu8(e, "N"), 0);
                chk32("CMP64 (zero) Z", emu8(e, "Z"), 1);
            }
        } finally { e.dispose(); }
    }

    // -----------------------------------------------------------------------
    // 7. ZALR ACC,loc16  (0x5613 : loc16) -- now one ACC store, not AL/AH halves
    // -----------------------------------------------------------------------

    private void zalr(AddressSpace sp) throws Exception {
        println("=== ZALR ACC,@PH ===");
        // loc16 @PH = loc_full8 0b10101010 = 0xaa, in the low byte of the second word.
        // P = 0xaabbccdd -> PH = 0xaabb -> ACC = 0xaabb8000, and P is left alone.
        EmulatorHelper e = at(sp, 0xc0a8L, 0x5613, 0x00AA);
        try {
            seed(e, 0x11223344L, 0xAABBCCDDL);
            if (step1(e, "ZALR")) expect(e, "ZALR", 0xAABB8000L, 0xAABBCCDDL);
        } finally { e.dispose(); }
    }

    private long emu8(EmulatorHelper emu, String reg) {
        return emu.readRegister(reg).longValue() & 0xFFL;
    }
}
