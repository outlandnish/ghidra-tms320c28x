// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for issue #110 MOV family flag audit. Two classes of regression:
//
// (1) Constructors that used to skip N/Z entirely.
//     - MOV ACC,loc16<<#0 / MOV ACC,#imm16<<#0..15 / MOV ACC,loc16<<T /
//       MOV ACC,loc16<<#1..15 all routed through `mov_acc_mext_shift`, which
//       did the load but did not set N/Z. Fixed by adding setNZ32(ACC) to the
//       macro (tms320c28x.sinc).
//     - MOVL ACC,loc32       (tms320c28x_mov.sinc) : N/Z unconditional per spec.
//     - MOVL ACC,P<<PM       (tms320c28x_more.sinc, both pm_shift halves) : N/Z
//       unconditional per SPRU430F p.299.
//     - MOVP T,loc16         (tms320c28x_mac.sinc) : documented alias of
//       MOVL ACC,P<<PM with loc16=@T -- must set N/Z on the ACC=P load AND honor
//       the PM shift. Prior body dropped both.
//
// (2) Destination-conditional forms (SPRU430F: "N/Z set only when loc16=@AX" or
//     "only when loc32=@ACC"). Modeled via the PREAD-style @AH/@AL/@ACC split
//     (tms320c28x_more.sinc:396 precedent) so the register-alias destination gets
//     the flags while the memory-store destination stays flag-silent.
//     - MOVL @ACC,ACC        (mov.sinc)
//     - MOV @AH/@AL,P        (more.sinc, both pm_shift halves)
//     - MOVH @AH/@AL,P       (more.sinc, both pm_shift halves)
//     - MOVH @AH/@AL,ACC<<1  (more.sinc)
//     - MOV @AH/@AL,ACC<<#2..8 and MOVH @AH/@AL,ACC<<#2..8 (ext56.sinc, 2-word)
//
// Every case pre-seeds the asserted flag to its opposite; a body that leaves
// the flag alone (the pre-fix state) will fail.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuMovAccFlagsTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuMovAccFlagsTest extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP_BASE = 0x8000L;
    private static final long LOC_SP1 = 0x41L;      // *-SP[1] loc16/loc32 selector
    private static final long LOC_AH  = 0xA8L;      // @AH register-alias byte
    private static final long LOC_AL  = 0xA9L;      // @AL / @ACC (same low byte in loc16 / loc32)

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ============================================================
            // Class 1: unconditional N/Z holes (were flag-silent)
            // ============================================================

            // 1. MOV ACC,loc16<<#0 (op_hi8=0x85). Load negative -> N=1.
            // Value 0x8000 with SXM=0 sign-extends to 0x00008000 (positive: MOV
            // ACC,loc16 defaults to zero-extend when SXM=0). Use SXM=1 for negative
            // extension, so 0x8000 -> 0xffff8000, bit 31 set.
            movAccLoc16Sh0(emu, sp, /*sxm*/1L, /*mem*/0x8000L, /*wantAcc*/0xffff8000L, /*N*/1, /*Z*/0,
                "MOV ACC,loc16<<#0 : sxm=1 mem=0x8000 -> ACC negative, N=1 (macro regression)");
            // Zero -> Z=1.
            movAccLoc16Sh0(emu, sp, 0L, 0x0000L, 0x00000000L, 0, 1,
                "MOV ACC,loc16<<#0 : mem=0 -> Z=1 (macro regression)");

            // 2. MOV ACC,#imm16<<#0..15 (op_hi8=0xFF loc_hi4=0b0010 shft4). imm=0x8000,
            // shift=0, SXM=1 -> ACC=0xffff8000, N=1.
            movAccImmSh(emu, sp, /*sxm*/1L, /*imm*/0x8000L, /*shft*/0L, 0xffff8000L, 1, 0,
                "MOV ACC,#0x8000<<#0 sxm=1 -> N=1 (macro regression)");
            // imm=1, shift=15 -> ACC=0x00008000, N=0 Z=0.
            movAccImmSh(emu, sp, 0L, 0x0001L, 15L, 0x00008000L, 0, 0,
                "MOV ACC,#1<<#15 -> ACC=0x8000, N=0 Z=0 (regression sanity)");

            // 3. MOV ACC,loc16<<#1..15 (2-word: op16=0x5603 ; word2 = shft_hi4<<8 | loc).
            // SXM=1 mem=0x8000 shift=3 -> ACC=(sext 0x8000)<<3 = 0xfffc0000, N=1.
            movAccLoc16ShN(emu, sp, /*sxm*/1L, /*mem*/0x8000L, /*shft*/3L, 0xfffc0000L, 1, 0,
                "MOV ACC,loc16<<#3 sxm=1 mem=0x8000 -> N=1 (macro regression)");

            // 4. MOVL ACC,loc32 (op_hi8=0x06). loc32=0x80000001 -> ACC negative, N=1.
            movlAccLoc32(emu, sp, 0x80000001L, 1, 0,
                "MOVL ACC,loc32 : 0x80000001 -> N=1 (issue #110)");
            movlAccLoc32(emu, sp, 0x00000000L, 0, 1,
                "MOVL ACC,loc32 : 0 -> Z=1 (issue #110)");

            // 5. MOVL ACC,P<<PM pm_shift=0 (op16=0x16AC). P=0x80000000 -> ACC negative, N=1.
            movlAccP(emu, sp, 0x80000000L, 1, 0,
                "MOVL ACC,P (pm_shift=0) : P=0x80000000 -> N=1 (issue #110)");
            movlAccP(emu, sp, 0x00000000L, 0, 1,
                "MOVL ACC,P (pm_shift=0) : P=0 -> Z=1 (issue #110)");

            // 6. MOVP T,loc16 (op_hi8=0x16, loc!=0xAC). Documented alias of MOVL ACC,P<<PM
            // with loc16=@T. Prior body dropped BOTH the PM shift and the N/Z flags. On
            // pm_shift=0 the shift is a no-op, so N/Z is the observable regression here.
            // loc16=*-SP[1] rather than @AH: the ACC=P side would overwrite AH (ACC=AH:AL
            // sub-piece), invalidating any assertion on T=[AH].
            movpTLoc16(emu, sp, /*p*/0x80000000L, /*mem*/0x1234L,
                /*wantAcc*/0x80000000L, /*wantT*/0x1234L, 1, 0,
                "MOVP T,*-SP[1] : ACC=P, N=1, T=[mem] (issue #110)");
            movpTLoc16(emu, sp, 0L, 0x0000L, 0L, 0L, 0, 1,
                "MOVP T,*-SP[1] : P=0 -> Z=1, T=0 (issue #110)");

            // ============================================================
            // Class 2: destination-conditional splits (@ACC / @AH / @AL)
            // ============================================================

            // 7. MOVL @ACC,ACC (op_hi8=0x1E, loc_full8=0xA9). Store is a no-op on the
            // register alias; N/Z reflect ACC per spec (issue #110). Pre-set both flags
            // to opposite; a body that ignores the special dest keeps them stale.
            movlAtAccAcc(emu, sp, 0x80000000L, 1, 0,
                "MOVL @ACC,ACC : ACC=0x80000000 -> N=1 (deferred split)");
            movlAtAccAcc(emu, sp, 0L, 0, 1,
                "MOVL @ACC,ACC : ACC=0 -> Z=1 (deferred split)");

            // 8. MOV @AH,P pm_shift=0 (op_hi8=0x3F, loc_full8=0xA8). AH = PL, N/Z from AH.
            // P=0x00008000 -> PL=0x8000 -> AH=0x8000 -> N=1 (bit 15).
            movAtAxP(emu, sp, LOC_AH, /*p*/0x00008000L, /*wantAX*/0x8000L, 1, 0,
                "MOV @AH,P : P=0x8000 low half -> AH=0x8000, N=1");
            movAtAxP(emu, sp, LOC_AL, 0x00000000L, 0x0000L, 0, 1,
                "MOV @AL,P : P=0 -> AL=0, Z=1");

            // 9. MOVH @AL,P pm_shift=0 (op_hi8=0x57). AL = PH.
            // P=0x80000000 -> PH=0x8000 -> AL=0x8000 -> N=1.
            movhAtAxP(emu, sp, LOC_AL, 0x80000000L, 0x8000L, 1, 0,
                "MOVH @AL,P : P=0x80000000 -> AL=PH=0x8000, N=1");

            // 10. MOVH @AH,ACC<<1 (op_hi8=0xB3, loc_full8=0xA8). Store hi word of (ACC<<1).
            // ACC=0x40000000 -> ACC<<1 = 0x80000000 -> hi word 0x8000 -> AH=0x8000, N=1.
            movhAtAxAcc1(emu, sp, LOC_AH, 0x40000000L, 0x8000L, 1, 0,
                "MOVH @AH,ACC<<1 : ACC=0x40000000 -> AH=0x8000, N=1");
            movhAtAxAcc1(emu, sp, LOC_AL, 0L, 0L, 0, 1,
                "MOVH @AL,ACC<<1 : ACC=0 -> AL=0, Z=1");

            // 11. MOV @AH,ACC<<#3 (op16=0x562d, 2-word). Low word of (ACC<<3).
            // ACC=0x10000000 -> <<3 = 0x80000000 -> low word 0x0000 -> AH=0, Z=1.
            // Use a value that gives a distinct low word: ACC=0x00001100, <<3 -> 0x00008800
            // -> low word 0x8800 -> N=1.
            movAtAxAccShN(emu, sp, LOC_AH, /*acc*/0x00001100L, /*shft*/3L, 0x8800L, 1, 0,
                "MOV @AH,ACC<<#3 : ACC=0x1100 -> AH=0x8800, N=1 (2-word)");

            // 12. MOVH @AL,ACC<<#3 (op16=0x562f). High word of (ACC<<3).
            // ACC=0x10000000 -> <<3 = 0x80000000 -> high word 0x8000 -> AL=0x8000, N=1.
            movhAtAxAccShN(emu, sp, LOC_AL, 0x10000000L, 3L, 0x8000L, 1, 0,
                "MOVH @AL,ACC<<#3 : ACC=0x10000000 -> AL=0x8000, N=1 (2-word)");

            if (failures == 0) {
                println("EmuMovAccFlagsTest.java> PASS: MOV family N/Z audit (issue #110, 14 cases)");
            } else {
                println("EmuMovAccFlagsTest.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    // ---- helpers --------------------------------------------------------

    private void seedFlags(EmulatorHelper emu, long wantN, long wantZ) {
        emu.writeRegister("N", wantN == 1 ? 0L : 1L);
        emu.writeRegister("Z", wantZ == 1 ? 0L : 1L);
    }

    private void movAccLoc16Sh0(EmulatorHelper emu, AddressSpace sp, long sxm, long mem,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SXM", sxm);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x8500L | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movAccImmSh(EmulatorHelper emu, AddressSpace sp, long sxm, long imm, long shft,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SXM", sxm);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 6;
        // op_hi8=0xFF, loc_hi4=0b0010 (bits 4-7), shft4 (bits 0-3)
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0xFF20L | (shft & 0xfL));
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, imm & 0xffffL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movAccLoc16ShN(EmulatorHelper emu, AddressSpace sp, long sxm, long mem, long shft,
            long wantAcc, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SXM", sxm);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 6;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x5603L);
        // word2 = shft_hi4 (bits 8-11) | loc16
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ((shft & 0xfL) << 8) | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movlAccLoc32(EmulatorHelper emu, AddressSpace sp, long loc32val,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, loc32val & 0xffffL);
        emu.writeMemoryValue(sp.getAddress(SP_BASE * 2), 2, (loc32val >> 16) & 0xffffL);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x0600L | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, loc32val);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movlAccP(EmulatorHelper emu, AddressSpace sp, long pval,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("P", pval);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x16ACL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, pval);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movpTLoc16(EmulatorHelper emu, AddressSpace sp, long pval, long mem,
            long wantAcc, long wantT, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("P", pval);
        emu.writeRegister("SP", SP_BASE);
        emu.writeMemoryValue(sp.getAddress((SP_BASE - 1) * 2), 2, mem);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        // MOVP T,loc16 : op_hi8=0x16, loc16=*-SP[1] (0x41)
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x1600L | LOC_SP1);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, wantAcc);
        expect(what + " [T]",   emu.readRegister("T").longValue() & 0xffffL, wantT);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movlAtAccAcc(EmulatorHelper emu, AddressSpace sp, long accval,
            long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", accval);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        // MOVL loc32,ACC with loc32=@ACC : op_hi8=0x1E, loc_full8=0xA9
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x1E00L | LOC_AL);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        expect(what + " [ACC]", emu.readRegister("ACC").longValue() & 0xffffffffL, accval);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movAtAxP(EmulatorHelper emu, AddressSpace sp, long locByte, long pval,
            long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("P", pval);
        emu.writeRegister("AH", 0L);
        emu.writeRegister("AL", 0L);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        // MOV loc16,P (op_hi8=0x3F) : stores PL into AH/@AL
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x3F00L | locByte);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        String reg = locByte == LOC_AH ? "AH" : "AL";
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movhAtAxP(EmulatorHelper emu, AddressSpace sp, long locByte, long pval,
            long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("P", pval);
        emu.writeRegister("AH", 0L);
        emu.writeRegister("AL", 0L);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        // MOVH loc16,P (op_hi8=0x57) : stores PH into AH/@AL
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x5700L | locByte);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        String reg = locByte == LOC_AH ? "AH" : "AL";
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movhAtAxAcc1(EmulatorHelper emu, AddressSpace sp, long locByte, long accval,
            long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("ACC", accval);
        emu.writeRegister("AH", 0L);
        emu.writeRegister("AL", 0L);
        // ACC = AH:AL, so the AH/AL writes above will have modified ACC. Re-write ACC last.
        emu.writeRegister("ACC", accval);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 4;
        // MOVH loc16,ACC<<1 (op_hi8=0xB3)
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0xB300L | locByte);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        String reg = locByte == LOC_AH ? "AH" : "AL";
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movAtAxAccShN(EmulatorHelper emu, AddressSpace sp, long locByte,
            long accval, long shft, long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("AH", 0L);
        emu.writeRegister("AL", 0L);
        emu.writeRegister("ACC", accval);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 6;
        // MOV loc16,ACC<<#2..8 : op16=0x562d ; word2 = shft_hi4<<8 | loc
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x562dL);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ((shft & 0xfL) << 8) | locByte);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        String reg = locByte == LOC_AH ? "AH" : "AL";
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void movhAtAxAccShN(EmulatorHelper emu, AddressSpace sp, long locByte,
            long accval, long shft, long wantAX, long wantN, long wantZ, String what) throws Exception {
        emu.writeRegister("AH", 0L);
        emu.writeRegister("AL", 0L);
        emu.writeRegister("ACC", accval);
        seedFlags(emu, wantN, wantZ);
        long here = codeCursor; codeCursor += 6;
        // MOVH loc16,ACC<<#2..8 : op16=0x562f ; word2 = shft_hi4<<8 | loc
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, 0x562fL);
        emu.writeMemoryValue(sp.getAddress((here + 1) * 2), 2, ((shft & 0xfL) << 8) | locByte);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, emu.getLastError()); return; }
        String reg = locByte == LOC_AH ? "AH" : "AL";
        expect(what + " [" + reg + "]", emu.readRegister(reg).longValue() & 0xffffL, wantAX);
        expect(what + " [N]", emu.readRegister("N").longValue(), wantN);
        expect(what + " [Z]", emu.readRegister("Z").longValue(), wantZ);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuMovAccFlagsTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuMovAccFlagsTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
