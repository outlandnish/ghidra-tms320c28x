// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Paul van der Wateren
//
// Emulation test for PUSH DP:ST1 / POP DP:ST1 (0x7609 / 0x7601), both previously <UNDEF>.
// SPRU430F pp.374 / 358:
//   PUSH: [SP] = ST1; [SP+1] = DP; SP += 2
//   POP:  SP -= 2; ST1 = [SP]; DP = [SP+1]
// ST1 is held as unpacked flag registers, so PUSH must pack them into the stored word and
// POP must unpack the restored word back into them; both directions are checked.
//
// Run: analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//     -processor TMS320C28x:LE:32:default -postScript EmuPushPopDpSt1Test.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuPushPopDpSt1Test extends GhidraScript {

    private static final long CODE = 0xc100L;
    private static final long SP0  = 0x0400L;
    private static final long DPV  = 0x0123L;
    // ST1 fields, LSB first: INTM DBGM PAGE0 VMAP SPA LOOP EALLOW IDLESTAT AMODE OBJMODE
    // (bit 10 reserved) M0M1MAP XF ARP(13..15)
    private static final String[] ST1_FIELDS =
        { "INTM", "DBGM", "PAGE0", "VMAP", "SPA", "LOOP", "EALLOW", "IDLESTAT", "AMODE", "OBJMODE" };
    // INTM=1, VMAP=1, EALLOW=1, OBJMODE=1, XF=1, ARP=5
    private static final long ST1V = 0x0001L | 0x0008L | 0x0040L | 0x0200L | 0x1000L | (5L << 13);

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // ---- PUSH DP:ST1
            emu.writeRegister("SP", SP0);
            emu.writeRegister("DP", DPV);
            writeSt1(emu, ST1V);
            emu.writeMemoryValue(sp.getAddress(SP0 * 2), 2, 0xdeadL);
            emu.writeMemoryValue(sp.getAddress((SP0 + 1) * 2), 2, 0xbeefL);
            emu.writeMemoryValue(sp.getAddress(CODE * 2), 2, 0x7609L);
            emu.writeRegister("PC", CODE);
            if (!emu.step(monitor)) { fail("PUSH DP:ST1", emu.getLastError()); }
            else {
                expect("PUSH DP:ST1 [SP]", emu.readRegister("SP").longValue() & 0xffffL, SP0 + 2);
                expect("PUSH DP:ST1 [SP+0]=ST1", mem(emu, sp, SP0), ST1V);
                expect("PUSH DP:ST1 [SP+1]=DP",  mem(emu, sp, SP0 + 1), DPV);
            }

            // ---- POP DP:ST1: clobber DP and every ST1 flag, then restore from the stack.
            emu.writeRegister("DP", 0x3ffL);
            writeSt1(emu, ~ST1V & 0xfbffL);
            emu.writeMemoryValue(sp.getAddress((CODE + 1) * 2), 2, 0x7601L);
            emu.writeRegister("PC", CODE + 1);
            if (!emu.step(monitor)) { fail("POP DP:ST1", emu.getLastError()); }
            else {
                expect("POP DP:ST1 [SP]", emu.readRegister("SP").longValue() & 0xffffL, SP0);
                expect("POP DP:ST1 [DP]", emu.readRegister("DP").longValue() & 0xffffL, DPV);
                expect("POP DP:ST1 [ST1 flags]", readSt1(emu), ST1V);
            }

            if (failures == 0) {
                println("EmuPushPopDpSt1Test.java> PASS: PUSH/POP DP:ST1 stack layout + ST1 pack/unpack (6 checks)");
            } else {
                println("EmuPushPopDpSt1Test.java> FAIL: " + failures + " check(s) failed");
            }
        } finally {
            emu.dispose();
        }
    }

    private void writeSt1(EmulatorHelper emu, long v) {
        for (int i = 0; i < ST1_FIELDS.length; i++) emu.writeRegister(ST1_FIELDS[i], (v >> i) & 1);
        emu.writeRegister("M0M1MAP", (v >> 11) & 1);
        emu.writeRegister("XF", (v >> 12) & 1);
        emu.writeRegister("ARP", (v >> 13) & 7);
    }
    private long readSt1(EmulatorHelper emu) {
        long v = 0;
        for (int i = 0; i < ST1_FIELDS.length; i++) v |= (emu.readRegister(ST1_FIELDS[i]).longValue() & 1) << i;
        v |= (emu.readRegister("M0M1MAP").longValue() & 1) << 11;
        v |= (emu.readRegister("XF").longValue() & 1) << 12;
        v |= (emu.readRegister("ARP").longValue() & 7) << 13;
        return v;
    }
    private long mem(EmulatorHelper emu, AddressSpace sp, long word) throws Exception {
        byte[] b = emu.readMemory(sp.getAddress(word * 2), 2);
        return (b[0] & 0xffL) | ((b[1] & 0xffL) << 8);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuPushPopDpSt1Test.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuPushPopDpSt1Test.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
