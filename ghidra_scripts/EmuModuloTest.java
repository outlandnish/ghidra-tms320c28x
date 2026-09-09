// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for *AR6%++ circular buffer wrap (issue #127 follow-up).
//
// SPRU430F §5.6.3: on each *AR6%++ reference, if AR6[7:0] == AR1[7:0] then
// AR6[7:0] = 0 (upper 8 bits of AR6 preserved); else AR6 post-increments by 1
// (loc16) or 2 (loc32). Only AR6 (== XAR6[15:0]) participates; XAR6[31:16] is
// never touched. The check is on the PRE-increment low byte and reads AR1 at
// runtime, so this cannot be modelled from disassembly-time context.
//
// A wrong or missing wrap decodes plausibly (listing is unchanged) but silently
// walks off the end of any circular buffer under emulation.
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuModuloTest extends GhidraScript {

    private static final long CODE = 0xc100L;

    // SUB ACC,*AR6%++ -- upper byte 0xAE (SUB ACC,loc16 opcode), lower 0xBF (*AR6%++).
    // The instruction is used purely to exercise the loc16 side-effect on XAR6; ACC
    // and the read value are not inspected.
    private static final long SUB_AR6_MOD = 0xAEBFL;

    // MOVL ACC,*AR6%++ -- 0x06 (MOVL ACC,loc32 opcode) | 0xBF (*AR6%++) shifted into
    // the low byte via the loc32 sub-table.  Chosen for the loc32 path (+= 2 stride).
    private static final long MOVL_AR6_MOD = 0x06BFL;

    private int failures = 0;
    private long codeCursor = CODE;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // loc16 (+1 stride). AR1=3, AR6 sweeps 0->1->2->3->wrap.
            step16(emu, sp, 0x00000000L, 0x00000003L, 0x00000001L, "loc16 step 0 -> 1");
            step16(emu, sp, 0x00000001L, 0x00000003L, 0x00000002L, "loc16 step 1 -> 2");
            step16(emu, sp, 0x00000002L, 0x00000003L, 0x00000003L, "loc16 step 2 -> 3");
            step16(emu, sp, 0x00000003L, 0x00000003L, 0x00000000L, "loc16 step 3 -> wrap to 0");

            // AR6[15:8] preserved on wrap.  AR6=0xFF03, AR1=0x03 -> wrap -> 0xFF00.
            step16(emu, sp, 0x0000FF03L, 0x00000003L, 0x0000FF00L,
                "loc16 wrap preserves AR6[15:8]");

            // XAR6[31:16] preserved on both wrap and non-wrap paths.
            step16(emu, sp, 0x12340000L, 0x00000003L, 0x12340001L,
                "loc16 no-wrap preserves XAR6[31:16]");
            step16(emu, sp, 0x12340003L, 0x00000003L, 0x12340000L,
                "loc16 wrap preserves XAR6[31:16]");

            // AR1[15:8] must NOT affect the check -- only AR1[7:0] matters.
            step16(emu, sp, 0x00000003L, 0x0000FF03L, 0x00000000L,
                "loc16 wrap ignores AR1[15:8]");
            step16(emu, sp, 0x00000003L, 0x00000004L, 0x00000004L,
                "loc16 no-wrap when AR1[7:0] != AR6[7:0]");

            // loc32 (+2 stride). AR1=6, AR6 sweeps 0->2->4->6->wrap.
            step32(emu, sp, 0x00000000L, 0x00000006L, 0x00000002L, "loc32 step 0 -> 2");
            step32(emu, sp, 0x00000002L, 0x00000006L, 0x00000004L, "loc32 step 2 -> 4");
            step32(emu, sp, 0x00000004L, 0x00000006L, 0x00000006L, "loc32 step 4 -> 6");
            step32(emu, sp, 0x00000006L, 0x00000006L, 0x00000000L, "loc32 step 6 -> wrap to 0");

            step32(emu, sp, 0x12340006L, 0x00000006L, 0x12340000L,
                "loc32 wrap preserves XAR6[31:16]");
        }
        finally {
            emu.dispose();
        }

        if (failures == 0)
            println("EmuModuloTest.java> PASS: *AR6%++ wrap semantics (loc16 + loc32)");
        else println("EmuModuloTest.java> FAIL: " + failures + " check(s) failed");
    }

    /** Step one SUB ACC,*AR6%++ and assert the new XAR6. */
    private void step16(EmulatorHelper emu, AddressSpace sp,
            long preXar6, long preXar1, long wantXar6, String what) throws Exception {
        emu.writeRegister("XAR6", preXar6);
        emu.writeRegister("XAR1", preXar1);
        long here = codeCursor; codeCursor += 2;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, SUB_AR6_MOD);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, "step: " + emu.getLastError()); return; }
        long got = emu.readRegister("XAR6").longValue() & 0xFFFFFFFFL;
        expect(what, got, wantXar6);
    }

    /** Step one MOVL ACC,*AR6%++ (loc32, stride 2) and assert the new XAR6. */
    private void step32(EmulatorHelper emu, AddressSpace sp,
            long preXar6, long preXar1, long wantXar6, String what) throws Exception {
        emu.writeRegister("XAR6", preXar6);
        emu.writeRegister("XAR1", preXar1);
        long here = codeCursor; codeCursor += 2;
        emu.writeMemoryValue(sp.getAddress(here * 2), 2, MOVL_AR6_MOD);
        emu.writeRegister("PC", here);
        if (!emu.step(monitor)) { fail(what, "step: " + emu.getLastError()); return; }
        long got = emu.readRegister("XAR6").longValue() & 0xFFFFFFFFL;
        expect(what, got, wantXar6);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuModuloTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
    private void fail(String what, String msg) {
        println("EmuModuloTest.java> FAIL (" + what + "): " + msg);
        failures++;
    }
}
