// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the LC / LRET pair -- the SOFTWARE-STACK long call, which is a
// different mechanism from the LCR / LRETR pair covered by EmuCallTest.
//
// SPRU430F p.218-219 is explicit that LC does NOT use RPC:
//
//     temp(21:0) = PC + 2;
//     [SP] = temp(15:0);   SP = SP + 1;
//     [SP] = temp(21:16);  SP = SP + 1;
//     PC = 22bit;
//
// and LRET pops that word back off SP. RPC is never touched -- that is the entire
// difference between the two mechanisms, and TI's own note recommends LCR/LRETR
// instead when OBJMODE=1, which is why a TI-compiled image is essentially all LCR.
//
// WHY THIS TEST EXISTS. LC used to be modelled as `RPC = inst_next >> 1` with no stack
// write, copied from LCR, while LRET already popped a 32-bit return address off SP. The
// pair therefore did not compose: nothing was ever pushed, so LRET returned to whatever
// happened to sit at the top of the frame. The emulator's state modifier hid it by
// listing LC in its RPC-chain callback, which pushed the caller's STALE RPC into that
// slot rather than the return address -- so a two-level test still terminated, at the
// wrong address, and a one-level test could pass by accident.
//
// Three things are asserted, and each fails on a different half of the old model:
//   * PC returns to the instruction after the call  -- the push must carry the RETURN
//     ADDRESS, not the stale RPC the state modifier used to store;
//   * SP is balanced back to its seed                -- the push must actually happen,
//     and be 2 words;
//   * RPC still holds its seed                       -- LC must not write RPC at all.
//
// Nesting is deliberate. One level cannot distinguish a correct push from a stale-RPC
// push when the seed happens to be plausible; the inner call is what would clobber a
// shared register, and the outer return is what proves the two frames stayed distinct.
//
// Run headless (any TMS320C28x program works as the import target; the test is
// host-driven and never reads the program's own bytes):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuLcTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuLcTest extends GhidraScript {

    // LC 22bit: 0000 0000 10CC CCCC : CCCC CCCC CCCC CCCC
    // word1 = 0x0080 | addr[21:16], word2 = addr[15:0].
    private static final long LC_W1 = 0x0080L;
    private static final long LRET = 0x7614L;
    private static final long ADD_ACC_1 = 0x0901L;

    // A value LC must leave completely alone.
    private static final long SEED_RPC = 0xABCDL;
    private static final long STACK = 0x500L;       // word address, inside M1_RAM

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // outer caller: calls A, then lands on the ADD only if both returns are right
            write(emu, sp, 0xc100L, LC_W1);
            write(emu, sp, 0xc101L, 0xc200L);
            write(emu, sp, 0xc102L, ADD_ACC_1);
            // A: calls B, then returns
            write(emu, sp, 0xc200L, LC_W1);
            write(emu, sp, 0xc201L, 0xc300L);
            write(emu, sp, 0xc202L, LRET);
            // B: returns immediately
            write(emu, sp, 0xc300L, LRET);

            // Initialise the stack words the calls push through, so a pop reads
            // emulator-initialised memory rather than faulting on undefined bytes.
            emu.writeMemoryValue(sp.getAddress(STACK * 2), 4, 0L);
            emu.writeMemoryValue(sp.getAddress((STACK + 2) * 2), 4, 0L);

            emu.writeRegister("ACC", 0L);
            emu.writeRegister("SP", STACK);
            emu.writeRegister("RPC", SEED_RPC);
            emu.writeRegister("PC", 0xc100L);

            // Run to the stop word. Not "PC < 0xc103": the callees live *above* that
            // address, so a bound test exits on the very first call.
            int steps = 0;
            while ((emu.readRegister("PC").longValue() & 0xFFFFFFFFL) != 0xc103L) {
                if (!emu.step(monitor)) {
                    println("EmuLcTest.java> FAIL: emu.step at step " + steps + ": "
                        + emu.getLastError());
                    return;
                }
                if (++steps > 40) {
                    println("EmuLcTest.java> FAIL: no termination in 40 steps"
                        + " (LC pushed no return address?) PC=0x"
                        + Long.toHexString(emu.readRegister("PC").longValue()));
                    return;
                }
            }

            long pc = emu.readRegister("PC").longValue() & 0xFFFFFFFFL;
            long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
            long spv = emu.readRegister("SP").longValue() & 0xFFFFFFFFL;
            long rpc = emu.readRegister("RPC").longValue() & 0xFFFFFFFFL;

            // 5 instructions: LC, LC, LRET, LRET, ADD.
            boolean ok = pc == 0xc103L && acc == 1L && spv == STACK && rpc == SEED_RPC
                && steps == 5;
            if (ok) {
                println("EmuLcTest.java> PASS: nested LC/LRET stack chain, RPC untouched"
                    + " (PC=0x" + Long.toHexString(pc) + " ACC=" + acc
                    + " SP=0x" + Long.toHexString(spv)
                    + " RPC=0x" + Long.toHexString(rpc) + " steps=" + steps + ")");
            }
            else {
                println("EmuLcTest.java> FAIL: expected PC=0xc103 ACC=1"
                    + " SP=0x" + Long.toHexString(STACK)
                    + " RPC=0x" + Long.toHexString(SEED_RPC) + " steps=5, got"
                    + " PC=0x" + Long.toHexString(pc) + " ACC=" + acc
                    + " SP=0x" + Long.toHexString(spv)
                    + " RPC=0x" + Long.toHexString(rpc) + " steps=" + steps);
            }
        }
        finally {
            emu.dispose();
        }
    }

    /** Write one 16-bit instruction word at a word address (byte offset = word * 2). */
    private void write(EmulatorHelper emu, AddressSpace sp, long word, long value)
            throws Exception {
        emu.writeMemoryValue(sp.getAddress(word * 2), 2, value);
    }
}
