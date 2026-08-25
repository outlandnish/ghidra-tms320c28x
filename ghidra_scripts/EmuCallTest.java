// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the RPC nested-call chain, which lives in
// TMS320C28xEmulateInstructionStateModifier rather than in SLEIGH.
//
// On the hardware, LCR pushes the *caller's* RPC and loads RPC with its own return
// address; LRETR returns through RPC and pops the saved one back. That save/restore
// used to be open-coded in the LCR/LRETR p-code, but pushing RPC there wrecked
// decompilation: unlike x86's CALL, which pushes the constant inst_next, the C28x push
// sources a live-in register, so the decompiler could not prove the store missed the
// caller's own frame. Every local collapsed into an offset off a roaming frame pointer
// and each return address surfaced as an ordinary value. The cspec already declares RPC
// via <returnaddress>, so only the emulator needs the chain -- hence the move, and hence
// this test, since nothing else covers it.
//
// ONE level of nesting cannot catch a missing chain: the single LRETR still finds the
// right address in RPC. It takes TWO, because the inner call is what clobbers RPC:
//
//   0xc100  LCR #0xc200      push RPC(seed); RPC=0xc102        -> outer call
//   0xc102  ADD ACC,#1       lands here only if both returns are correct
//   0xc103  (stop)
//   0xc200  LCR #0xc300      push RPC(0xc102); RPC=0xc202      -> inner call
//   0xc202  LRETR            PC=0xc202... ; pop RPC=0xc102
//   0xc300  LRETR            PC=0xc202    ; pop RPC=0xc102
//
// Without the pop, the outer LRETR re-reads the inner return address still sitting in
// RPC and jumps to 0xc202 forever -- so the failure mode is the step cap tripping, not a
// wrong-but-terminating answer.
//
// Run headless (any TMS320C28x program works as the import target; the test is
// host-driven and never reads the program's own bytes):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuCallTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuCallTest extends GhidraScript {

    // LCR #22bit: 0111 0110 01CC CCCC : CCCC CCCC CCCC CCCC
    // word1 = 0x7640 | addr[21:16], word2 = addr[15:0]. Cross-checked against a real
    // image: bytes 4a 76 e3 42 -> words 0x764a,0x42e3 -> LCR 0x000a42e3.
    private static final long LCR_W1 = 0x7640L;
    private static final long LRETR = 0x0006L;
    private static final long ADD_ACC_1 = 0x0901L;

    private static final long SEED_RPC = 0xABCDL;   // caller's own return address
    private static final long STACK = 0x500L;       // word address, inside M1_RAM

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            // outer caller
            write(emu, sp, 0xc100L, LCR_W1);
            write(emu, sp, 0xc101L, 0xc200L);
            write(emu, sp, 0xc102L, ADD_ACC_1);
            // A: calls B, then returns
            write(emu, sp, 0xc200L, LCR_W1);
            write(emu, sp, 0xc201L, 0xc300L);
            write(emu, sp, 0xc202L, LRETR);
            // B: returns immediately
            write(emu, sp, 0xc300L, LRETR);

            // Initialise the stack words the chain will push through, so the pops read
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
                    println("EmuCallTest.java> FAIL: emu.step at step " + steps + ": "
                        + emu.getLastError());
                    return;
                }
                if (++steps > 40) {
                    // The signature of a broken chain: the outer LRETR keeps returning
                    // into A because RPC was never restored.
                    println("EmuCallTest.java> FAIL: no termination in 40 steps"
                        + " (RPC never restored?) PC=0x"
                        + Long.toHexString(emu.readRegister("PC").longValue()));
                    return;
                }
            }

            long pc = emu.readRegister("PC").longValue() & 0xFFFFFFFFL;
            long acc = emu.readRegister("ACC").longValue() & 0xFFFFFFFFL;
            long spv = emu.readRegister("SP").longValue() & 0xFFFFFFFFL;
            long rpc = emu.readRegister("RPC").longValue() & 0xFFFFFFFFL;

            // 5 instructions: LCR, LCR, LRETR, LRETR, ADD.
            boolean ok = pc == 0xc103L && acc == 1L && spv == STACK && rpc == SEED_RPC
                && steps == 5;
            if (ok) {
                println("EmuCallTest.java> PASS: nested LCR/LRETR chain"
                    + " (PC=0x" + Long.toHexString(pc) + " ACC=" + acc
                    + " SP=0x" + Long.toHexString(spv)
                    + " RPC=0x" + Long.toHexString(rpc) + " steps=" + steps + ")");
            }
            else {
                println("EmuCallTest.java> FAIL: expected PC=0xc103 ACC=1"
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
