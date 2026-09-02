// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Emulation test for the C2xLP source-compatible family's two semantics that DISASSEMBLY
// CANNOT SEE. Both were wrong in this module for as long as the family has been decoded, and
// neither run_disasm_test nor run_fw_parity could ever have caught them: the listing text is
// identical either way, because both compare mnemonics.
//
//  1. THE 0x3F PROGRAM PAGE. SPRU430F forces the upper 6 bits of the 22-bit program address for
//     every X* instruction -- "[loc16] = Prog[0x3F:pma]", "PC = 0x3F:pma". This module formed a
//     plain 16-bit address, so an XPREAD read the wrong page entirely. Note the NON-X `MAC
//     P,loc16,*(pma)` forces 0x00 instead, so a family-wide "add the page" would be wrong; the
//     PREAD case below is the guard for that distinction.
//
//  2. XCALL/XRET USE THE SOFTWARE STACK, NOT RPC. SPRU430F: XCALL does
//     "temp(21:0) = PC + 1; [SP] = temp(15:0); SP = SP + 1", and XRETC does
//     "SP = SP - 1; PC = 0x3F:[SP]". This module modelled both through RPC, the LCR/LRETR
//     mechanism. That was SELF-CONSISTENT -- XCALL wrote RPC and XRET read it back, so a
//     call/return pair round-tripped and nothing looked broken -- while leaving SP unmoved
//     across the call and clobbering a register hardware does not touch.
//
// Run headless (any TMS320C28x program works; the test drives memory itself):
//   analyzeHeadless <proj> t -import tests/fpu_flags.bin \
//       -processor TMS320C28x:LE:32:default -postScript EmuC2xlpTest.java -noanalysis
//@category C28x.Test
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;

public class EmuC2xlpTest extends GhidraScript {

    // Each case gets its OWN code address and its OWN EmulatorHelper. Ghidra's emulator caches
    // the decoded instruction per address, so re-using one address across cases silently re-runs
    // the PREVIOUS case's instruction even after the opcode word underneath it is rewritten --
    // which shows up as wildly wrong results that look like spec bugs.
    private static final long CODE_XPREAD = 0xc100L;
    private static final long CODE_PREAD = 0xc110L;
    private static final long CODE_XCALL = 0xc120L;
    private static final long CODE_XRET = 0xc130L;
    private static final long CODE_XBANZ = 0xc140L;
    private static final long STACK = 0x0500L;
    private static final long PMA = 0x1234L;          // the 16-bit operand
    private static final long PAGED = 0x3f1234L;      // where SPRU430F says it must land
    private static final long PAGED_WORD = 0xbeefL;   // planted at the paged address
    private static final long BARE_WORD = 0xdeadL;    // planted at the un-paged address

    private int failures = 0;

    @Override
    public void run() throws Exception {
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        run(sp, 0);
        run(sp, 1);
        run(sp, 2);
        run(sp, 3);
        run(sp, 4);
        if (failures == 0)
            println("EmuC2xlpTest.java> PASS: 0x3F page + XCALL/XRET stack + XBANZ via ARP");
        else println("EmuC2xlpTest.java> FAIL: " + failures + " check(s) failed");
    }

    private void run(AddressSpace sp, int which) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            if (which == 0) xpreadPage(emu, sp);
            else if (which == 1) preadStaysUnpaged(emu, sp);
            else if (which == 2) xcallPushesStack(emu, sp);
            else if (which == 3) xretPopsStack(emu, sp);
            else xbanzIndexesByArp(emu, sp);
        }
        finally {
            emu.dispose();
        }
    }

    /** XPREAD @AL,*(pma) must read Prog[0x3F:pma], not Prog[pma]. */
    private void xpreadPage(EmulatorHelper emu, AddressSpace sp) throws Exception {
        emu.writeMemoryValue(sp.getAddress(PAGED * 2), 2, PAGED_WORD);
        emu.writeMemoryValue(sp.getAddress(PMA * 2), 2, BARE_WORD);
        emu.writeMemoryValue(sp.getAddress(CODE_XPREAD * 2), 2, 0xACA9L);          // XPREAD @AL,*(pma)
        emu.writeMemoryValue(sp.getAddress((CODE_XPREAD + 1) * 2), 2, PMA);
        emu.writeRegister("AL", 0L);
        emu.writeRegister("PC", CODE_XPREAD);
        emu.step(monitor);
        expect("XPREAD reads the 0x3F page", emu.readRegister("AL").longValue() & 0xffffL,
            PAGED_WORD);
    }

    /**
     * The counterpart guard: PREAD is NOT an X* instruction and must keep reading *XAR7 as a
     * plain 22-bit address. If someone ever "fixes" the page family-wide, this fails.
     */
    private void preadStaysUnpaged(EmulatorHelper emu, AddressSpace sp) throws Exception {
        emu.writeMemoryValue(sp.getAddress(PMA * 2), 2, BARE_WORD);
        emu.writeMemoryValue(sp.getAddress(CODE_PREAD * 2), 2, 0x24A9L);           // PREAD @AL,*XAR7
        emu.writeRegister("XAR7", PMA);
        emu.writeRegister("AL", 0L);
        emu.writeRegister("PC", CODE_PREAD);
        emu.step(monitor);
        expect("PREAD stays un-paged", emu.readRegister("AL").longValue() & 0xffffL, BARE_WORD);
    }

    /** XCALL *AL pushes the low 16 bits of the return address and bumps SP; RPC is untouched. */
    private void xcallPushesStack(EmulatorHelper emu, AddressSpace sp) throws Exception {
        emu.writeMemoryValue(sp.getAddress(CODE_XCALL * 2), 2, 0x5634L);           // XCALL *AL
        emu.writeRegister("AL", PMA);
        emu.writeRegister("SP", STACK);
        emu.writeRegister("RPC", 0x123456L);
        emu.writeRegister("PC", CODE_XCALL);
        emu.step(monitor);

        expect("XCALL branches to the 0x3F page",
            emu.readRegister("PC").longValue() & 0x3fffffL, PAGED);
        expect("XCALL pushes one word", emu.readRegister("SP").longValue() & 0xffffL, STACK + 1);
        byte[] b = emu.readMemory(sp.getAddress(STACK * 2), 2);
        expect("XCALL pushes the return address",
            (b[0] & 0xffL) | ((b[1] & 0xffL) << 8), CODE_XCALL + 1);
        expect("XCALL leaves RPC alone (it is not the LCR mechanism)",
            emu.readRegister("RPC").longValue() & 0xffffffL, 0x123456L);
    }

    /** XRETC UNC pops that word back and re-forces the page. */
    private void xretPopsStack(EmulatorHelper emu, AddressSpace sp) throws Exception {
        emu.writeMemoryValue(sp.getAddress(STACK * 2), 2, PMA);
        emu.writeMemoryValue(sp.getAddress(CODE_XRET * 2), 2, 0x56FFL);            // XRETC UNC
        emu.writeRegister("SP", STACK + 1);
        emu.writeRegister("PC", CODE_XRET);
        emu.step(monitor);

        expect("XRETC returns to the 0x3F page",
            emu.readRegister("PC").longValue() & 0x3fffffL, PAGED);
        expect("XRETC pops one word", emu.readRegister("SP").longValue() & 0xffffL, STACK);
    }

    /**
     * XBANZ tests and updates XAR[ARP] -- selected at runtime, so the constructor indexes the
     * register space (&XAR0 + ARP*4) rather than naming a register. With ARP=3 and XAR3=1 the
     * branch must be taken and XAR3 must post-increment; nothing else may move.
     */
    private void xbanzIndexesByArp(EmulatorHelper emu, AddressSpace sp) throws Exception {
        emu.writeMemoryValue(sp.getAddress(CODE_XBANZ * 2), 2, 0x560AL);           // XBANZ pma,*++
        emu.writeMemoryValue(sp.getAddress((CODE_XBANZ + 1) * 2), 2, PMA);
        emu.writeRegister("ARP", 3L);
        emu.writeRegister("XAR3", 1L);
        emu.writeRegister("XAR0", 0x1111L);
        emu.writeRegister("PC", CODE_XBANZ);
        emu.step(monitor);

        expect("XBANZ branches on XAR[ARP] != 0",
            emu.readRegister("PC").longValue() & 0x3fffffL, PAGED);
        expect("XBANZ post-increments XAR[ARP]",
            emu.readRegister("XAR3").longValue() & 0xffffffffL, 2L);
        expect("XBANZ leaves the other ARs alone",
            emu.readRegister("XAR0").longValue() & 0xffffffffL, 0x1111L);
    }

    private void expect(String what, long got, long want) {
        if (got == want) return;
        println(String.format("EmuC2xlpTest.java> FAIL: %s -- expected 0x%x, got 0x%x",
            what, want, got));
        failures++;
    }
}
