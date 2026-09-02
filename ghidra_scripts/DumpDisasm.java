// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Headless test helper: disassemble the whole program linearly and print each
// instruction as "<wordaddr>\t<bytes>\t<mnemonic+operands>". Compared against
// tests/*.expected.txt by run_disasm_test.sh.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DumpDisasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Disassemble the block LINEARLY. A single disassemble(start) only follows flow, so the
        // first unconditional branch or return ends the sweep and every later fixture line comes
        // back missing -- which a fixture full of branches (c2xlp) is entirely made of. Walk the
        // block instead and seed disassembly at any address that is not already an instruction,
        // advancing by the decoded length so a 2-word instruction's operand word is never
        // mistaken for an opcode.
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address start = blk.getStart();
        Address end = blk.getEnd();
        for (Address a = start; a.compareTo(end) <= 0; ) {
            Instruction at = getInstructionAt(a);
            if (at == null) {
                disassemble(a);
                at = getInstructionAt(a);
            }
            // 2 bytes == 1 word on this wordsize=2 space; that is the fallback step when an
            // address will not decode at all, so one bad word cannot abort the whole sweep.
            a = a.add(at == null ? 2 : at.getLength());
        }

        Instruction insn = getInstructionAt(start);
        println("=== DISASM BEGIN ===");
        while (insn != null) {
            Address a = insn.getAddress();
            StringBuilder bytes = new StringBuilder();
            try {
                for (byte b : insn.getBytes()) bytes.append(String.format("%02x", b & 0xff));
            } catch (Exception e) { bytes.append("??"); }
            println(a.toString() + "\t" + bytes + "\t" + insn.toString());
            insn = insn.getNext();
        }
        println("=== DISASM END ===");
    }
}
