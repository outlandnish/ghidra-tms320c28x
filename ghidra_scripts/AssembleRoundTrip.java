// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Assembler regression for the immediates whose bits are SPLIT across both words
// of a two-word instruction: the 22-bit branch/call/pointer operand and the FPU
// #16FHi operand. Driven by tests/run_assembler_check.{sh,ps1}.
//
// WHY THIS EXISTS. A split operand is reassembled in a disassembly action, e.g.
//
//     [ xar22 = (loc_off6 << 16) | imm16; ]
//
// Ghidra's assembler works by INVERTING that expression to solve for the two
// fields given the operand the user typed. It can invert `|` over disjoint fields;
// it cannot invert `+`. The two are numerically identical here -- the fields do not
// overlap, so no carry can ever cross between them -- which is exactly what makes
// this dangerous: swapping `|` for `+` changes nothing about disassembly, emulation
// or the decompiler, and every other test in this repo keeps passing. The only
// symptom is that "Patch Instruction" and the WildcardAssembler stop being able to
// produce the instruction at all (AssemblySemanticException), on the 22-bit
// pointer loads that are the single most common way this target names a peripheral.
//
// Measured: breaking the join on ONE imm22 form and ONE FPU form costs 186 and 512
// cases here. Nothing else in tests/ moves.
//
// The upstream project hit this for real and fixed it in mwdmwd/ghidra-c28x
// d488358; our spec already used `|` throughout, so this test is what keeps it
// that way rather than a port of their change. See THIRD-PARTY.md.
//
// Three independent checks:
//   1. every form assembles to the encoding SPRU430F/SPRUEO2B specify, over a value
//      matrix that walks every operand bit, the word boundary and every high-field
//      combination, in both hex and decimal spelling;
//   2. an out-of-range operand is REJECTED, not silently truncated into a wrong
//      instruction;
//   3. round trip -- the text our own disassembler prints is text our own assembler
//      accepts, and reassembles to the identical bytes. Check 1 uses hand-written
//      operand syntax, so on its own it would not notice the listing drifting to a
//      rendering the assembler cannot parse.
//
// @category TMS320C28x
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

public class AssembleRoundTrip extends GhidraScript {

    // Operand template ("%s" is the literal) and the first opcode word.
    // SPRU430F: LB/LC/LCR 22bit, FFC XAR7,22bit, MOVL XARn,#22bit. Word 1 carries
    // operand bits 21:16 in its low six bits, word 2 carries bits 15:0.
    private static final String[][] IMM22 = {
        {"LB %s", "0040"}, {"LC %s", "0080"}, {"LCR %s", "7640"},
        {"FFC XAR7,%s", "00C0"},
        {"MOVL XAR0,#%s", "8D00"}, {"MOVL XAR1,#%s", "8D40"},
        {"MOVL XAR2,#%s", "8D80"}, {"MOVL XAR3,#%s", "8DC0"},
        {"MOVL XAR4,#%s", "8F00"}, {"MOVL XAR5,#%s", "8F40"},
        {"MOVL XAR6,#%s", "7680"}, {"MOVL XAR7,#%s", "76C0"},
    };

    // Mnemonic, first opcode word, and how many of the operand's low bits live in
    // word 2. SPRUEO2B: the LSW always holds the HIGH-order operand bits. The
    // 13-bit forms take one register operand, the 10-bit forms take two.
    private static final String[][] FPU = {
        {"MOVIZ", "E800", "13"}, {"MOVXI", "E808", "13"}, {"CMPF32", "E810", "13"},
        {"MAXF32", "E820", "13"}, {"MINF32", "E830", "13"},
        {"MPYF32", "E840", "10"}, {"ADDF32", "E880", "10"}, {"SUBF32", "E8C0", "10"},
    };

    // Somewhere clear of whatever stub the harness imported, for check 3's corpus.
    private static final long CORPUS_BASE = 0x40000L;

    private int pass;
    private int fail;
    private int rejected;
    private int accepted;
    private final List<String> failures = new ArrayList<>();

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);
        Address at = currentProgram.getMemory().getBlocks()[0].getStart();

        checkImm22(asm, at);
        int imm22Pass = pass;
        int imm22Fail = fail;
        int imm22Rejected = rejected;
        int imm22Accepted = accepted;
        println(String.format("IMM22 pass=%d fail=%d rejected=%d accepted_out_of_range=%d",
            imm22Pass, imm22Fail, imm22Rejected, imm22Accepted));

        pass = fail = rejected = accepted = 0;
        checkFpu(asm, at);
        println(String.format("FPU_IMM16 pass=%d fail=%d rejected=%d accepted_out_of_range=%d",
            pass, fail, rejected, accepted));

        // An accepted out-of-range operand is recorded as a failure too, so it is
        // already inside matrixFail -- `accepted` is the breakdown, not an addend.
        int matrixFail = imm22Fail + fail;
        int matrixAccepted = imm22Accepted + accepted;
        int matrixPass = imm22Pass + pass;
        int matrixRejected = imm22Rejected + rejected;

        pass = fail = 0;
        checkRoundTrip(asm);
        println(String.format("ROUNDTRIP pass=%d fail=%d", pass, fail));

        for (String f : failures) {
            println("  " + f);
        }
        if (matrixFail + fail == 0) {
            println(String.format(
                "ASSEMBLER PASS: %d encodings, %d out-of-range rejected, %d round-tripped",
                matrixPass, matrixRejected, pass));
        } else {
            println(String.format("ASSEMBLER FAIL: %d encoding (of which %d out-of-range "
                + "accepted), %d round-trip", matrixFail, matrixAccepted, fail));
        }
    }

    private void checkImm22(Assembler asm, Address at) {
        // Every operand bit, the word boundary, asymmetric halves, and every
        // high-six-bit combination: a join that drops or mis-shifts either half
        // cannot survive all of these.
        TreeSet<Long> values = new TreeSet<>();
        for (long v : new long[] {0, 0xFFFF, 0x10000, 0x10001, 0x123456, 0x2AAAAA,
                                  0x155555, 0x3FFFFF}) {
            values.add(v);
        }
        for (int bit = 0; bit < 22; bit++) {
            values.add(1L << bit);
        }
        for (int high = 0; high < 64; high++) {
            values.add(((long) high << 16) | 0xA55A);
        }

        for (String[] form : IMM22) {
            int opcode = Integer.parseInt(form[1], 16);
            for (long v : values) {
                String want = word(opcode | (int) (v >> 16)) + word((int) (v & 0xFFFF));
                check(asm, at, String.format(form[0], "0x" + Long.toHexString(v)), want);
                check(asm, at, String.format(form[0], Long.toString(v)), want);
            }
            // 22 bits is the whole operand; anything wider has no encoding.
            for (String bad : new String[] {"-1", "0x400000", "0x412345", "0xffffffff"}) {
                reject(asm, at, String.format(form[0], bad));
            }
        }
    }

    private void checkFpu(Assembler asm, Address at) {
        for (String[] form : FPU) {
            int opcode = Integer.parseInt(form[1], 16);
            int low = Integer.parseInt(form[2]);
            boolean threeOperand = low == 10;

            TreeSet<Long> values = new TreeSet<>();
            for (long v : new long[] {0, 0xFFFF, 0xA55A, 0x5AA5, 0x3F80, 0xBF80,
                                      (1L << low) - 1, 1L << low, (1L << low) + 1}) {
                values.add(v);
            }
            for (int bit = 0; bit < 16; bit++) {
                values.add(1L << bit);
            }
            for (int high = 0; high < (1 << (16 - low)); high++) {
                values.add(((long) high << low) | 0x155);
            }

            // Sweep the register selectors too: on the 10-bit forms they share word 2
            // with the immediate's low bits, so a bad shift lands on a register field.
            for (int dest = 0; dest < 8; dest++) {
                for (int src = 0; src < (threeOperand ? 8 : 1); src++) {
                    String template = form[0] + " R" + dest + "H,#%s"
                        + (threeOperand ? ",R" + src + "H" : "");
                    for (long v : values) {
                        int w2 = (int) ((v & ((1L << low) - 1)) << (16 - low))
                            | (src << 3) | dest;
                        String want = word(opcode | (int) (v >> low)) + word(w2);
                        check(asm, at, String.format(template, "0x" + Long.toHexString(v)),
                            want);
                        check(asm, at, String.format(template, Long.toString(v)), want);
                    }
                    for (String bad : new String[] {"-1", "0x10000", "0x1a55a"}) {
                        reject(asm, at, String.format(template, bad));
                    }
                }
            }
        }
    }

    // Build the same encodings as bytes, disassemble them with this module, and feed
    // the rendered text back to the assembler.
    private void checkRoundTrip(Assembler asm) throws Exception {
        List<Integer> words = new ArrayList<>();
        for (String[] form : IMM22) {
            int opcode = Integer.parseInt(form[1], 16);
            for (long v : new long[] {0x123456, 0x3FFFFF, 0x00FFFF, 0x010000}) {
                words.add(opcode | (int) (v >> 16));
                words.add((int) (v & 0xFFFF));
            }
        }
        for (String[] form : FPU) {
            int opcode = Integer.parseInt(form[1], 16);
            int low = Integer.parseInt(form[2]);
            int src = low == 10 ? 5 : 0;
            for (long v : new long[] {0x46A5, 0xFFFF}) {
                words.add(opcode | (int) (v >> low));
                words.add((int) ((v & ((1L << low) - 1)) << (16 - low)) | (src << 3) | 3);
            }
        }

        byte[] corpus = new byte[words.size() * 2];
        for (int i = 0; i < words.size(); i++) {
            corpus[i * 2] = (byte) (words.get(i) & 0xff);
            corpus[i * 2 + 1] = (byte) ((words.get(i) >> 8) & 0xff);
        }

        Memory memory = currentProgram.getMemory();
        Address base = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(CORPUS_BASE);
        memory.createInitializedBlock("asm_round_trip", base, corpus.length, (byte) 0,
            monitor, false);
        memory.setBytes(base, corpus);

        // Sweep LINEARLY. Half this corpus is unconditional branches to addresses that
        // do not exist here, so following flow would stop at the first one.
        Address end = base.add(corpus.length - 1);
        for (Address a = base; a.compareTo(end) <= 0; ) {
            Instruction at = getInstructionAt(a);
            if (at == null) {
                disassemble(a);
                at = getInstructionAt(a);
            }
            // 2 bytes == 1 word on this wordsize=2 space: the fallback step, so one
            // address that will not decode cannot abort the whole sweep.
            a = a.add(at == null ? 2 : at.getLength());
        }

        for (Address a = base; a.compareTo(end) <= 0; ) {
            Instruction insn = getInstructionAt(a);
            if (insn == null) {
                record("no disassembly at " + a);
                a = a.add(2);
                continue;
            }
            String text = insn.toString();
            String have = hex(insn.getBytes());
            try {
                String got = hex(asm.assembleLine(a, text));
                if (got.equals(have)) {
                    pass++;
                } else {
                    record("round trip [" + text + "] was " + have + " reassembled " + got);
                }
            } catch (Throwable t) {
                record("round trip [" + text + "] (" + have + ") threw "
                    + t.getClass().getSimpleName());
            }
            a = a.add(insn.getLength());
        }
    }

    // One 16-bit word, little-endian, matching Instruction.getBytes().
    private static String word(int w) {
        return String.format("%02x%02x", w & 0xff, (w >> 8) & 0xff);
    }

    private void check(Assembler asm, Address at, String line, String want) {
        try {
            String got = hex(asm.assembleLine(at, line));
            if (got.equals(want)) {
                pass++;
            } else {
                record("[" + line + "] want " + want + " got " + got);
            }
        } catch (Throwable t) {
            record("[" + line + "] want " + want + " threw " + t.getClass().getSimpleName());
        }
    }

    private void reject(Assembler asm, Address at, String line) {
        try {
            String got = hex(asm.assembleLine(at, line));
            accepted++;
            record("out-of-range operand accepted: [" + line + "] -> " + got);
        } catch (Throwable t) {
            rejected++;
        }
    }

    // Cap the detail: a systemic break produces hundreds of these and the count is
    // the signal, not the list.
    private void record(String message) {
        fail++;
        if (failures.size() < 20) {
            failures.add(message);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
