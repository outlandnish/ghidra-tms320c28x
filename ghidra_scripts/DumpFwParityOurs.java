// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Our-side per-region disassembly dump for the fw-parity BOOTSTRAP sweep.
//
// Input : regions manifest TSV via -Dc28x.parity.regions.in=<path>. Each line is
//         `<start_word_hex>\t<len_words_dec>` (extra columns ignored).
// Output: <region_start_hex>\t<word_addr_hex>\t<mnem+operands> lines, plus
//         <region_start_hex>\tEND\t<consumed_words> per region. Path from
//         -Dc28x.parity.regions.out=<path>.
//
// The whole point of batching every region into one headless run is startup cost.
// analyzeHeadless boots in ~10s; per-region imports were the original bottleneck
// in run_fw_parity. Here we import the raw firmware ONCE at the right base and
// walk each seeded region from that single program.
//
// The import must be flat at the firmware's actual base (pass -loader
// BinaryLoader -loader-block-base <base_bytes>) or every word address in
// regions.tsv falls outside memory and the sweep degrades to all-UNDEF.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class DumpFwParityOurs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String in  = getProp("c28x.parity.regions.in",  null);
        String out = getProp("c28x.parity.regions.out", null);
        if (in == null || out == null) {
            println("DumpFwParityOurs: set -Dc28x.parity.regions.in and -Dc28x.parity.regions.out");
            return;
        }

        List<long[]> regions = new ArrayList<>();  // [startWord, lenWords]
        try (BufferedReader br = new BufferedReader(new FileReader(in))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] cols = line.split("\t");
                if (cols.length < 2) continue;
                long sw = Long.parseLong(cols[0].replaceFirst("^0x", ""), 16);
                long lw = Long.parseLong(cols[1]);
                regions.add(new long[]{sw, lw});
            }
        }

        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();
        StringBuilder sb = new StringBuilder();
        int ok = 0, missMem = 0, undef = 0;

        for (long[] r : regions) {
            long startWord = r[0], lenWords = r[1];
            Address a   = ram.getAddress(startWord * 2);
            Address end = ram.getAddress((startWord + lenWords) * 2);
            if (!mem.contains(a)) {
                sb.append(String.format("%08x\tMISS_MEM\n", startWord));
                missMem++;
                continue;
            }
            long consumed = 0;
            while (a.compareTo(end) < 0) {
                if (getInstructionAt(a) == null) disassemble(a);
                Instruction ins = getInstructionAt(a);
                long w = a.getOffset() / 2;
                if (ins == null) {
                    sb.append(String.format("%08x\t%08x\t<UNDEF>\n", startWord, w));
                    a = a.add(2);
                    consumed += 1;
                    undef++;
                    continue;
                }
                // Clean the operand string: Ghidra prints operands separated by ", " already,
                // but multi-space or tab whitespace from odd operand renderers ruins the
                // simple `first-token = mnem` alignment the aggregator does. Collapse.
                String txt = ins.toString().replaceAll("\\s+", " ").trim();
                sb.append(String.format("%08x\t%08x\t%s\n", startWord, w, txt));
                int len = ins.getLength();
                a = a.add(len);
                consumed += len / 2;
                ok++;
            }
            sb.append(String.format("%08x\tEND\t%d\n", startWord, consumed));
        }

        try (FileWriter fw = new FileWriter(out)) { fw.write(sb.toString()); }
        println(String.format("DumpFwParityOurs: %d regions, %d insns, %d UNDEF, %d unmapped",
            regions.size(), ok, undef, missMem));
    }

    // JVM system property first, then -Dkey=value in script args (analyzeHeadless
    // does NOT hoist -D onto system properties on every Ghidra release, so read both).
    private String getProp(String key, String dflt) {
        String v = System.getProperty(key);
        if (v != null) return v;
        String[] args = getScriptArgs();
        if (args != null) {
            String pfx = "-D" + key + "=";
            for (String a : args) if (a != null && a.startsWith(pfx)) return a.substring(pfx.length());
        }
        return dflt;
    }
}
