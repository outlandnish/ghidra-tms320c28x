// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Dump the analyzed program's function set as a TSV, for the fw-parity BOOTSTRAP
// reachability diff. Output rows:
//   <entry_word_hex>\t<len_words>\t<name>
//
// WHY. BFS from a data-side seed set discovers every function that dis2000 can
// reach through statically-visible CALL targets. Any function our analyzer
// created but that BFS did NOT visit is either (i) genuinely unreachable code
// (dead or reached only through indirect dispatch), (ii) a false seed, or
// (iii) a real bug in our control-flow modeling (a call site our decoder
// didn't recognize, so the target never joined the graph). The DIFF is what
// the orchestrator computes; this script just supplies the "what our analyzer
// found" half. Symmetric with what SeedFunctions + MarkComponentRegistry
// bring in, but with no coupling to either -- we walk the FunctionManager.
//
// Output path from -Dc28x.parity.functions.out=<path> (default `functions.tsv`
// in cwd).
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;

public class DumpFwParityFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String out = getProp("c28x.parity.functions.out", "functions.tsv");
        StringBuilder sb = new StringBuilder();
        sb.append("# entry_word\tlen_words\tname\n");
        int n = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f == null || f.getEntryPoint() == null) continue;
            long entryWord = f.getEntryPoint().getOffset() / 2;
            long bodyBytes = f.getBody() != null ? f.getBody().getNumAddresses() : 0;
            long lenWords  = bodyBytes / 2;
            sb.append(String.format("0x%x\t%d\t%s%n", entryWord, lenWords, f.getName()));
            n++;
        }
        try (FileWriter fw = new FileWriter(out)) { fw.write(sb.toString()); }
        println(String.format("DumpFwParityFunctions: %d function(s) -> %s", n, out));
    }

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
