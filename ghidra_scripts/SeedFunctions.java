// Seed functions in a HEADERLESS C28x firmware image.
//
// A raw firmware .bin imported into Ghidra has no symbols and no entry points, so the
// auto-analyzer finds almost nothing. This script recovers function entries from the bytes
// themselves and creates real Ghidra functions at them (disassemble + CreateFunctionCmd),
// so the decompiler has something to work on.
//
// TWO entry signals, then a general DATA filter to reject false seeds:
//
//   (A) CALL/BRANCH TARGETS — HIGH confidence. LCR/LC/FFC/LB encode an absolute 22-bit
//       target; anything called is, by definition, a real code entry. These never land in
//       data, so they are the trustworthy signal.
//
//   (B) PROLOGUE patterns — MEDIUM confidence. C-compiled functions open with callee-saved
//       pushes / frame setup (MOVL *SP++,XARn = lo8 0xBD; ADDB SP,#N = hi8 0xFE; MOV32
//       *SP++,RnH = 0xE203). A run of these is a likely entry.
//
//   (C) FN-PTR-TABLE targets — recovers PROLOGUE-LESS LEAF functions reached only via LCR *XARn
//       (register-indirect call through a const fn-ptr table). These have no prologue (B misses)
//       and no literal call word (A misses), but their entry address IS stored as a 2-word const
//       table entry (lo16, hi6). We scan for those entries and seed each target that is (a) not
//       yet a function, (b) a clean [entry..its-own-return] block, (c) looks-like-code.
//       NOTE: an earlier "seed the addr after every return" version was tested and REJECTED — it
//       over-fired into padding/alignment/LRETR-tails and created hundreds of junk 1-word funcs.
//       The fn-ptr-table scan is high-precision instead. (Found PCS411's 0xaa00..0xaa04 service
//       dispatch table — 7 leaf handlers, all missed by A+B.) Disable with -Dc28x.seed.noGapScan.
//
//   FALSE-SEED FILTER (general). The failure mode is a prologue/call-like byte pattern that
//   occurs by CHANCE inside a DATA table (strings, calibration/crypto blobs), producing a
//   bogus function that immediately hits halt_baddata. Real C28x code is LOW-entropy and
//   structured: a small opcode vocabulary, lots of repeated common words (0x..BD pushes,
//   0x76.. calls, 0x56.. prefixes), and addressing low-bytes. Data blobs are HIGH-entropy
//   (near-uniform byte distribution, few repeats). So before seeding any candidate we sample
//   a window after it and score "code-likeness": reject if the byte entropy is too high OR
//   too few words look like plausible opcodes. This catches data false-seeds regardless of
//   whether they happen to be call/prologue matches — it's the generalization of the
//   "zero-xrefs + ASCII string table" checks that found the earlier false seeds by hand.
//
// Properties (all optional, pass with -Dname=value to analyzeHeadless or set in a wrapper):
//   c28x.seed.minPrologueRun       (int,  default 2)     prologue run length to seed on B
//   c28x.seed.prologuesOnlyIfCalled(bool, default false) require prologue addrs to be called
//   c28x.seed.includeLoneProlog    (bool, default false) seed every 1-op prologue match (noisy)
//   c28x.seed.maxEntropy           (double,default 7.0)  reject window if byte entropy > this
//                                                        (0..8 bits/byte; ~7.0 ≈ random data)
//   c28x.seed.minCodeFrac          (double,default 0.55) reject if < this fraction of sampled
//                                                        words look like plausible opcodes
//   c28x.seed.window               (int,  default 24)    words to sample for the data filter
//   c28x.seed.noDataFilter         (bool, default false) disable the entropy/code-likeness gate
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import java.util.*;

public class SeedFunctions extends GhidraScript {
    long base, lo, hi;
    byte[] mem;
    boolean[] initialized;   // per-byte init flag; uninitialized bytes are not real words
    AddressSpace space;

    int wordAt(long byteOff) {
        if (byteOff < 0 || byteOff + 1 >= mem.length) return -1;
        if (initialized != null && (!initialized[(int)byteOff] || !initialized[(int)(byteOff+1)])) return -1;
        return (mem[(int)byteOff] & 0xff) | ((mem[(int)(byteOff+1)] & 0xff) << 8);
    }

    // word address -> Ghidra Address (API takes a BYTE offset = word * 2)
    Address addr(long word) { return space.getAddress(word * 2); }

    @Override
    public void run() throws Exception {
        int minRun = Integer.getInteger("c28x.seed.minPrologueRun", 2);
        boolean prologOnlyIfCalled = Boolean.getBoolean("c28x.seed.prologuesOnlyIfCalled");
        boolean includeLoneProlog  = Boolean.getBoolean("c28x.seed.includeLoneProlog");
        double maxEntropy   = Double.parseDouble(System.getProperty("c28x.seed.maxEntropy",  "7.0"));
        double minCodeFrac  = Double.parseDouble(System.getProperty("c28x.seed.minCodeFrac", "0.55"));
        int    window       = Integer.getInteger("c28x.seed.window", 24);
        boolean noDataFilter = Boolean.getBoolean("c28x.seed.noDataFilter");

        space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Pick the loaded firmware block: the LARGEST INITIALIZED block. (getBlocks()[0] is
        // unsafe — running SetupF28377D first adds uninitialized MMIO/RAM blocks, one of which
        // may sort first or be only partially initialized, so a wholesale getBytes() throws
        // "Attempted to read from uninitialized block".)
        ghidra.program.model.mem.Memory memory = currentProgram.getMemory();
        MemoryBlock blk = null;
        long bestLen = -1;
        for (MemoryBlock b : memory.getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; blk = b; }
        }
        if (blk == null) { println("ERROR: no initialized memory block found — import the raw image first."); return; }
        Address start = blk.getStart(), end = blk.getEnd();
        base = start.getOffset() / 2;
        long nbytes = end.getOffset() - start.getOffset() + 1;
        mem = new byte[(int)nbytes];
        // Read only the INITIALIZED sub-ranges of the chosen block; mark uninitialized gaps
        // with a sentinel so wordAt() reports "no word" there instead of throwing. (A block
        // can be partly initialized — e.g. an image smaller than the block it was mapped into.)
        java.util.Arrays.fill(mem, (byte) 0);
        initialized = new boolean[(int) nbytes];
        ghidra.program.model.address.AddressSetView initSet =
            memory.getLoadedAndInitializedAddressSet().intersect(
                currentProgram.getAddressFactory().getAddressSet(start, end));
        for (ghidra.program.model.address.AddressRange rng : initSet) {
            long rs = rng.getMinAddress().getOffset(), re = rng.getMaxAddress().getOffset();
            int off = (int) (rs - start.getOffset());
            int len = (int) (re - rs + 1);
            byte[] buf = new byte[len];
            memory.getBytes(rng.getMinAddress(), buf);
            System.arraycopy(buf, 0, mem, off, len);
            for (int i = off; i < off + len; i++) initialized[i] = true;
        }
        long nwords = nbytes / 2;
        lo = base; hi = base + nwords - 1;

        // --- (A) call/branch targets (absolute 22-bit) --------------------------
        // A CALL target (LCR/LC/FFC) is high-confidence real code — something calls it.
        // We also remember (callSite -> target) so we can add the reference to Ghidra's
        // xref DB: by scanning raw bytes we find the call before its site is disassembled,
        // so the call graph would otherwise stay invisible until late in analysis.
        Set<Long> calledTargets = new TreeSet<>();
        Map<Long,Long> callSiteToTarget = new HashMap<>();   // callSite word -> target word
        for (long wi = 0; wi < nwords - 1; wi++) {
            int w1 = wordAt(wi * 2);
            if (w1 < 0) continue;
            int hi8 = (w1 >> 8) & 0xff, lo6 = w1 & 0x3f, b76 = (w1 >> 6) & 0x3;
            boolean isCall =
                (hi8 == 0x76 && b76 == 0x1) ||   // LCR
                (hi8 == 0x00 && b76 == 0x2) ||   // LC
                (hi8 == 0x00 && b76 == 0x3);     // FFC
            boolean isBranch = (hi8 == 0x00 && b76 == 0x1);  // LB (target is code, not nec. an entry)
            if (!isCall && !isBranch) continue;
            int w2 = wordAt((wi + 1) * 2);
            if (w2 < 0) continue;
            long tgt = ((long)lo6 << 16) | (w2 & 0xffff);
            if (tgt < lo || tgt > hi) continue;
            // GATE THE CALL SITE, not just the target. This is a raw byte scan, so a word
            // pair inside a DATA table (or inside the immediate of a 2-word instruction)
            // can look exactly like LCR/LB + a plausible in-image address. Those invented
            // "calls" then (a) seed a bogus function at a data address -- which bypasses the
            // data filter below, because call targets are trusted -- and (b) inject a fake
            // UNCONDITIONAL_CALL xref that makes the junk look corroborated. Requiring the
            // SITE itself to look like code removes both at the source. (Observed on a real
            // F28377D image: 7 halt_baddata stubs seeded into the const-table region, four
            // of them carrying fake call xrefs from other data words.)
            if (!noDataFilter && !looksLikeCode(base + wi, window, maxEntropy, minCodeFrac)) continue;
            calledTargets.add(tgt);
            if (isCall) callSiteToTarget.put(base + wi, tgt);   // record CALL sites for ref-adding
        }

        // --- (B) prologue addresses (with run length) ---------------------------
        Map<Long,Integer> prologRun = new HashMap<>();
        for (long wi = 0; wi < nwords; wi++) {
            int run = prologueRun(wi);
            if (run > 0) prologRun.put(base + wi, run);
        }

        // --- decide the seed set ------------------------------------------------
        Set<Long> raw = new TreeSet<>();
        raw.addAll(calledTargets);                          // always consider call targets
        for (Map.Entry<Long,Integer> e : prologRun.entrySet()) {
            long a = e.getKey(); int run = e.getValue();
            if (prologOnlyIfCalled) {
                if (calledTargets.contains(a)) raw.add(a);
            } else if (includeLoneProlog) {
                raw.add(a);
            } else if (run >= minRun || calledTargets.contains(a)) {
                raw.add(a);                                 // default: solid run OR called
            }
        }

        // --- general DATA filter: reject high-entropy / non-code-like candidates ---
        // CALL targets bypass the filter — something calls them, so they are real code even
        // if they happen to start with table-like bytes. Only the weaker prologue-only
        // candidates are gated (those are where false-seeds-on-data come from).
        Set<Long> seeds = new TreeSet<>();
        int rejectedData = 0;
        for (long a : raw) {
            if (noDataFilter || calledTargets.contains(a)
                    || looksLikeCode(a, window, maxEntropy, minCodeFrac)) seeds.add(a);
            else rejectedData++;
        }

        // --- add call-site -> target references ---------------------------------
        // Make the byte-scanned call graph visible in Ghidra's xref DB (helps analysis and
        // distinguishes real call targets from data false-seeds in later sweeps).
        var refMgr = currentProgram.getReferenceManager();
        int refsAdded = 0;
        for (Map.Entry<Long,Long> e : callSiteToTarget.entrySet()) {
            Address from = addr(e.getKey()), to = addr(e.getValue());
            // only add if not already present (avoid duplicates on re-run)
            boolean exists = false;
            for (var r : refMgr.getReferencesFrom(from)) if (r.getToAddress().equals(to)) { exists = true; break; }
            if (!exists) {
                refMgr.addMemoryReference(from, to, ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL,
                                          ghidra.program.model.symbol.SourceType.USER_DEFINED, 0);
                refsAdded++;
            }
        }

        // --- create functions ---------------------------------------------------
        int created = 0, already = 0, failed = 0;
        java.util.TreeSet<Long> createdEntries = new java.util.TreeSet<>();
        int offcut = 0;
        for (long w : seeds) {
            Address a = addr(w);
            if (currentProgram.getFunctionManager().getFunctionAt(a) != null) { already++; continue; }
            // OFFCUT REJECT: `a` lies INSIDE an already-decoded instruction but is not its
            // start. That is a byte-scan artifact -- the raw scan happily matches the trailing
            // immediate word of a 2-word instruction (e.g. the 0x0016 of `MOV @TH,#0x16`) and
            // proposes it as an entry. Seeding there produces a 1-word stub that can never
            // decode, which then masquerades as a missing opcode. Real entries are always at
            // an instruction boundary.
            ghidra.program.model.listing.Instruction host =
                currentProgram.getListing().getInstructionContaining(a);
            if (host != null && !host.getAddress().equals(a)) { offcut++; continue; }
            if (currentProgram.getListing().getInstructionAt(a) == null) {
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd(a);
            cmd.applyTo(currentProgram, monitor);
            if (currentProgram.getFunctionManager().getFunctionAt(a) != null) { created++; createdEntries.add(w); }
            else failed++;
        }

        // --- (C) fn-ptr-table targets (prologue-less leaves via LCR *XARn) -------------------
        // Recovers leaf handlers dispatched through a CONST fn-ptr table (e.g. PCS411's
        // 0xaa00..0xaa04 service table). These have no prologue (B misses) and no literal call
        // word (A misses), but their entry address IS stored in a 2-word const table entry.
        // Scan for those entries; seed each target that is (a) not yet a function and (b) a
        // clean [entry..its-own-return] block that looks like code.
        //
        // WHY NOT "seed the address after every return": tested on PCS411, that over-fires
        // massively — inter-function padding/alignment and 1-2 word LRETR tails produce hundreds
        // of junk 1-word "functions" (xrefs=0). The fn-ptr-table scan is high-PRECISION: a 2-word
        // value that is a valid in-image code addr starting a return-bounded block is almost
        // certainly a real indirect-call target. (Disable with -Dc28x.seed.noGapScan.)
        int gapSeeded = 0, gapRejected = 0;
        if (!Boolean.getBoolean("c28x.seed.noGapScan")) {
            var fmgr = currentProgram.getFunctionManager();
            var listing = currentProgram.getListing();

            // CODE/DATA discrimination (critical guard) — CODE-DENSITY, not a global cutoff.
            // Const tables (fn-ptr tables, floats, calib blobs) hold 2-word values that LOOK like
            // pointers (small hi word) but are DATA; seeding into them disassembles data-as-code
            // and yields halt_baddata. A fixed "code ends at 0xN" boundary is NOT reliable — code
            // and data can interleave and the boundary differs per image. Instead, accept a target
            // only if its NEIGHBORHOOD is already densely covered by A+B-recognized functions: real
            // code sits among other code; data tables have ~0 function coverage. (Verified on
            // PCS411: real leaves score 0.50–1.00, every data-region false target scores 0.00.)
            // Tunables: -Dc28x.seed.minLeafWords (default 3), -Dc28x.seed.minDensity (default 0.25),
            // -Dc28x.seed.densityWin (default 64 words each side).
            //
            // FUTURE (if density alone proves insufficient on a harder image): the image also
            // contains explicit ADDRESS TABLES that mark the data region — e.g. PCS411 has a
            // 224-entry fn-ptr table at word 0x995a4 (right where code ends ~0x993a0), plus the
            // 0xa2xxx dispatch tables. A run of >=8 consecutive valid in-image address pairs is a
            // table => its span is data; exclude targets landing inside such spans. The image has
            // NO labeled "code-extent/data-extent" descriptor (that lived in the stripped BHX/linker
            // output; the sibling .hex is a different image — bootloader/RAM-app), so this
            // table-run heuristic is the closest in-image structural marker. Not needed yet:
            // code-density already cleanly separates (real leaves 0.5-1.0, data targets 0.0).
            int minLeafWords = Integer.getInteger("c28x.seed.minLeafWords", 3);
            double minDensity = Double.parseDouble(System.getProperty("c28x.seed.minDensity", "0.25"));
            int densWin       = Integer.getInteger("c28x.seed.densityWin", 64);

            // candidate targets from 2-word const entries: word[i]=lo16, word[i+1]=hi(0..0x3f).
            java.util.TreeSet<Long> tgts = new java.util.TreeSet<>();
            for (long wi = 0; wi < nwords - 1; wi++) {
                int loW = wordAt(wi * 2);
                int hi6w = wordAt((wi + 1) * 2);
                if (loW < 0 || hi6w < 0 || hi6w > 0x3f) continue;
                long tgt = ((long) hi6w << 16) | (loW & 0xffff);
                if (tgt < lo || tgt > hi) continue;        // in-image
                tgts.add(tgt);
            }
            for (long tWord : tgts) {
                Address a = addr(tWord);
                if (fmgr.getFunctionContaining(a) != null) continue;                              // already owned
                if (codeDensity(tWord, densWin) < minDensity) { gapRejected++; continue; }        // guard (0): in a code neighborhood, not a data table
                if (!tryDecodeToReturn(a, listing)) { gapRejected++; continue; }                  // guard (1): clean [entry..return]
                if (!looksLikeCode(tWord, window, maxEntropy, minCodeFrac)) { gapRejected++; continue; } // guard (2): not data
                if (listing.getInstructionAt(a) == null)
                    new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                CreateFunctionCmd cc = new CreateFunctionCmd(a);
                cc.applyTo(currentProgram, monitor);
                Function nf = fmgr.getFunctionAt(a);
                if (nf == null) { gapRejected++; continue; }
                // guard (3): reject tiny tails (1-2 word "functions" = padding/stranded LRETR)
                long sz = nf.getBody().getMaxAddress().getOffset() / 2 - tWord + 1;
                if (sz < minLeafWords) { new ghidra.app.cmd.function.DeleteFunctionCmd(a).applyTo(currentProgram); gapRejected++; continue; }
                gapSeeded++; created++; createdEntries.add(tWord);
            }
            println(String.format("gap-scan: minDensity=%.2f win=%d minLeafWords=%d", minDensity, densWin, minLeafWords));
        }

        // --- PRUNE: drop seeds that are immediately-truncating stubs sitting in DATA ------
        // A seeded function whose very first fall-through path runs into an undecodable word
        // is either (a) data misread as code, or (b) a genuine hole in the SLEIGH module.
        // Those two need OPPOSITE handling, and the discriminator is the neighbourhood: real
        // code sits among other recognized functions, const tables do not. So only prune when
        // code density is ~0; a truncating stub AMONG code is kept and reported, because that
        // is exactly the signal that finds a missing opcode (this is how MPY P,loc16,#16bit
        // was found -- do NOT let the prune hide that class).
        // Everything dropped is printed: no silent truncation of the seed set.
        int pruned = 0, keptGaps = 0;
        int pruneMaxWords = Integer.getInteger("c28x.seed.pruneMaxWords", 16);
        double pruneDensity = Double.parseDouble(System.getProperty("c28x.seed.pruneDensity", "0.25"));
        // own copy: the gap-scan's densWin is scoped to the (optional) gap-scan block
        int pruneWin = Integer.getInteger("c28x.seed.densityWin", 64);
        if (!Boolean.getBoolean("c28x.seed.noPrune")) {
            // Sweep ALL default-named (FUN_xxx) functions, not just this run's creations, so a
            // re-run also cleans junk left by an earlier pass. Anything the user has renamed is
            // never touched.
            java.util.ArrayList<Long> candidates = new java.util.ArrayList<>();
            for (Function f0 : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f0.getSymbol() == null
                    || f0.getSymbol().getSource() != ghidra.program.model.symbol.SourceType.DEFAULT) continue;
                candidates.add(f0.getEntryPoint().getOffset() / 2);
            }
            for (long w : candidates) {
                Address a = addr(w);
                Function f = currentProgram.getFunctionManager().getFunctionAt(a);
                if (f == null) continue;
                long sz = f.getBody().getMaxAddress().getOffset() / 2 - w + 1;
                if (sz > pruneMaxWords) continue;                 // big enough to be real
                if (!truncatesEarly(a, 32)) continue;             // decodes fine -> keep
                double dens = codeDensity(w, pruneWin);
                if (dens >= pruneDensity) {
                    println(String.format("  KEPT truncating stub @%05x (density %.2f) -- among real code: "
                        + "likely a MISSING OPCODE, investigate", w, dens));
                    keptGaps++;
                    continue;
                }
                new ghidra.app.cmd.function.DeleteFunctionCmd(a).applyTo(currentProgram);
                currentProgram.getListing().clearCodeUnits(a, f.getBody().getMaxAddress(), false);
                println(String.format("  pruned data false-seed @%05x (%d words, density %.2f)", w, sz, dens));
                pruned++;
            }
        }
        println(String.format("prune: removed %d data false-seeds, kept %d truncating stubs in code regions",
            pruned, keptGaps));

        println(String.format("image: base=0x%x  words=%d", base, nwords));
        println(String.format("gap-scan (signal C): seeded %d leaf functions, rejected %d", gapSeeded, gapRejected));
        println(String.format("call/branch targets in-image: %d", calledTargets.size()));
        println(String.format("prologue addresses (run>0): %d", prologRun.size()));
        println(String.format("candidates: %d  ->  rejected as data (entropy/non-code): %d  ->  seeds: %d",
            raw.size(), rejectedData, seeds.size()));
        println(String.format("created %d, already existed %d, failed %d, offcut-rejected %d ; call-site refs added %d",
            created, already, failed, offcut, refsAdded));
        if (!prologOnlyIfCalled && !includeLoneProlog)
            println("(default mode: call targets + prologue runs >= " + minRun +
                    " words, filtered by the data/entropy gate. Tune with -Dc28x.seed.* ;\n" +
                    " -Dc28x.seed.noDataFilter=true disables the gate; -Dc28x.seed.includeLoneProlog=true\n" +
                    " adds every 1-op prologue match. See the header for all properties.)");
    }

    // --- Signal C guard: does [entry .. ] disassemble cleanly through to its OWN return? -----
    // Walks instructions from `entry`, following fall-through, up to a cap. Returns true iff it
    // reaches a function-terminating return (LRETR/LRET/IRET) WITHOUT hitting a bad/halt
    // instruction or running off into another already-owned function. This is the guard that
    // separates real prologue-less leaves from split-artifact fragments (which run past their
    // own region and never terminate) and from mid-data garbage. Disassembles on demand so it
    // works even when the gap bytes were never reached by fall-through.
    boolean tryDecodeToReturn(Address entry, ghidra.program.model.listing.Listing listing) {
        Address a = entry;
        for (int i = 0; i < 200; i++) {                 // cap: real leaves here are < ~60 instrs
            ghidra.program.model.listing.Instruction ins = listing.getInstructionAt(a);
            if (ins == null) {
                // followFlow=TRUE. With false, only the fall-through path got disassembled,
                // so a conditional-branch target INSIDE the leaf (e.g. the `SB ret0,EQ` /
                // `ret0: MOVB AL,#0; LRETR` tail every compiler emits) was left as raw bytes.
                // CreateFunctionCmd then built a body that stops at the first LRETR and the
                // decompiler truncated on the un-disassembled arm -- a halt_baddata that
                // looked like a missing opcode but was really missing COVERAGE. (Observed on
                // a real F28377D image: 6 such arms across 5 signal-C leaves.)
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                ins = listing.getInstructionAt(a);
                if (ins == null) return false;          // undecodable / bad instruction
            }
            String m = ins.getMnemonicString();
            if (m.equals("LRETR") || m.equals("LRET") || m.equals("IRET")) return true;  // own return
            // if we wander into an already-owned function, this isn't a clean standalone leaf
            if (i > 0 && currentProgram.getFunctionManager().getFunctionAt(a) != null) return false;
            Address nxt = ins.getMaxAddress().add(1);
            if (nxt.getOffset() > hi * 2 + 1) return false;
            a = nxt;
        }
        return false;                                   // no return within cap → not a clean leaf
    }

    // --- Prune helper: does the fall-through path from `entry` hit an undecodable word fast? --
    // Walks fall-through ONLY, up to `cap` instructions, and returns true if it runs into an
    // address with no instruction that also refuses to decode -- i.e. exactly where the
    // decompiler would emit halt_baddata. Read-only: uses PseudoDisassembler, so probing a
    // candidate never lays down code (unlike tryDecodeToReturn, which is allowed to).
    boolean truncatesEarly(Address entry, int cap) {
        ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(currentProgram);
        ghidra.program.model.listing.Listing listing = currentProgram.getListing();
        Address a = entry;
        for (int i = 0; i < cap; i++) {
            ghidra.program.model.listing.Instruction ins = listing.getInstructionAt(a);
            if (ins == null) {
                try { return pd.disassemble(a) == null; } catch (Exception e) { return true; }
            }
            String m = ins.getMnemonicString();
            if (m.equals("LRETR") || m.equals("LRET") || m.equals("IRET")) return false;
            Address nxt = ins.getFallThrough();
            if (nxt == null) return false;                  // unconditional flow change, not a stub
            if (nxt.getOffset() > hi * 2 + 1) return false;
            a = nxt;
        }
        return false;
    }

    // --- Signal C guard (0): is `entryWord` in a CODE neighborhood (vs a data table)? --------
    // Fraction of a +/- `win`-word window already covered by an A+B-recognized function body.
    // Real code regions are densely covered (a leaf sits among other functions); const/data
    // tables have ~0 coverage. Per-region — no global code/data cutoff assumed (code & data can
    // interleave, and the boundary differs per image). This is what makes the fn-ptr-table scan
    // safe: a 2-word "pointer" that happens to point into a data blob lands in a 0-density region
    // and is rejected, while a real indirect-call target lands among code.
    double codeDensity(long entryWord, int win) {
        var fmgr = currentProgram.getFunctionManager();
        int inFn = 0, tot = 0;
        for (long p = entryWord - win; p <= entryWord + win; p++) {
            if (p < lo || p > hi) continue;
            tot++;
            if (fmgr.getFunctionContaining(addr(p)) != null) inFn++;
        }
        return tot > 0 ? (double) inFn / tot : 0.0;
    }

    // --- General data filter: does the window of words at `entry` look like CODE? ---------
    // Two cheap, independent signals, both pointing the same way for the data blobs that
    // produced false seeds (string tables, calibration/crypto data):
    //   (1) Byte entropy. Code reuses a small set of opcodes/operands → lower Shannon entropy.
    //       Near-random data → entropy approaches 8 bits/byte. Reject if entropy > maxEntropy.
    //   (2) Opcode plausibility. Fraction of sampled words whose high byte is a "known-ish"
    //       C28x opcode region (the common families). Real code clusters in these; random
    //       data scatters across all 256 high bytes. Reject if codeFrac < minCodeFrac.
    // A candidate must pass BOTH to be seeded. Conservative by design: it's better to drop a
    // few real entries (they'll still be reached by fall-through/branch once neighbors seed)
    // than to litter the program with halt_baddata stubs on data.
    boolean looksLikeCode(long entryWord, int window, double maxEntropy, double minCodeFrac) {
        long startByte = (entryWord - base) * 2;
        int[] freq = new int[256];
        int nbytesSampled = 0, nwordsSampled = 0, codeWords = 0;
        for (int i = 0; i < window; i++) {
            int w = wordAt(startByte + i * 2);
            if (w < 0) break;
            freq[w & 0xff]++; freq[(w >> 8) & 0xff]++;
            nbytesSampled += 2; nwordsSampled++;
            if (isPlausibleOpcodeHi((w >> 8) & 0xff)) codeWords++;
        }
        if (nwordsSampled < 6) return true;   // too little to judge — don't reject
        // (1) Shannon entropy of the byte distribution
        double ent = 0.0;
        for (int c : freq) if (c > 0) { double p = (double) c / nbytesSampled; ent -= p * (Math.log(p) / Math.log(2)); }
        if (ent > maxEntropy) return false;
        // (2) opcode-plausibility fraction
        double codeFrac = (double) codeWords / nwordsSampled;
        if (codeFrac < minCodeFrac) return false;
        return true;
    }

    // High-byte values that begin a common C28x instruction family. Not exhaustive (decode is
    // the real test) — just a fast "is this in the code vocabulary" check for the data filter.
    boolean isPlausibleOpcodeHi(int hi8) {
        // common families: MOVL/MOV/ADD/SUB loc-forms, branches, calls, 0x56/0xFF/0xE2 prefixes,
        // ALU AX-forms, MOVB/MOVZ, SP pushes, etc. Spans most of the real opcode map.
        switch (hi8) {
            case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
            case 0x06: case 0x07: case 0x08: case 0x09: case 0x0A: case 0x0B:
            case 0x0C: case 0x0D: case 0x0E: case 0x0F:
            case 0x10: case 0x11: case 0x12: case 0x13: case 0x1B: case 0x1D: case 0x1E:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x36: case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3F:
            case 0x40: case 0x4C:
            case 0x56: case 0x57:
            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
            case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0x72: case 0x74: case 0x76: case 0x77: case 0x78: case 0x79:
            case 0x81: case 0x89:
            case 0x92: case 0x93: case 0x94: case 0x9A:
            case 0xA0: case 0xA2: case 0xA8: case 0xAA: case 0xAE: case 0xAF:
            case 0xB2: case 0xB3: case 0xB6: case 0xB7: case 0xBD: case 0xBE: case 0xBF:
            case 0xC2: case 0xC3:
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
            case 0xE0: case 0xE2: case 0xE3: case 0xE5: case 0xE6: case 0xE7: case 0xE8:
            case 0xEC: case 0xED: case 0xEE: case 0xEF:
            case 0xF5: case 0xF6: case 0xF7: case 0xFE: case 0xFF:
                return true;
            default:
                return false;
        }
    }

    // Count consecutive SP-saving / frame-setup ops starting at word wi (the prologue run).
    int prologueRun(long wi) {
        int n = 0; long p = wi;
        for (int k = 0; k < 8; k++) {
            int w = wordAt(p * 2);
            if (w < 0) break;
            int hi8 = (w >> 8) & 0xff, lo8 = w & 0xff;
            boolean isPush =
                (lo8 == 0xBD) ||                          // MOVL *SP++,XARn
                (hi8 == 0xFE && (lo8 & 0x80) == 0) ||     // ADDB SP,#7bit (frame alloc)
                (hi8 == 0xE2 && lo8 == 0x03);             // MOV32 *SP++,RnH (2-word)
            if (isPush) { n++; p += (hi8 == 0xE2 ? 2 : 1); }
            else break;
        }
        return n;
    }
}
