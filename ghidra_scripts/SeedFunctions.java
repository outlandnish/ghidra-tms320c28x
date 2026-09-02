// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
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
//       data, so they are the trustworthy signal. Gated by a BOUNDARY test (below), because
//       a byte scan also finds "calls" that are really two adjacent words of a numeric table.
//
//   BOUNDARY GATE (signal A only). A raw scan cannot tell a call from a coincidence, and the
//   entropy/vocabulary filter cannot either when the coincidence lives in a table of SMALL
//   numbers — low entropy, and high bytes in 0x00..0x03 are all legitimate opcode bytes, so
//   such a table scores as clean code. The phantom target that results is arbitrary and often
//   lands in the MIDDLE of a real instruction, where seeding it splits a healthy function and
//   leaves a stub that reads as a missing opcode. The offcut check in the creation loop cannot
//   help: it only rejects seeds inside an ALREADY-DECODED instruction, and at scan time nothing
//   is decoded — in particular the enclosing function may have a sub-threshold prologue and no
//   caller, so nothing seeds it first. So test the target directly, by BACKWARD LINEAR-SWEEP
//   RESYNCHRONIZATION: pseudo-disassemble from each of the preceding K words in turn and see
//   where each decode stream lands. Code is self-synchronizing, so a real entry is landed on
//   from nearly every back-off, while a mid-instruction address is STEPPED OVER by nearly all
//   of them. Read-only (PseudoDisassembler), so probing never lays down code. Measured over
//   2169 distinct targets in two application images: every real target drew at most 2
//   step-over votes and every mid-instruction target at least 7 — 36 phantoms rejected, 0 real
//   targets lost. Disable with -Dc28x.seed.noBoundaryGate.
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
//   (D) C-RUNTIME ENTRY (_c_int00) — recovers the one entry NO other signal can reach.
//       Per SPRU513Z (TMS320C28x Assembly Language Tools) §3.3.1: _c_int00 is the startup (boot)
//       routine; the name means it is *the interrupt handler for interrupt number 0, RESET*, and
//       the linker defines it as the program entry point (§3.3.2.3). §3.2 also notes the device
//       cannot read the entry-point field out of the object file, so it is encoded in the program
//       one of three ways — the bootloader's boot table branches to it, it is installed as the
//       RESET interrupt handler, or a hosted debugger sets PC to it. Every one of those means
//       nothing CALLS it, and on a partial dump the vector/boot table usually lives in a sector
//       the dump omits. It also opens with status/configuration-register setup rather than
//       callee-saved pushes, so signals A, B and C all miss it and the image ends up with no flow
//       anchor at all. That is not cosmetic: with no entry, Ghidra never disassembles the startup
//       path, so the .cinit/copy-table call chain and anything reached only from it stay
//       invisible, and emulation from the entry is impossible. (Observed on that application image,
//       whose swapped dump starts at 0x80800 and omits the 0x80000 sector.)
//
//       §3.3.1 lists what the startup routine must do, IN THIS ORDER, and signal D's two tests
//       are just the first two of them:
//         1. set up status and configuration registers      <- the CORROBORATION below
//         2. set up the stack                               <- the ANCHOR below
//         3. process the .cinit table to autoinitialize globals (--rom_model)
//         4. call all global object constructors in .init_array (EABI) / .pinit (COFF)
//         5. call main
//         6. call exit when main returns
//
//       ANCHOR (responsibility 2): the word 0x28AD = `MOV @SP,#16bit`. Absolute stack-pointer
//       initialization is the one thing only a C-runtime entry does — compiled C moves SP with
//       ADDB/SUBB SP,#imm, never a literal load. Measured: 0x28AD occurs ONCE in each of two
//       ~86k/238k-word application images, and every occurrence in the corpus sits in a boot
//       sequence.
//
//       CORROBORATION (responsibility 1): within `crtWindow` words of the anchor, require at
//       least `crtMinModeOps` of the C28x configuration-register trio — SETC OBJMODE (0x561F) /
//       CLRC AMODE (0x5616) / SETC M0M1MAP (0x561A) — AND at least one LCR (responsibilities
//       3-6 are reached by call: __TI_auto_init, then main). This rejects a coincidental 0x28AD.
//
//       Note the ORDER is why the walk-back below is needed at all: configuration registers come
//       FIRST and the stack SECOND, so the true entry sits a few words BEFORE the anchor, at the
//       start of the status-register setup. On the application images in the corpus that is
//       `SETC INTM|DBGM ; MOV @AL,#0 ; MOV IER,@AL` — responsibility 1 — three words ahead of
//       the `MOV @SP,#16bit` anchor.
//
//       ENTRY WALK-BACK: the anchor is the stack init, which is NOT the first instruction —
//       the app entries in the corpus open `SETC INTM|DBGM ; MOV @AL,#0 ; MOV IER,@AL` three
//       words earlier, while the bootloader entries start at the anchor itself. So seeding the
//       anchor would repeat exactly the off-by-one section B warns about. Instead reuse the
//       backward linear-sweep resynchronization from the boundary gate: decode forward from
//       each of the preceding `crtBackoff` words, keep only the streams that land exactly on
//       the anchor, and in each take the last flow TERMINATOR (LRETR/LRET/IRET or any
//       no-fall-through op) before it — the entry is the instruction right after it, because
//       functions are laid out back-to-back. Streams vote; the majority wins. A back-off that
//       desyncs abstains rather than votes.
//
//       Measured over 5 F28377D images / 658k words — four application images spanning three
//       firmware generations, plus a bootloader: 8 anchors -> 7 recovered, 1 rejected by the gate
//       (a 0x28AD scoring 0/3 mode ops and no LCR). Every accepted entry drew a UNANIMOUS vote
//       (20-24 back-offs, one distinct candidate), and the one case with independent ground
//       truth resolved to exactly the hand-recovered address. The bootloader image yields 3
//       entries — it links several C-runtime units — so multiples are expected, not an error.
//       Disable with -Dc28x.seed.noCrtScan.
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
//   c28x.seed.noBoundaryGate       (bool, default false) disable the signal-A boundary gate
//   c28x.seed.boundaryBackoff      (int,  default 10)    words to resynchronize from
//   c28x.seed.boundaryVotes        (int,  default 4)     step-over votes needed to reject
//   c28x.seed.noCrtScan            (bool, default false) disable the signal-D _c_int00 scan
//   c28x.seed.crtWindow            (int,  default 24)    words after the anchor to corroborate in
//   c28x.seed.crtMinModeOps        (int,  default 2)     of the 3 boot mode-setup ops required
//   c28x.seed.crtBackoff           (int,  default 24)    words to resynchronize the entry from
//   c28x.seed.noCrtNames           (bool, default false) don't name the C-runtime skeleton /
//                                                        main / the .cinit + copy-table symbols
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

    // --- signal-A boundary gate state (see BOUNDARY GATE in the header) ---
    ghidra.app.util.PseudoDisassembler pdis;
    int boundaryBackoff = 10, boundaryVotes = 4;
    boolean noBoundaryGate = false;
    final Map<Long,Integer> pdLenCache = new HashMap<>();     // word addr -> length in WORDS (0 = undecodable)
    final Map<Long,Boolean> boundaryCache = new HashMap<>();  // word addr -> is an instruction boundary
    final Map<Long,Boolean> termCache = new HashMap<>();      // word addr -> ends a function body (signal D)

    // run_ghidra_script / the MCP bridge deliver -Dkey=value as getScriptArgs(), NOT as JVM system
    // properties, so every c28x.seed.* override below silently no-ops when the script is driven that
    // way — the documented knobs appear to work and quietly do nothing. Promote any -Dkey=value (or
    // bare -Dkey -> "true") script arg to a real property first.
    // Clear first: system properties are JVM-global and survive between script runs in one Ghidra
    // session, so a flag passed once would stay set for every later run in that session.
    void promoteDashDArgs() {
        for (String k : new ArrayList<>(System.getProperties().stringPropertyNames()))
            if (k.startsWith("c28x.seed.")) System.clearProperty(k);
        String[] args = getScriptArgs();
        if (args == null) return;
        for (String a : args) {
            if (a == null || !a.startsWith("-D")) continue;
            String kv = a.substring(2);
            int eq = kv.indexOf('=');
            if (eq > 0) System.setProperty(kv.substring(0, eq), kv.substring(eq + 1));
            else if (!kv.isEmpty()) System.setProperty(kv, "true");
        }
    }

    @Override
    public void run() throws Exception {
        promoteDashDArgs();
        int minRun = Integer.getInteger("c28x.seed.minPrologueRun", 2);
        boolean prologOnlyIfCalled = Boolean.getBoolean("c28x.seed.prologuesOnlyIfCalled");
        boolean includeLoneProlog  = Boolean.getBoolean("c28x.seed.includeLoneProlog");
        double maxEntropy   = Double.parseDouble(System.getProperty("c28x.seed.maxEntropy",  "7.0"));
        double minCodeFrac  = Double.parseDouble(System.getProperty("c28x.seed.minCodeFrac", "0.55"));
        int    window       = Integer.getInteger("c28x.seed.window", 24);
        boolean noDataFilter = Boolean.getBoolean("c28x.seed.noDataFilter");
        noBoundaryGate  = Boolean.getBoolean("c28x.seed.noBoundaryGate");
        boundaryBackoff = Integer.getInteger("c28x.seed.boundaryBackoff", 10);
        boundaryVotes   = Integer.getInteger("c28x.seed.boundaryVotes", 4);

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
        Set<Long> phantomOffcut = new TreeSet<>();           // targets refused by the boundary gate
        int phantomSites = 0;                                // sites whose target was refused
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
            // BOUNDARY GATE: refuse a target that sits INSIDE an instruction (see the header).
            // The site's reference is dropped with it -- a "call" to a mid-instruction address
            // is phantom by construction, and injecting the xref anyway would let a later
            // analysis pass re-create the very function this gate just refused to seed.
            if (!noBoundaryGate && !isInstructionBoundary(tgt)) {
                phantomOffcut.add(tgt); phantomSites++;
                continue;
            }
            calledTargets.add(tgt);
            if (isCall) callSiteToTarget.put(base + wi, tgt);   // record CALL sites for ref-adding
        }

        // --- (B) prologue addresses (with run length) ---------------------------
        Map<Long,Integer> prologRun = new HashMap<>();
        for (long wi = 0; wi < nwords; wi++) {
            int run = prologueRun(wi);
            if (run > 0) prologRun.put(base + wi, run);
        }

        // Seed only the START of a prologue run. prologueRun() counts consecutive pushes
        // from wherever it is asked, so EVERY address inside a run scores > 0: a 3-push
        // prologue scores 3, 2, 1 on successive words. With the default minRun of 2 that
        // admits both the true entry and the word after it, and which of the two ends up
        // owning the body is arbitrary. When the interior one wins, every caller -- which
        // of course targets the true entry -- has its xref land outside that function, and
        // a perfectly ordinary function reads as permanently orphaned. (Seen on an
        // F28377D application image: the true entry got a 1-word stub while the word after
        // it took the whole 306-word body, and that function's one caller stayed invisible
        // until the boundary was corrected.)
        //
        // The offcut guard in the creation loop cannot catch this: it rejects seeds that
        // fall inside a decoded INSTRUCTION, and every word of a push run is its own
        // 1-word instruction, so each looks like a legitimate boundary.
        //
        // A call target is direct evidence of an entry, so it is never suppressed here.
        // Compare against a snapshot: removing a+1 must not change the verdict for a+2.
        Map<Long,Integer> runSnapshot = new HashMap<>(prologRun);
        int interiorDropped = 0;
        for (java.util.Iterator<Long> it = prologRun.keySet().iterator(); it.hasNext(); ) {
            long a = it.next();
            Integer prev = runSnapshot.get(a - 1);
            if (prev != null && prev > runSnapshot.get(a) && !calledTargets.contains(a)) {
                it.remove();
                interiorDropped++;
            }
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

        // --- (D) C-runtime entry (_c_int00) -------------------------------------------------
        // The reset entry is unreachable by A/B/C: nothing calls it, and it opens with mode-setup
        // ops instead of pushes. Anchor on `MOV @SP,#16bit` (0x28AD), corroborate with the boot
        // mode-setup trio + an LCR into the C runtime, then walk back to the true first
        // instruction. See section (D) in the header for the measurements behind each gate.
        int crtSeeded = 0, crtRejected = 0;
        if (!Boolean.getBoolean("c28x.seed.noCrtScan")) {
            int crtWindow     = Integer.getInteger("c28x.seed.crtWindow", 24);
            int crtMinModeOps = Integer.getInteger("c28x.seed.crtMinModeOps", 2);
            int crtBackoff    = Integer.getInteger("c28x.seed.crtBackoff", 24);
            if (pdis == null) pdis = new ghidra.app.util.PseudoDisassembler(currentProgram);

            java.util.TreeSet<Long> crtEntries = new java.util.TreeSet<>();
            for (long wi = 0; wi < nwords; wi++) {
                if (wordAt(wi * 2) != 0x28AD) continue;            // MOV @SP,#16bit
                long anchor = base + wi;
                // DISTINCT ops, not occurrences: CLRC AMODE alone appears 7-8 times in a typical
                // image, so counting repeats would let one op standing in for the trio pass.
                int seen = 0; boolean lcr = false;
                for (long k = anchor; k < anchor + crtWindow && k <= hi; k++) {
                    int w = wordAt((k - base) * 2);
                    if (w < 0) break;
                    if (w == 0x561F) seen |= 1;                                    // SETC OBJMODE
                    else if (w == 0x5616) seen |= 2;                               // CLRC AMODE
                    else if (w == 0x561A) seen |= 4;                               // SETC M0M1MAP
                    if (((w >> 8) & 0xff) == 0x76 && ((w >> 6) & 0x3) == 0x1) lcr = true;   // LCR
                }
                int modeOps = Integer.bitCount(seen);
                if (modeOps < crtMinModeOps || !lcr) {
                    println(String.format("  CRT anchor @%05x rejected (mode ops %d/3, LCR %s)",
                        anchor, modeOps, lcr ? "yes" : "no"));
                    crtRejected++;
                    continue;
                }
                crtEntries.add(crtEntryOf(anchor, crtBackoff));
            }

            // One entry -> it is THE C-runtime entry. Several -> the image links several runtime
            // units (a bootloader region holding more than one linked program does this), and
            // nothing in the bytes says which is "the" one, so each is named by its address
            // rather than silently promoting one of them.
            boolean single = crtEntries.size() == 1;
            for (long w : crtEntries) {
                Address a = addr(w);
                var fmgr2 = currentProgram.getFunctionManager();
                Function f = fmgr2.getFunctionAt(a);
                Function covering = fmgr2.getFunctionContaining(a);
                if (f == null && covering != null) {
                    // Something already owns these bytes from a different start. Re-cutting it
                    // here would split a function analysis already bound; report and leave it.
                    println(String.format("  CRT entry @%05x lies inside %s -- left alone", w, covering.getName()));
                    continue;
                }
                if (f == null) {
                    if (currentProgram.getListing().getInstructionAt(a) == null)
                        new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                    new CreateFunctionCmd(a).applyTo(currentProgram, monitor);
                    f = fmgr2.getFunctionAt(a);
                    if (f == null) { println(String.format("  CRT entry @%05x FAILED to bind", w)); continue; }
                    created++; createdEntries.add(w);
                }
                String nm = single ? "_c_int00" : String.format("_c_int00_%05x", w);
                // never rename over a name the operator chose
                if (f.getSymbol() == null
                        || f.getSymbol().getSource() == ghidra.program.model.symbol.SourceType.DEFAULT) {
                    try { f.setName(nm, ghidra.program.model.symbol.SourceType.ANALYSIS); }
                    catch (Exception e) { println("  CRT rename failed @" + Long.toHexString(w) + ": " + e); }
                }
                // Mark it an entry point: this is the flow anchor the image was missing, and it
                // is what lets later analysis (and emulation) start from the real reset path.
                currentProgram.getSymbolTable().addExternalEntryPoint(a);
                if (getPlateComment(a) == null)
                    setPlateComment(a, "C-runtime startup routine (SeedFunctions signal D): recovered "
                        + "from the MOV @SP,#16bit stack init + configuration-register idiom.\n"
                        + "_c_int00 is the handler for interrupt 0 (RESET) and the linker's program "
                        + "entry point, so nothing calls it -- it is reached by the boot table, the "
                        + "RESET vector, or a debugger setting PC (SPRU513Z 3.2/3.3.1).\n"
                        + "Order per SPRU513Z 3.3.1: (1) status/config registers, (2) stack, "
                        + "(3) .cinit autoinit of globals, (4) global ctors in .init_array (EABI) or "
                        + ".pinit (COFF), (5) main, (6) exit.");
                println(String.format("  CRT entry @%05x -> %s", w, f.getName()));
                crtSeeded++;
                if (!Boolean.getBoolean("c28x.seed.noCrtNames")) nameCRuntime(w);
            }
            if (crtEntries.size() > 1)
                println("  NOTE: " + crtEntries.size() + " C-runtime entries -- this image links "
                    + "several runtime units; none was promoted to the bare _c_int00 name.");
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
        println(String.format("C-runtime entry (signal D): %d recovered, %d anchors rejected", crtSeeded, crtRejected));
        println(String.format("call/branch targets in-image: %d", calledTargets.size()));
        if (!noBoundaryGate) {
            println(String.format("boundary gate: refused %d phantom targets landing mid-instruction "
                + "(from %d call/branch sites; backoff=%d, votes>=%d)",
                phantomOffcut.size(), phantomSites, boundaryBackoff, boundaryVotes));
            int shown = 0;
            for (long t : phantomOffcut) {
                if (shown++ >= 20) { println(String.format("  ... and %d more", phantomOffcut.size() - 20)); break; }
                println(String.format("  phantom call target @%05x (offcut)", t));
            }
        }
        println(String.format("prologue addresses (run-starts): %d  (dropped %d interior "
            + "run addresses -- see the off-by-one note at section B)", prologRun.size(), interiorDropped));
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

    // --- Signal D follow-on: name the TI C-runtime skeleton laid out around _c_int00 ----------
    // Once the entry is known, the rest of the startup skeleton falls out of its SHAPE, and with
    // it `main` -- which roots the whole application call graph and is otherwise just another
    // FUN_xxx. The layout below was identical in all three application images checked, spanning
    // three firmware generations, which is unsurprising: it is TI's stock boot28.asm/args_main.c,
    // emitted once per link.
    //
    //   _c_int00:
    //     <mode setup>
    //     LCR  _system_pre_init      \ first call, then CMPB AL,#0 / SB join,EQ:
    //     CMPB AL,#0                 / a zero return skips C init but still runs main
    //     SB   join,EQ
    //     ... guarded weak calls, then the INLINED .cinit walk:
    //     MOV  @AL,#lo / MOV @AH,#hi ; MOVL XAR7,#(hi:lo)   <- __TI_CINIT_Base
    //     ... PREAD copy loop ...
    //     MOVL XAR4,#tableptr ; LCR walker                  <- copy-table init (see below)
    //     MOV  @AL,#lo / MOV @AH,#hi ; LCR (hi:lo)          <- __TI_auto_init
    //   join:
    //     LCR  _args_main            <- and _args_main's one call is main()
    //     LCR  exit
    //
    // TWO rules do the real work, and both are self-checking rather than positional:
    //
    //   * __TI_auto_init is the guarded call whose materialized 32-bit CONSTANT EQUALS ITS OWN
    //     TARGET. The startup code loads a weak symbol's address, tests it against 0/-1 and calls
    //     it only if present, so const == target identifies it exactly. This matters because
    //     _c_int00 contains SEVERAL such guarded calls -- in every image checked there is another
    //     one whose constant is 0x00001 (a flag, not an address), and a purely positional "the
    //     Nth call" rule would name that one instead.
    //   * The COPY-TABLE pointer is the `MOVL XARn,#imm22` that is FOLLOWED by a call; the
    //     .cinit base is the one that is NOT (it feeds the inlined PREAD loop). In all three
    //     images the copy-table pointer was 0x3fffff -- the linker's "absent" sentinel -- which
    //     is itself worth reporting: it means the image has no copy table and any table a
    //     structural scan turns up is not the one startup uses.
    //
    // Everything here is additive and never renames a symbol the operator set.
    void nameCRuntime(long entryWord) {
        java.util.ArrayList<ghidra.program.model.listing.Instruction> ins = crtWalk(entryWord, 200);
        long preInit = -1, join = -1, argsMain = -1, exitFn = -1, autoInit = -1;
        long cinitBase = -1, ctPtr = -1, ctWalker = -1;
        long lastAl = -1, lastAh = -1;
        for (int k = 0; k < ins.size(); k++) {
            ghidra.program.model.listing.Instruction i = ins.get(k);
            String m = i.getMnemonicString();
            if (m.equals("MOV")) {
                // Only the 2-word `MOV loc16,#16bit` form renders a separate loc operand; the
                // 1-word short form bakes it in and is not an address materialization anyway.
                long s = firstScalar(i);
                String o0 = i.getNumOperands() > 1 ? i.getDefaultOperandRepresentation(0) : null;
                if (s >= 0 && o0 != null) {
                    if (o0.equals("@AL")) lastAl = s;
                    else if (o0.equals("@AH")) lastAh = s;
                }
            } else if (m.equals("MOVL")) {
                long sv = firstScalar(i);
                if (sv >= 0) {
                    long v = sv;
                    long callAfter = -1;
                    for (int j = k + 1; j < Math.min(k + 3, ins.size()); j++)
                        if (ins.get(j).getMnemonicString().equals("LCR")) { callAfter = flowWord(ins.get(j)); break; }
                    if (callAfter >= 0) { ctPtr = v; ctWalker = callAfter; }   // copy-table init call
                    else if (v >= lo && v <= hi) cinitBase = v;                // feeds the PREAD loop
                }
            } else if (m.equals("LCR")) {
                long t = flowWord(i);
                if (t < 0) continue;
                if (join >= 0 && i.getAddress().getOffset() / 2 == join) {
                    argsMain = t;
                    if (k + 1 < ins.size() && ins.get(k + 1).getMnemonicString().equals("LCR"))
                        exitFn = flowWord(ins.get(k + 1));
                    break;                                     // past this is the next function
                }
                if (preInit < 0 && k + 2 < ins.size()
                        && ins.get(k + 1).getMnemonicString().equals("CMPB")
                        && ins.get(k + 2).getMnemonicString().equals("SB")) {
                    preInit = t;
                    join = flowWord(ins.get(k + 2));
                } else if (lastAl >= 0 && lastAh >= 0 && (((lastAh << 16) | lastAl) == t)) {
                    autoInit = t;                              // const == target => the weak call
                }
            }
        }

        // main() is _args_main's only call: it tests the 0xffffffff "no args" sentinel, sets
        // argc/argv, then tail-calls main. If the shape isn't a single call, say nothing.
        long mainFn = -1;
        if (argsMain >= lo && argsMain <= hi) {
            long only = -1; int n = 0;
            for (ghidra.program.model.listing.Instruction i : crtWalk(argsMain, 40))
                if (i.getMnemonicString().equals("LCR")) { only = flowWord(i); n++; }
            if (n == 1) mainFn = only;
        }

        nameCrtFn(preInit,  "_system_pre_init", "TI C-runtime: returns non-zero to allow C initialization.");
        nameCrtFn(autoInit, "__TI_auto_init",   "TI C-runtime autoinitialization (SPRU513Z 3.3.1 steps 3-4): processes the .cinit table to autoinitialize globals (--rom_model / EABI ROM model, tables located by __TI_CINIT_Base) and runs the global object constructors in .init_array (EABI) or .pinit (COFF). Weak-guarded call from _c_int00 -- its address is materialized and null-tested at the call site.");
        nameCrtFn(argsMain, "_args_main",       "TI C-runtime: sets up argc/argv from the linker args block, then calls main.");
        nameCrtFn(mainFn,   "main",             "Application entry, reached as _c_int00 -> _args_main -> main.");
        nameCrtFn(exitFn,   "exit",             "TI C-runtime: called with main's return value.");
        nameCrtFn(ctWalker, "__TI_copy_table_init",
            "TI C-runtime: called from _c_int00 with the copy-table pointer in XAR4.");

        if (cinitBase >= lo && cinitBase <= hi) {
            crtLabel(cinitBase, "__TI_CINIT_Base");
            println(String.format("    __TI_CINIT_Base = %05x (inlined .cinit walk in _c_int00)", cinitBase));
        }
        if (ctPtr >= 0) {
            boolean absent = (ctPtr == 0x3fffff || ctPtr > hi || ctPtr < lo);
            if (!absent) {
                crtLabel(ctPtr, "__TI_COPY_TABLE");
                println(String.format("    __TI_COPY_TABLE = %05x (MaterializeCopyTable will use this)", ctPtr));
            } else {
                println(String.format("    copy-table pointer is ABSENT (0x%x = linker sentinel) -- this image "
                    + "initializes data through the inlined .cinit walk, not a copy table", ctPtr));
            }
        }
    }

    // Linear walk of the instructions at `startWord` (the startup code is laid out linearly, so
    // this deliberately sweeps ADDRESS order rather than following branches). Read-only.
    java.util.ArrayList<ghidra.program.model.listing.Instruction> crtWalk(long startWord, int cap) {
        java.util.ArrayList<ghidra.program.model.listing.Instruction> out = new java.util.ArrayList<>();
        long p = startWord;
        for (int n = 0; n < cap && p >= lo && p <= hi; n++) {
            ghidra.program.model.listing.Instruction i;
            try { i = pdis.disassemble(addr(p)); } catch (Exception e) { break; }
            if (i == null) break;
            out.add(i);
            String m = i.getMnemonicString();
            if (m.equals("LRETR") || m.equals("LRET") || m.equals("IRET")) break;
            p += i.getLength() / 2;
        }
        return out;
    }

    // First scalar operand of `i`, or -1. Scans EVERY operand rather than assuming an index:
    // constructors that bake the register into the display (`MOVL XAR7,#imm22`) expose a single
    // operand holding the immediate, while `MOV @AL,#imm16` exposes two with the immediate second.
    long firstScalar(ghidra.program.model.listing.Instruction i) {
        for (int k = 0; k < i.getNumOperands(); k++) {
            ghidra.program.model.scalar.Scalar s = i.getScalar(k);
            if (s != null) return s.getUnsignedValue();
        }
        return -1;
    }

    // First flow target of `i` as a WORD address, or -1.
    long flowWord(ghidra.program.model.listing.Instruction i) {
        Address[] f = i.getFlows();
        if (f == null || f.length == 0) return -1;
        return f[0].getOffset() / 2;
    }

    // Bind + name one C-runtime function, creating it if the seed scan missed it. Additive:
    // a name the operator set is reported and kept, never overwritten.
    void nameCrtFn(long word, String name, String why) {
        if (word < lo || word > hi) return;
        Address a = addr(word);
        var fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionAt(a);
        if (f == null) {
            if (fm.getFunctionContaining(a) != null) return;      // owned from elsewhere; leave it
            if (currentProgram.getListing().getInstructionAt(a) == null)
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
            new CreateFunctionCmd(a).applyTo(currentProgram, monitor);
            f = fm.getFunctionAt(a);
            if (f == null) return;
        }
        if (f.getSymbol() != null
                && f.getSymbol().getSource() != ghidra.program.model.symbol.SourceType.DEFAULT) {
            println(String.format("    %-22s @%05x -- already named %s, kept", name, word, f.getName()));
            return;
        }
        try {
            f.setName(name, ghidra.program.model.symbol.SourceType.ANALYSIS);
            if (getPlateComment(a) == null) setPlateComment(a, why);
            println(String.format("    %-22s @%05x", name, word));
        } catch (Exception e) {
            println("    naming " + name + " @" + Long.toHexString(word) + " failed: " + e);
        }
    }

    // Label a startup DATA table, unless something is already labeled there.
    void crtLabel(long word, String name) {
        Address a = addr(word);
        try {
            for (var s : currentProgram.getSymbolTable().getSymbols(a))
                if (s.getSource() != ghidra.program.model.symbol.SourceType.DEFAULT) return;
            currentProgram.getSymbolTable().createLabel(a, name,
                ghidra.program.model.symbol.SourceType.ANALYSIS);
        } catch (Exception e) { println("    label " + name + " failed: " + e); }
    }

    // --- Signal D: walk an anchor back to the first instruction of the C-runtime entry --------
    // The anchor (MOV @SP,#16bit) sits a few instructions INTO _c_int00, so it cannot be seeded
    // directly -- that is the same off-by-one section B documents, and here it would also point
    // the program's entry point at the middle of a function.
    //
    // Backward linear-sweep resynchronization, as in the boundary gate: decode forward from each
    // of the preceding `backoff` words and keep only the streams that land EXACTLY on the anchor
    // (a stream that steps over it was misaligned, so it abstains). Within each surviving stream,
    // the entry is the instruction following the last flow TERMINATOR before the anchor: functions
    // are emitted back-to-back, so the word after the previous function's LRETR is this one's
    // first instruction. Streams vote and the majority wins; measured over the corpus in the
    // header, every real entry was unanimous across 20-24 back-offs. Falls back to the anchor
    // itself when no terminator is in range -- never guesses EARLIER than it can show.
    long crtEntryOf(long anchorWord, int backoff) {
        Map<Long,Integer> votes = new HashMap<>();
        for (int k = 1; k <= backoff; k++) {
            long s = anchorWord - k;
            if (s < lo) break;
            java.util.ArrayList<Long> bounds = new java.util.ArrayList<>();
            long p = s;
            boolean ok = true;
            while (p < anchorWord) {
                int len = pdWordLen(p);
                if (len <= 0) { ok = false; break; }     // undecodable -> abstain
                bounds.add(p);
                p += len;
            }
            if (!ok || p != anchorWord) continue;        // stepped over the anchor -> abstain
            for (int i = bounds.size() - 1; i >= 0; i--) {
                long b = bounds.get(i);
                if (isFlowTerminator(b)) { votes.merge(b + pdWordLen(b), 1, Integer::sum); break; }
            }
        }
        long best = anchorWord;
        int bestVotes = 0;
        for (Map.Entry<Long,Integer> e : votes.entrySet())
            if (e.getValue() > bestVotes) { bestVotes = e.getValue(); best = e.getKey(); }
        return best;
    }

    // Does the instruction at `word` END a function body? A return, or anything with no
    // fall-through (an unconditional branch). Read-only (PseudoDisassembler) and cached, like
    // pdWordLen -- the vote above revisits the same addresses from many back-offs.
    boolean isFlowTerminator(long word) {
        Boolean c = termCache.get(word);
        if (c != null) return c;
        boolean t = false;
        try {
            ghidra.program.model.listing.Instruction ins = pdis.disassemble(addr(word));
            if (ins != null) {
                String m = ins.getMnemonicString();
                t = m.equals("LRETR") || m.equals("LRET") || m.equals("IRET")
                    || ins.getFallThrough() == null;
            }
        } catch (Exception e) { t = false; }
        termCache.put(word, t);
        return t;
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

    // --- Signal A gate: is `tgtWord` at a real INSTRUCTION BOUNDARY? -------------------------
    // Backward linear-sweep resynchronization. Decode forward from each of the preceding
    // `boundaryBackoff` words; each run either LANDS exactly on the target (so the target is a
    // boundary) or STEPS OVER it (so the target is inside an instruction). Code is
    // self-synchronizing, which is what makes this work: real entries are landed on from nearly
    // every back-off, mid-instruction addresses are stepped over by nearly all of them, and the
    // two populations do not overlap in practice. An undecodable back-off abstains rather than
    // votes, so a target preceded by data keeps the benefit of the doubt. Read-only:
    // PseudoDisassembler works off the bytes, so this is safe to run before any disassembly.
    boolean isInstructionBoundary(long tgtWord) {
        Boolean memo = boundaryCache.get(tgtWord);
        if (memo != null) return memo;
        if (pdis == null) pdis = new ghidra.app.util.PseudoDisassembler(currentProgram);
        int landed = 0, steppedOver = 0;
        for (int k = 1; k <= boundaryBackoff; k++) {
            long s = tgtWord - k;
            if (s < lo) break;
            long p = s;
            for (int step = 0; step <= boundaryBackoff; step++) {
                if (p == tgtWord) { landed++; break; }
                if (p > tgtWord)  { steppedOver++; break; }
                int len = pdWordLen(p);
                if (len <= 0) break;                        // undecodable -> abstain
                p += len;
            }
        }
        boolean ok = !(steppedOver >= boundaryVotes && steppedOver > landed);
        boundaryCache.put(tgtWord, ok);
        return ok;
    }

    // Length in WORDS of the instruction the bytes at `word` decode to, or 0 if undecodable.
    // Cached: the sweep above revisits the same addresses from many different back-offs.
    int pdWordLen(long word) {
        Integer c = pdLenCache.get(word);
        if (c != null) return c;
        int len = 0;
        try {
            ghidra.program.model.listing.Instruction ins = pdis.disassemble(addr(word));
            if (ins != null) len = ins.getLength() / 2;
        } catch (Exception e) { len = 0; }
        pdLenCache.put(word, len);
        return len;
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
