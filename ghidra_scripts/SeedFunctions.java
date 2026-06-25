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
        Set<Long> calledTargets = new TreeSet<>();
        for (long wi = 0; wi < nwords - 1; wi++) {
            int w1 = wordAt(wi * 2);
            int hi8 = (w1 >> 8) & 0xff, lo6 = w1 & 0x3f, b76 = (w1 >> 6) & 0x3;
            boolean isCall =
                (hi8 == 0x76 && b76 == 0x1) ||   // LCR
                (hi8 == 0x00 && b76 == 0x2) ||   // LC
                (hi8 == 0x00 && b76 == 0x3) ||   // FFC
                (hi8 == 0x00 && b76 == 0x1);     // LB
            if (!isCall) continue;
            int w2 = wordAt((wi + 1) * 2);
            if (w2 < 0) continue;
            long tgt = ((long)lo6 << 16) | (w2 & 0xffff);
            if (tgt >= lo && tgt <= hi) calledTargets.add(tgt);
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
        Set<Long> seeds = new TreeSet<>();
        int rejectedData = 0;
        for (long a : raw) {
            if (noDataFilter || looksLikeCode(a, window, maxEntropy, minCodeFrac)) seeds.add(a);
            else rejectedData++;
        }

        // --- create functions ---------------------------------------------------
        int created = 0, already = 0, failed = 0;
        for (long w : seeds) {
            Address a = addr(w);
            if (currentProgram.getFunctionManager().getFunctionAt(a) != null) { already++; continue; }
            if (currentProgram.getListing().getInstructionAt(a) == null) {
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd(a);
            cmd.applyTo(currentProgram, monitor);
            if (currentProgram.getFunctionManager().getFunctionAt(a) != null) created++;
            else failed++;
        }

        println(String.format("image: base=0x%x  words=%d", base, nwords));
        println(String.format("call/branch targets in-image: %d", calledTargets.size()));
        println(String.format("prologue addresses (run>0): %d", prologRun.size()));
        println(String.format("candidates: %d  ->  rejected as data (entropy/non-code): %d  ->  seeds: %d",
            raw.size(), rejectedData, seeds.size()));
        println(String.format("created %d, already existed %d, failed %d", created, already, failed));
        if (!prologOnlyIfCalled && !includeLoneProlog)
            println("(default mode: call targets + prologue runs >= " + minRun +
                    " words, filtered by the data/entropy gate. Tune with -Dc28x.seed.* ;\n" +
                    " -Dc28x.seed.noDataFilter=true disables the gate; -Dc28x.seed.includeLoneProlog=true\n" +
                    " adds every 1-op prologue match. See the header for all properties.)");
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
