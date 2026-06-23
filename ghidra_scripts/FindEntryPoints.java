// Find probable function entry points in a HEADERLESS C28x image.
//
// Headerless firmware (e.g. Tesla DIR/PMR/RAMAPP) has no flow anchor: a linear sweep
// from offset 0 lands in data and desyncs. This script recovers candidate entries
// from the bytes themselves, by two independent signals, and cross-scores them:
//
//   (A) CALL-TARGET back-refs (HIGH confidence). Every LCR #22bit / LC #22bit /
//       FFC XAR7,#22bit encodes an ABSOLUTE 22-bit target — that target is a real
//       function entry. We scan the whole image at each word, decode just these
//       opcodes, and collect targets that land inside the image.
//         LCR  word1 = 0111 0110 01CC CCCC (0x7640|hi6) ; word2 = lo16
//         LC   word1 = 0000 0000 10CC CCCC (0x0080|hi6) ; word2 = lo16
//         LB   word1 = 0000 0000 01CC CCCC (0x0040|hi6) ; word2 = lo16   (branch, not call,
//              but still a code target — tracked separately)
//         FFC  word1 = 0000 0000 11CC CCCC (0x00C0|hi6) ; word2 = lo16
//
//   (B) PROLOGUE byte patterns (MEDIUM confidence). C28x C-compiled functions open
//       with callee-saved pushes / frame setup:
//         MOVL *SP++, XARn   word = 0xBD00|? actually 0xB2BD..  -> low byte selects XARn
//              encodings seen: bd b2 (XAR1), bd aa (XAR2), bd a2 (XAR3) ... i.e.
//              word 0xB2BD/0xAABD/0xA2BD/... = "MOVL *SP++,XARn" (op_hi8 varies, lo8=0xBD)
//         ADDB SP,#N         word = 0xFE00|N (0x00..0x7F)  -> 0xFE-high-byte? lo8=0xFE...
//              actually ADDB SP,#7bit = 1111 1110 0CCC CCCC -> high byte 0xFE.
//         MOV32 *SP++,RnH    word 0xE203 ...
//       A run of one-or-more SP-push/alloc ops at an address is a strong entry hint.
//
// Output: ranked candidate list. A target hit by a CALL (A) AND showing a prologue (B)
// is highest confidence. Writes the full list to a file; prints a summary.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.util.*;

public class FindEntryPoints extends GhidraScript {
    long base;
    long lo, hi;          // inclusive word-address range of the image
    byte[] mem;           // raw image bytes

    int wordAt(long byteOff) {
        if (byteOff < 0 || byteOff + 1 >= mem.length) return -1;
        return (mem[(int)byteOff] & 0xff) | ((mem[(int)(byteOff+1)] & 0xff) << 8);
    }

    @Override
    public void run() throws Exception {
        MemoryBlock blk = currentProgram.getMemory().getBlocks()[0];
        Address start = blk.getStart(), end = blk.getEnd();
        base = start.getOffset() / 2;                 // word address of first word
        long nbytes = end.getOffset() - start.getOffset() + 1;
        mem = new byte[(int)nbytes];
        blk.getBytes(start, mem);
        long nwords = nbytes / 2;
        lo = base; hi = base + nwords - 1;

        // --- (A) collect call/branch targets -----------------------------------
        Map<Long,int[]> callHits = new HashMap<>();   // target -> {LCR,LC,FFC,LB counts}
        for (long wi = 0; wi < nwords - 1; wi++) {     // need a 2nd word
            int w1 = wordAt(wi*2);
            int hi8 = (w1 >> 8) & 0xff;
            int lo6 = w1 & 0x3f;
            int b76 = (w1 >> 6) & 0x3;
            int kind = -1;                              // 0 LCR,1 LC,2 FFC,3 LB
            if (hi8 == 0x76 && b76 == 0x1) kind = 0;            // LCR 0x76,01
            else if (hi8 == 0x00 && b76 == 0x2) kind = 1;       // LC  0x00,10
            else if (hi8 == 0x00 && b76 == 0x3) kind = 2;       // FFC 0x00,11
            else if (hi8 == 0x00 && b76 == 0x1) kind = 3;       // LB  0x00,01
            if (kind < 0) continue;
            int w2 = wordAt((wi+1)*2);
            if (w2 < 0) continue;
            long tgt = ((long)lo6 << 16) | (w2 & 0xffff);
            if (tgt < lo || tgt > hi) continue;          // target must be in-image
            callHits.computeIfAbsent(tgt, k -> new int[4])[kind]++;
        }

        // --- (B) prologue detection at each word --------------------------------
        // returns a small score for how "prologue-like" the words at wi look.
        Set<Long> prologueAddrs = new HashSet<>();
        for (long wi = 0; wi < nwords; wi++) {
            if (prologueScore(wi) > 0) prologueAddrs.add(base + wi);
        }

        // --- cross-score + rank -------------------------------------------------
        // candidate = any call target OR any prologue address.
        Set<Long> cands = new TreeSet<>();
        cands.addAll(callHits.keySet());
        cands.addAll(prologueAddrs);

        List<long[]> ranked = new ArrayList<>();        // {addr, score, callCount, hasProlog}
        for (long c : cands) {
            int[] ch = callHits.get(c);
            int callCount = ch == null ? 0 : ch[0] + ch[1] + ch[2];   // calls only (LCR/LC/FFC)
            int branchCount = ch == null ? 0 : ch[3];
            boolean prolog = prologueAddrs.contains(c);
            // score: a called target is strong; a called target WITH a prologue is strongest.
            int score = callCount * 10 + (prolog ? 5 : 0) + branchCount;
            ranked.add(new long[]{c, score, callCount, prolog ? 1 : 0, branchCount});
        }
        ranked.sort((a,b) -> Long.compare(b[1], a[1]));

        StringBuilder sb = new StringBuilder();
        long calledFns = callHits.values().stream().filter(v -> v[0]+v[1]+v[2] > 0).count();
        sb.append(String.format("image: base=0x%06x  words=%d  (0x%06x..0x%06x)\n", base, nwords, lo, hi));
        sb.append(String.format("call-targets in-image: %d distinct  | prologue addrs: %d\n",
            calledFns, prologueAddrs.size()));
        sb.append(String.format("total candidates: %d\n", ranked.size()));
        sb.append("rank  addr      score  calls  prolog  branches\n");
        int shown = 0;
        for (long[] r : ranked) {
            sb.append(String.format("  0x%06x  %5d  %4d   %s     %d\n",
                r[0], r[1], r[2], r[3]==1?"Y":".", r[4]));
            if (++shown >= 60) { sb.append("  ... (truncated; full list in file)\n"); break; }
        }
        String outPath = System.getProperty("c28x.entries.out",
            System.getProperty("java.io.tmpdir") + "/c28x_entries.txt");
        java.io.PrintWriter pw = new java.io.PrintWriter(outPath);
        pw.printf("# addr score calls prolog branches%n");
        for (long[] r : ranked) pw.printf("0x%06x %d %d %d %d%n", r[0], r[1], r[2], r[3], r[4]);
        pw.close();
        println(sb.toString());
        println("full ranked list -> " + outPath);
    }

    // Prologue heuristic: count consecutive SP-saving/frame ops starting at word wi.
    // MOVL *SP++,XARn : lo8 == 0xBD (op_hi8 is the XARn-specific store opcode; the
    //   distinguishing low byte is 0xBD). ADDB SP,#7bit : hi8 == 0xFE & bit7==0.
    //   MOV32 *SP++,RnH : w == 0xE203-ish (lo8==0x03 & hi8==0xE2).
    int prologueScore(long wi) {
        int n = 0;
        long p = wi;
        for (int k = 0; k < 8; k++) {                  // look at up to 8 words
            int w = wordAt(p*2);
            if (w < 0) break;
            int hi8 = (w >> 8) & 0xff, lo8 = w & 0xff;
            boolean isPush =
                (lo8 == 0xBD) ||                              // MOVL *SP++,XARn
                (hi8 == 0xFE && (lo8 & 0x80) == 0) ||         // ADDB SP,#7bit (alloc)
                (hi8 == 0xE2 && lo8 == 0x03);                 // MOV32 *SP++,RnH
            if (isPush) { n++; p += (hi8 == 0xE2 ? 2 : 1); }  // MOV32 form is 2 words
            else break;
        }
        // require at least one push AND the run to be plausibly a prologue (n>=1).
        return n;
    }
}
