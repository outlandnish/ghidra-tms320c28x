// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Materialize copied-to-RAM sections (.ramfunc / .cinit / initialized data) in a C28x image.
//
// THE PROBLEM. On TI-RTS C28x images, time-critical code (`.ramfunc` — flash program/erase,
// motor-control inner loops) and initialized data (`.cinit`) live in FLASH at a LOAD address and
// are copied to RAM at a RUN address by the APPLICATION'S OWN C-runtime startup (not the
// bootloader). In a static flash-only dump the RAM run regions are uninitialized, so:
//   - an `LCR 0x9669`-into-RAM hits "Disassembly not permitted within uninitialized memory block"
//     and every RAM-resident function is INVISIBLE (no body, no decompilation);
//   - the ~148 flash callers of a ramfunc dangle at an empty address.
// Data xrefs into RAM already resolve (SetupF28377D maps the RAM blocks); the gap is RAM CODE.
// Copying the flash load-image into the RAM run region — "materializing" — closes it, and because
// the copy is done by the app's startup, the flash-only dump already contains everything needed.
//
// THE MECHANISM. A startup dispatcher (`copyInitSections`) calls a tight word memcpy
// (`memcpyWords(countWords, dst, src)`, a `*dst++ = *src++` loop) once per section with CONSTANT
// args: size (word count), dst = RAM run address, src = flash load address. The SAME memcpy is
// also used for ~19 runtime copies whose args are NOT constant — those are ignored here.
//
// DETECTION. A forward constant-propagation pass over every function tracks each register's last
// immediate value (invalidating a register the moment a non-immediate writes it, so a runtime copy
// whose pointer comes off the stack cannot masquerade as a section). At each call we snapshot the
// live constants and try to form a valid (size, run, load) triple:
//   - load  is a word in the FLASH image block and [load, load+size) is fully initialized;
//   - run   is a word mapped in a NON-image (RAM) block and [run, run+size) is fully mapped;
//   - size  is an explicit count const, OR is derived from a second flash const (load-end pointer).
// The callee that accumulates the most DISTINCT valid triples (>= minSites) is the copy routine;
// its triples are the sections. Override the routine with -Dc28x.mat.copyfn=0xWORD if detection
// picks wrong (e.g. a copy-table `__TI_auto_init` variant that this inline-const scan can't read).
//
// MATERIALIZE (per section, ADDITIVELY — never overwrites an existing symbol/function/typed data):
//   - convertToInitialized each RAM block the run region overlaps (fill 0), then setBytes the flash
//     load-image into it, SPLITTING the write at block boundaries (the .ramfunc run region straddles
//     the LS0-5 / D0-1 seam at word 0xB000);
//   - CODE section (run region has incoming CALL refs from flash) -> mark the block(s) executable,
//     then disassemble (flow restricted to the region) + CreateFunction at each CALL-target;
//   - DATA section (no incoming code refs) -> leave the placed bytes so globals show init values.
//
// POST-ANALYSIS FINALIZE. Two artifacts are fixed by the companion FinalizeRamfuncs.java, run AFTER
// analysis settles (both depend on background analysis, which a Swing-thread script cannot force):
//   - ~half the ramfuncs bind a 1-word body here because CreateFunction runs before analysis has
//     decoded every fall-through (the instructions land loose); a delete+recreate once decoded binds
//     the full body;
//   - Ghidra's "Non-Returning Functions - Discovered" analyzer flags many ramfuncs non-returning
//     (its call-site heuristic misfires on the still-uninitialized body), stamping a CALL_RETURN
//     override on every LCR to them that truncates the flash fall-through into `??` data — an
//     analyzer artifact, NOT a bug in the LCR/LRETR SLEIGH (those emit correct call/return p-code).
//
// Run AFTER SetupF28377D (maps RAM blocks) + SeedFunctions (disassembles flash so the calls into
// RAM exist as refs). Pipeline: Setup -> Seed -> MarkDataTables -> MaterializeSections -> RetypeWideMemory.
//
// Properties (-Dname=value):
//   c28x.mat.dryRun   (bool, default false) report the detected copy fn + sections; make no changes
//   c28x.mat.copyfn   (hex,  default auto)  force the copy-routine ENTRY (word addr, e.g. 0xb2070)
//   c28x.mat.minSites (int,  default 2)     min distinct valid triples for a callee to be the copy fn
//   c28x.mat.maxWords (int,  default 0x40000) reject a triple whose size exceeds this (sanity cap)
//   c28x.mat.disasm   (bool, default true)  disassemble + CreateFunction at call-targets in CODE sections
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.*;

public class MaterializeSections extends GhidraScript {
    long base, nwords;                 // flash image: base word address, word count
    byte[] mem;                        // flash image bytes, indexed by (word-base)*2
    boolean[] init;                    // per-byte init flag over the image block
    AddressSpace space;
    Memory memory;
    MemoryBlock imageBlk;              // the loaded flash image (largest initialized block)
    long maxWords, minRunWord;

    // word address -> Ghidra Address (the API takes a BYTE offset = word * 2; wordsize=2 space).
    Address addr(long word) { return space.getAddress(word * 2); }

    @Override
    public void run() throws Exception {
        boolean dryRun  = Boolean.getBoolean("c28x.mat.dryRun");
        int minSites    = Integer.getInteger("c28x.mat.minSites", 2);
        maxWords        = Integer.getInteger("c28x.mat.maxWords", 0x40000);
        minRunWord      = Integer.getInteger("c28x.mat.minRunWord", 0x800);   // exclude M0/M1 scratch
        boolean doDisasm = Boolean.parseBoolean(System.getProperty("c28x.mat.disasm", "true"));
        long copyfnOverride = -1;
        String cf = System.getProperty("c28x.mat.copyfn");
        if (cf != null) copyfnOverride = Long.decode(cf.trim()).longValue();

        space  = currentProgram.getAddressFactory().getDefaultAddressSpace();
        memory = currentProgram.getMemory();

        // --- load the flash image: the LARGEST INITIALIZED block (see SeedFunctions for why the
        // naive getBlocks()[0] is unsafe once SetupF28377D has added RAM/MMIO blocks). ----------
        long bestLen = -1;
        for (MemoryBlock b : memory.getBlocks()) {
            if (!b.isInitialized()) continue;
            long len = b.getEnd().getOffset() - b.getStart().getOffset() + 1;
            if (len > bestLen) { bestLen = len; imageBlk = b; }
        }
        if (imageBlk == null) { println("ERROR: no initialized block — import the raw image first."); return; }
        Address istart = imageBlk.getStart(), iend = imageBlk.getEnd();
        base = istart.getOffset() / 2;
        long nbytes = iend.getOffset() - istart.getOffset() + 1;
        nwords = nbytes / 2;
        mem = new byte[(int) nbytes];
        init = new boolean[(int) nbytes];
        AddressSetView initSet = memory.getLoadedAndInitializedAddressSet().intersect(
            currentProgram.getAddressFactory().getAddressSet(istart, iend));
        for (var rng : initSet) {
            int off = (int) (rng.getMinAddress().getOffset() - istart.getOffset());
            int len = (int) (rng.getMaxAddress().getOffset() - rng.getMinAddress().getOffset() + 1);
            byte[] buf = new byte[len]; memory.getBytes(rng.getMinAddress(), buf);
            System.arraycopy(buf, 0, mem, off, len);
            for (int i = off; i < off + len; i++) init[i] = true;
        }
        println(String.format("image: base=0x%x  words=0x%x  block=%s", base, nwords, imageBlk.getName()));

        // --- forward constant-propagation pass: collect section triples PER COPY ROUTINE (callee) --
        // Group by the CALLEE (the word-copy routine), per the plan's discriminator: "the common
        // callee across >= minSites constant flash->RAM copy sites is the copy routine." Keying on the
        // callee uses the call REFERENCE (always present from the decoded LCR), so it does NOT depend
        // on the CALLER having been bound into a function yet — function binding is applied
        // asynchronously by background analysis, and depending on it made detection non-deterministic
        // (copyInitSections dropped out on a run where it was not yet a function, and a runtime helper
        // won). The M0/M1 run floor + full-range validation drop the ~19 runtime memcpys whose args
        // are not constant and the per-variable cinit-record loader that targets M0/M1 scratch.
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        Map<Long, LinkedHashSet<List<Long>>> byCallee = new HashMap<>();     // copy routine -> triples
        int ambiguous = 0;

        Map<String, Long> reg = new HashMap<>();
        Instruction prev = null;
        for (Instruction ins : listing.getInstructions(true)) {
            Address ia = ins.getMinAddress();
            // Straight-line scoping: reset at a function entry or any control-flow discontinuity.
            // Losing constants is always SAFE (never invents a triple); the section setup the
            // compiler emits is straight-line immediately before each call, so this suffices.
            boolean boundary = prev == null
                || fm.getFunctionAt(ia) != null
                || prev.getFallThrough() == null
                || !prev.getFallThrough().equals(ia);
            if (boundary) reg.clear();

            if (ins.getFlowType().isCall()) {
                Long callee = calleeWord(ins);
                Set<Long> vals = new HashSet<>(reg.values());
                List<Long> triple = uniqueTriple(vals);
                if (callee != null && triple != null) {
                    if (copyfnOverride < 0 || callee == copyfnOverride)      // forced routine only
                        byCallee.computeIfAbsent(callee, k -> new LinkedHashSet<>()).add(triple);
                } else if (callee != null && multiTriple(vals)) {
                    ambiguous++;
                }
                reg.clear();                       // a call clobbers the ABI-volatile registers
            } else {
                applyRegWrite(ins, reg);
            }
            prev = ins;
        }

        // --- pick the copy routine + its section set -----------------------------------------------
        // Score each candidate callee by its NON-OVERLAPPING triple set: real section copies target
        // DISJOINT run regions (you cannot copy two sections to the same RAM), whereas a scratch-
        // buffer helper copies many flash sources to the SAME run — which collapses to one region and
        // scores ~1. Prefer a callee whose set contains a CODE section (the .ramfunc — the whole point
        // of this pass; only the ramfunc-copier has one), then the larger disjoint set, then bytes.
        long copyfn = -1; boolean bestCode = false; int bestN = 0; long bestWords = -1;
        List<List<Long>> sections = null;
        for (var e : byCallee.entrySet()) {
            List<List<Long>> keep = nonOverlapping(e.getValue());
            boolean hasCode = false; long words = 0;
            for (List<Long> t : keep) { words += t.get(0); if (regionHasCode(t.get(1), t.get(0))) hasCode = true; }
            println(String.format("  copy-routine candidate 0x%05x %-20s %d/%d disjoint section(s), 0x%x words, code=%b",
                e.getKey(), fnName(fm, e.getKey()), keep.size(), e.getValue().size(), words, hasCode));
            if (keep.size() < minSites) continue;
            boolean better;
            if (copyfn < 0) better = true;
            else if (hasCode != bestCode) better = hasCode;
            else if (keep.size() != bestN) better = keep.size() > bestN;
            else if (words != bestWords) better = words > bestWords;
            else better = e.getKey() < copyfn;
            if (better) { copyfn = e.getKey(); bestCode = hasCode; bestN = keep.size(); bestWords = words; sections = keep; }
        }
        if (copyfn < 0) {
            println(String.format("NO copy routine found: no callee made >= %d disjoint constant flash->RAM "
                + "section copies. Pass -Dc28x.mat.copyfn=0xWORD to force it, or -Dc28x.mat.minSites=1 "
                + "for a single-section image. %d ambiguous site(s) skipped.", minSites, ambiguous));
            return;
        }
        println(String.format("copy routine: 0x%05x %s  (%d section(s)%s)",
            copyfn, fnName(fm, copyfn), sections.size(), copyfnOverride >= 0 ? ", forced" : ""));

        // Already run-sorted by nonOverlapping().
        List<List<Long>> secs = sections;

        // --- classify + materialize --------------------------------------------------------------
        int done = 0;
        List<Address> codeTargets = new ArrayList<>();     // all CODE-section entries (for the repair)
        for (List<Long> t : secs) {
            long size = t.get(0), run = t.get(1), load = t.get(2);
            // CODE vs DATA: a section holding RAM-resident code has incoming CALL/branch refs from
            // the flash (created when SeedFunctions disassembled the callers); pure data does not.
            AddressSet region = new AddressSet(addr(run), space.getAddress((run + size) * 2 - 1));
            List<Address> callTargets = callTargetsIn(region);
            boolean isCode = !callTargets.isEmpty();
            println(String.format("  section run=0x%05x load=0x%05x size=0x%-6x %s  (%d call-target%s)",
                run, load, size, isCode ? "CODE" : "DATA",
                callTargets.size(), callTargets.size() == 1 ? "" : "s"));
            if (dryRun) continue;

            // place the flash load-image into the RAM run region (split at block boundaries)
            byte[] blob = new byte[(int) (size * 2)];
            System.arraycopy(mem, (int) ((load - base) * 2), blob, 0, blob.length);
            List<MemoryBlock> touched = writeSplit(run, blob);

            if (isCode) {
                for (MemoryBlock b : touched) { try { b.setExecute(true); } catch (Exception ex) {} }
                if (doDisasm) {
                    // TWO passes. Disassemble EVERY entry's flow (followFlow, unrestricted — the
                    // SeedFunctions recipe) FIRST, THEN bind functions. A single interleaved pass
                    // stubs ~half the ramfuncs: CreateFunction(E) runs before a neighbouring entry's
                    // followFlow has laid down E's fall-through, so it binds a 1-word body. CALL-only
                    // targets (not jump/switch-table destinations) keep the sweep off data.
                    for (Address ta : callTargets)
                        new DisassembleCommand(ta, null, true).applyTo(currentProgram, monitor);
                    for (Address ta : callTargets)
                        if (fm.getFunctionAt(ta) == null)     // never overwrite an existing function
                            new CreateFunctionCmd(ta).applyTo(currentProgram, monitor);
                }
                markLoadImageAsData(load, size, run);
            }
            // additive breadcrumb at the run start (GhidraScript.setPlateComment is the
            // non-deprecated path; the run start is fresh RAM so this clobbers nothing).
            setPlateComment(addr(run), String.format(
                "materialized %s section: flash 0x%05x -> RAM 0x%05x, 0x%x words",
                isCode ? "code (.ramfunc)" : "data (.cinit/initialized)", load, run, size));
            done++;
        }
        println(String.format("%s: %d section(s) %s", dryRun ? "DRY RUN" : "done", secs.size(),
            dryRun ? "detected (no changes)" : ("materialized (" + done + " written)")));
        if (!dryRun && !codeTargets.isEmpty())
            println("NOTE: run FinalizeRamfuncs.java AFTER analysis settles to rebuild stubbed ramfunc "
                + "bodies and undo the false no-return Ghidra stamps on them (truncates flash callers).");
    }

    // The flash LOAD image of a code section is byte-identical to the RAM run image but is never
    // executed in place (it is only the copy SOURCE). SeedFunctions/analysis nonetheless disassembles
    // it as PHANTOM duplicate functions (e.g. FUN_00082f2c mirroring the ramfunc at RAM 0x9300), and
    // those phantom LCRs are what seed the residual no-return overrides. Drop the phantom (default-
    // named) functions in the load span and mark it as a data array so it reads as the load image it
    // is and re-analysis leaves it alone. User-renamed functions are never removed.
    void markLoadImageAsData(long load, long size, long run) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        Address lo = addr(load), hi = space.getAddress((load + size) * 2 - 1);
        List<Address> kill = new ArrayList<>();
        for (var it = fm.getFunctions(lo, true); it.hasNext(); ) {
            Function f = it.next();
            if (f.getEntryPoint().compareTo(hi) > 0) break;
            if (f.getSymbol() == null || f.getSymbol().getSource() == ghidra.program.model.symbol.SourceType.DEFAULT)
                kill.add(f.getEntryPoint());
        }
        for (Address k : kill) new ghidra.app.cmd.function.DeleteFunctionCmd(k).applyTo(currentProgram);
        try {
            listing.clearCodeUnits(lo, hi, false);
            listing.createData(lo, new ghidra.program.model.data.ArrayDataType(
                ghidra.program.model.data.Undefined2DataType.dataType, (int) size, 2));
        } catch (Exception e) {
            println(String.format("  load-image markup @0x%05x: %s", load, e.getMessage()));
        }
        setPlateComment(lo, String.format("flash LOAD image of code section -> RAM 0x%05x (0x%x words)", run, size));
        println(String.format("  load image 0x%05x-0x%05x marked data, %d phantom function(s) dropped",
            load, load + size - 1, kill.size()));
    }

    // --- constant tracking -------------------------------------------------------------------
    // Record the last immediate written to each register; invalidate a register (and its
    // parent/child sub-registers) on ANY other write, so a pointer loaded from the stack in a
    // runtime copy leaves no stale section constant behind. The destination register comes from
    // getResultObjects() and the immediate from getInputObjects(), NOT operand indices: on this
    // C28x module `MOVL XAR5,#0x82f2c` models the pointer as its ONLY operand with XAR5 implicit
    // (getRegister(0) == null, nops == 1), while `MOV @AL,#0x260c` puts the loc16 dest at operand 0
    // — an operand-index scan catches one form but not the other. The result/input view is uniform.
    void applyRegWrite(Instruction ins, Map<String, Long> reg) {
        List<Register> dsts = new ArrayList<>();
        for (Object o : ins.getResultObjects()) if (o instanceof Register) dsts.add((Register) o);
        Long imm = null;
        for (Object o : ins.getInputObjects()) if (o instanceof Scalar) { imm = ((Scalar) o).getUnsignedValue(); break; }
        if (imm != null && !dsts.isEmpty() && ins.getMnemonicString().startsWith("MOV")) {
            Register widest = null;      // key under the value register, not a co-written flag bit
            for (Register d : dsts) {
                clearFamily(reg, d);
                if (widest == null || d.getBitLength() > widest.getBitLength()) widest = d;
            }
            reg.put(widest.getName(), imm);
            return;
        }
        for (Register d : dsts) clearFamily(reg, d);       // non-immediate write clobbers its dest(s)
    }

    void clearFamily(Map<String, Long> reg, Register r) {
        if (r == null) return;
        reg.remove(r.getName());
        for (Register p = r.getParentRegister(); p != null; p = p.getParentRegister()) reg.remove(p.getName());
        List<Register> kids = r.getChildRegisters();
        if (kids != null) for (Register c : kids) reg.remove(c.getName());
    }

    String fnName(FunctionManager fm, long word) {
        Function f = fm.getFunctionAt(addr(word));
        return f != null ? f.getName() : "(no function)";
    }

    Long calleeWord(Instruction ins) {
        for (Reference r : ins.getReferencesFrom()) {
            if (r.getReferenceType().isCall() && r.getToAddress() != null && r.getToAddress().isMemoryAddress())
                return r.getToAddress().getOffset() / 2;
        }
        Address[] flows = ins.getFlows();
        if (flows != null) for (Address a : flows) if (a.isMemoryAddress()) return a.getOffset() / 2;
        return null;
    }

    // --- triple formation --------------------------------------------------------------------
    // From the live constants at a call, enumerate every VALID (size,run,load) assignment. size is
    // either an explicit count const or (flash load-end - load). Returns the unique triple, or null
    // if zero or (ambiguously) more than one validate.
    List<List<Long>> allTriples(Set<Long> vals) {
        LinkedHashSet<List<Long>> out = new LinkedHashSet<>();
        for (long load : vals) {
            if (!inImage(load)) continue;
            for (long run : vals) {
                if (!inRam(run)) continue;
                for (long size : vals)               // explicit count constant (a scalar, not a
                    if (!inImage(size) && !inRam(size)   // pointer — else a dst/src addr like 0x9300
                            && validTriple(size, run, load))  // masquerades as a second valid size)
                        out.add(List.of(size, run, load));
                for (long loadEnd : vals)            // count derived from a flash load-end pointer
                    if (inImage(loadEnd) && loadEnd > load && validTriple(loadEnd - load, run, load))
                        out.add(List.of(loadEnd - load, run, load));
            }
        }
        return new ArrayList<>(out);
    }
    List<Long> uniqueTriple(Set<Long> vals) { var t = allTriples(vals); return t.size() == 1 ? t.get(0) : null; }
    boolean multiTriple(Set<Long> vals) { return allTriples(vals).size() > 1; }

    boolean inImage(long w) { return w >= base && w <= base + nwords - 1; }
    // A section RUN target: mapped, outside the flash image, and above M0/M1 scratch (a .ramfunc /
    // .cinit / initialized-data run lives in LS/D/GS, never the 0x0-0x7FF core scratch — which is
    // where per-variable cinit-record loaders and small runtime copies write, and which would
    // otherwise be misread as sections).
    boolean inRam(long w) {
        if (w < minRunWord) return false;
        Address a = addr(w);
        MemoryBlock b = memory.getBlock(a);
        return b != null && !imageBlk.contains(a);
    }

    boolean validTriple(long size, long run, long load) {
        if (size < 1 || size > maxWords) return false;
        if (load < base || load + size > base + nwords) return false;   // within image word-range
        long sb = (load - base) * 2, eb = sb + size * 2;                // and fully initialized
        for (long i = sb; i < eb; i++) if (!init[(int) i]) return false;
        Address rs = addr(run), re = space.getAddress((run + size) * 2 - 1);
        if (!memory.contains(rs) || !memory.contains(re)) return false; // run region fully mapped
        if (!memory.contains(rs, re)) return false;
        if (imageBlk.contains(rs) || imageBlk.contains(re)) return false;   // and not the flash image
        return true;
    }

    // --- materialization helpers -------------------------------------------------------------
    // Greedy DISJOINT subset of a callee's triples, run-sorted. A real set of section copies is
    // already disjoint (all kept); a scratch-buffer helper's many same-run copies collapse to one.
    List<List<Long>> nonOverlapping(java.util.Collection<List<Long>> triples) {
        List<List<Long>> ts = new ArrayList<>(triples);
        ts.sort(Comparator.comparingLong(t -> t.get(1)));
        List<List<Long>> keep = new ArrayList<>();
        long lastEnd = Long.MIN_VALUE;
        for (List<Long> t : ts) {
            long run = t.get(1), end = run + t.get(0);
            if (run >= lastEnd) { keep.add(t); lastEnd = end; }
        }
        return keep;
    }

    boolean regionHasCode(long run, long size) {
        return !callTargetsIn(new AddressSet(addr(run), space.getAddress((run + size) * 2 - 1))).isEmpty();
    }

    // Addresses in `region` that are the destination of at least one CALL reference from the
    // already-disassembled flash — i.e. RAM-resident function ENTRIES to recover. CALL only, NOT
    // jump: a jump destination into a code section is usually a switch/branch table entry or an
    // intra-function label; disassembling there lands mid-instruction and cascades into
    // halt_baddata. Real function entries reached only by a tail JUMP are rare and are recovered by
    // fall-through/branch from a genuine caller instead.
    List<Address> callTargetsIn(AddressSet region) {
        ReferenceManager rm = currentProgram.getReferenceManager();
        TreeSet<Address> tgts = new TreeSet<>();
        for (var it = rm.getReferenceDestinationIterator(region, true); it.hasNext(); ) {
            Address d = it.next();
            for (var ri = rm.getReferencesTo(d); ri.hasNext(); ) {
                if (ri.next().getReferenceType().isCall()) { tgts.add(d); break; }
            }
        }
        return new ArrayList<>(tgts);
    }

    // Write `blob` starting at RAM word `run`, converting each overlapped block to initialized
    // (fill 0) first and SPLITTING the write at block seams (the .ramfunc region crosses LS0-5 ->
    // D0-1 at word 0xB000). Returns the blocks written to. Idempotent: a block already initialized
    // (a re-run) is just re-written.
    List<MemoryBlock> writeSplit(long run, byte[] blob) throws Exception {
        List<MemoryBlock> touched = new ArrayList<>();
        long startByte = run * 2;
        int written = 0;
        while (written < blob.length) {
            Address cur = space.getAddress(startByte + written);
            MemoryBlock b = memory.getBlock(cur);
            if (b == null) throw new Exception("run region leaves mapped memory at " + cur);
            if (!b.isInitialized()) { memory.convertToInitialized(b, (byte) 0); b = memory.getBlock(cur); }
            long blockEndByte = b.getEnd().getOffset();
            int chunk = (int) Math.min(blob.length - written, blockEndByte - (startByte + written) + 1);
            byte[] slice = Arrays.copyOfRange(blob, written, written + chunk);
            memory.setBytes(space.getAddress(startByte + written), slice);
            if (!touched.contains(b)) touched.add(b);
            written += chunk;
        }
        return touched;
    }
}
