// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Surface the data xrefs Ghidra misses on C28x: a global reached through a pointer register
// loaded with a constant, `MOVL XARn,#addr ; ... ; AND *+XARn[k],#imm`. The deref names a
// REGISTER, not the address, so the auto-analyzer records no reference and `references to X`
// shows nothing -- which is how a live consumer of a global looks dead to an operand scan.
//
// It re-derives each XARn value with Ghidra's own SymbolicPropogator (flow-following, path-
// merging constant propagation -- not a linear last-seen guess), so a base that differs across
// branches resolves to "unknown" and adds nothing rather than a wrong ref. For every
// `*+XARn[k]` / `*XARn` deref whose base resolves to a constant, it adds a memory reference from
// the instruction to (base + k), typed READ / WRITE / READ_WRITE from the instruction's pcode.
//
// -------------------------------------------------------------------------------------------
// THREE MODES (default = the whole-program dry run above):
//
//   1. default        resolve every constant-base deref; report / (apply) add references.
//   2. target=0xWORD  REVERSE query: report every deref site that resolves EXACTLY to 0xWORD,
//                     across all functions, with the containing function. Read-only. This is the
//                     "who reads this address" question for computed pointers.
//   3. accessor=0xWORD  INTERPROCEDURAL: for the generic-accessor function entering at 0xWORD,
//                     walk every CALL site and resolve the constant argument registers
//                     (ACC / AL / AH / XAR4 / XAR5) the caller set up. A `base(const)+index`
//                     table read hides WHICH element a caller touches in that caller's constant
//                     index arg -- this recovers it. With `base=` / `shift=` / `emask=` / `bmask=`
//                     it also prints the concrete element word + bit each caller reads, e.g. a
//                     bit-array accessor: base=0x.. shift=4 emask=0xfff bmask=0xf.
// -------------------------------------------------------------------------------------------
//
// A target is suppressed only when it is REAL CODE (resolves onto an instruction), or is off-map.
// Block-level executability is NOT used by default: GS0_15_RAM is exec-flagged (it holds copied
// .ramfunc code) yet is exactly where the globals live, so excluding the whole block discards
// nearly every global read. Pass `strictBlock` to restore the old whole-exec-block exclusion.
// SP-relative values come back register-relative from the propagator and are skipped, so stack
// slots never produce a ref.
//
// DRY RUN by default: it reports what it would add and touches nothing. Pass `apply` to write.
//
// Properties / args:
//   apply                 (script arg)  actually add references (default: dry run)
//   strictBlock           (script arg)  exclude entire exec-flagged blocks (old coarse behavior)
//   target                (0xWORD)      reverse-query mode: who resolves to this word
//   accessor              (0xWORD)      caller-index mode: resolve call-site constant args
//   base / shift / emask / bmask (0x..) accessor-mode element decode: elem=base+((AL>>shift)&emask), bit=AL&bmask
//   c28x.xref.minWord      (0xWORD)     only reference targets at/above this word addr (default 0xC000: on
//                                       F28377D that is GS RAM up, so M0/M1, the peripheral frames and
//                                       LS0-5 are skipped; lower it for peripheral refs or other maps)
//   c28x.xref.maxWord      (0xWORD)     only targets below this word addr (default: no cap)
//   c28x.xref.func         (0xWORD)     restrict default mode to one function entry (debug)
//
//@category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.util.regex.*;

public class ResolveComputedPointerXrefs extends GhidraScript {

    static final Pattern DEREF = Pattern.compile("\\*\\+?XAR([0-7])\\[0x([0-9a-fA-F]+)\\]|\\*XAR([0-7])(?![\\w\\[])");

    AddressSpace space;
    Memory mem;
    FunctionManager fm;
    ReferenceManager rm;
    Listing lst;
    Register[] xar = new Register[8];
    final List<Register> tracked = new ArrayList<>();    // XAR0-7 + the accessor-mode args

    Address wa(long w) { return space.getAddress(w * 2); }
    long wordOf(Address a) { return a.getOffset() / 2; }

    @Override
    public void run() throws Exception {
        space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        mem = currentProgram.getMemory();
        fm = currentProgram.getFunctionManager();
        rm = currentProgram.getReferenceManager();
        lst = currentProgram.getListing();
        for (int i = 0; i < 8; i++) xar[i] = currentProgram.getLanguage().getRegister("XAR" + i);
        tracked.addAll(Arrays.asList(xar));
        for (String n : new String[] { "AL", "AH", "ACC" })
            tracked.add(currentProgram.getLanguage().getRegister(n));

        long accessor = wordProp("accessor", -1L);
        long target = wordProp("target", -1L);
        if (accessor >= 0) { accessorMode(accessor); return; }
        if (target >= 0) { targetMode(target); return; }
        defaultMode();
    }

    // -------------------------------------------------------------------- default (whole-program)
    void defaultMode() throws Exception {
        boolean apply = hasFlag("apply");
        // A data ref is suppressed only when the target is REAL CODE (an instruction). Block-level
        // isExecute() is too coarse on these images: GS0_15_RAM is exec-flagged (it holds copied
        // .ramfunc code) yet is where the globals live -- excluding the whole block discards nearly
        // every global read. `strictBlock` restores the old block-level exclusion if ever needed.
        boolean strictBlock = hasFlag("strictBlock");
        long minWord = wordProp("c28x.xref.minWord", 0xC000L);
        long maxWord = wordProp("c28x.xref.maxWord", Long.MAX_VALUE);
        long onlyFunc = wordProp("c28x.xref.func", -1L);

        int fns = 0, derefs = 0, resolved = 0, added = 0, already = 0, offmap = 0, incode = 0;
        Map<Long, int[]> perTarget = new TreeMap<>();     // word -> {added, already}
        StringBuilder sample = new StringBuilder();

        for (Function f : fm.getFunctions(true)) {
            if (onlyFunc >= 0 && wordOf(f.getEntryPoint()) != onlyFunc) continue;
            fns++;
            Flow flow = propagate(f);
            for (Instruction ins : lst.getInstructions(f.getBody(), true)) {
                Matcher m = DEREF.matcher(ins.toString());
                while (m.find()) {
                    derefs++;
                    int r = m.group(1) != null ? Integer.parseInt(m.group(1)) : Integer.parseInt(m.group(3));
                    int k = m.group(2) != null ? Integer.parseInt(m.group(2), 16) : 0;
                    Long base = flow.constAt(ins.getAddress(), xar[r]);
                    if (base == null) continue;
                    long word = base + k;
                    resolved++;
                    if (word < minWord || word >= maxWord) continue;
                    Address t = wa(word);
                    MemoryBlock b = mem.getBlock(t);
                    if (b == null) { offmap++; continue; }
                    boolean isCode = strictBlock ? b.isExecute() : (getInstructionContaining(t) != null);
                    if (isCode) { incode++; continue; }
                    RefType rt = classify(ins);
                    boolean have = false;
                    for (Reference ex : rm.getReferencesFrom(ins.getAddress()))
                        if (ex.getToAddress().equals(t)) { have = true; break; }
                    int[] c = perTarget.computeIfAbsent(word, x -> new int[2]);
                    if (have) { already++; c[1]++; continue; }
                    c[0]++; added++;
                    if (apply)
                        rm.addMemoryReference(ins.getAddress(), t, rt, SourceType.ANALYSIS, 0);
                    else if (sample.length() < 2000)
                        sample.append(String.format("  %s  %-30s -> %05x %-10s %s%n",
                            ins.getAddress(), ins.toString(), word, "(" + rt + ")", b.getName()));
                }
            }
        }

        println(String.format("functions %d | derefs %d | base resolved %d | in-range new %d, already-known %d",
            fns, derefs, resolved, added, already));
        println(String.format("skipped: off-map %d, into-code %d%s", offmap, incode,
            strictBlock ? " (strictBlock: whole exec blocks excluded)" : " (code = real instructions only)"));
        println("\ntop newly-referenced targets (word : +new / known):");
        perTarget.entrySet().stream()
            .filter(e -> e.getValue()[0] > 0)
            .sorted((x, y) -> y.getValue()[0] - x.getValue()[0]).limit(20)
            .forEach(e -> {
                Symbol s = getSymbolAt(wa(e.getKey()));
                println(String.format("  %05x  +%-3d /%-3d  %s", e.getKey(),
                    e.getValue()[0], e.getValue()[1], s == null ? "" : s.getName()));
            });
        if (!apply) {
            println("\nsample of references that WOULD be added:");
            println(sample.toString());
            println("DRY RUN -- nothing written. Re-run with `apply` to add them.");
        } else {
            println("\nadded " + added + " references.");
        }
    }

    // -------------------------------------------------------------------- target (reverse query)
    void targetMode(long target) throws Exception {
        println(String.format("REVERSE QUERY: deref sites resolving to %05x  %s\n",
            target, symName(target)));
        int hits = 0;
        for (Function f : fm.getFunctions(true)) {
            Flow flow = propagate(f);
            for (Instruction ins : lst.getInstructions(f.getBody(), true)) {
                Matcher m = DEREF.matcher(ins.toString());
                while (m.find()) {
                    int r = m.group(1) != null ? Integer.parseInt(m.group(1)) : Integer.parseInt(m.group(3));
                    int k = m.group(2) != null ? Integer.parseInt(m.group(2), 16) : 0;
                    Long base = flow.constAt(ins.getAddress(), xar[r]);
                    if (base == null) continue;
                    if (base + k == target) {
                        hits++;
                        println(String.format("  %s  %-28s (%s)  in %s",
                            ins.getAddress(), ins.toString(), classify(ins), fname(f)));
                    }
                }
            }
        }
        println("\n" + hits + " exact deref site(s). NOTE: variable-index reads through a table whose");
        println("base is " + symName(target) + " show as xrefs to the BASE, not here -- use accessor= mode for those.");
    }

    // -------------------------------------------------------------------- accessor (caller index)
    void accessorMode(long entryWord) throws Exception {
        Address entry = wa(entryWord);
        Function acc = fm.getFunctionAt(entry);
        long base = wordProp("base", -1L);
        int shift = (int) wordProp("shift", 0L);
        long emask = wordProp("emask", 0xffffffffL);
        long bmask = wordProp("bmask", 0xfL);

        println(String.format("ACCESSOR CALLER-INDEX: %s @ %05x", acc == null ? "(no function)" : fname(acc), entryWord));
        if (base >= 0)
            println(String.format("element decode: elem = %05x + ((AL >> %d) & 0x%x) ; bit = AL & 0x%x\n", base, shift, emask, bmask));
        else
            println("(pass base=0x.. shift=N emask=0x.. bmask=0x.. to decode element+bit)\n");

        // collect call sites (references to the entry that are calls)
        List<Address> calls = new ArrayList<>();
        for (Reference ref : rm.getReferencesTo(entry))
            if (ref.getReferenceType().isCall()) calls.add(ref.getFromAddress());
        calls.sort(null);

        // group by calling function so we propagate each caller once
        Map<Function, List<Address>> byFn = new LinkedHashMap<>();
        for (Address ca : calls) {
            Function cf = fm.getFunctionContaining(ca);
            byFn.computeIfAbsent(cf, x -> new ArrayList<>()).add(ca);
        }

        int nCalls = 0, nConst = 0;
        Set<Long> distinctElems = new TreeSet<>();
        for (Map.Entry<Function, List<Address>> e : byFn.entrySet()) {
            Function cf = e.getKey();
            Flow flow = cf == null ? null : propagate(cf);
            for (Address ca : e.getValue()) {
                nCalls++;
                Long al = regConst(flow, ca, "AL");
                Long ah = regConst(flow, ca, "AH");
                Long acc32 = regConst(flow, ca, "ACC");
                Long x4 = regConst(flow, ca, "XAR4");
                Long x5 = regConst(flow, ca, "XAR5");
                StringBuilder ln = new StringBuilder();
                ln.append(String.format("  %s  in %-32s ", ca, cf == null ? "(none)" : fname(cf)));
                ln.append("AL=").append(hx(al)).append(" AH=").append(hx(ah));
                if (acc32 != null) ln.append(" ACC=").append(hx(acc32));
                if (x4 != null) ln.append(" XAR4=").append(hx(x4));
                if (x5 != null) ln.append(" XAR5=").append(hx(x5));
                if (al != null) {
                    nConst++;
                    if (base >= 0) {
                        long elem = base + ((al >> shift) & emask);
                        long bit = al & bmask;
                        distinctElems.add(elem);
                        ln.append(String.format("  =>  %05x bit %d  %s", elem, bit, symName(elem)));
                    }
                }
                println(ln.toString());
            }
        }
        println(String.format("\n%d call site(s); %d with a constant index arg.", nCalls, nConst));
        if (base >= 0 && !distinctElems.isEmpty()) {
            println("distinct elements read through this accessor:");
            for (long el : distinctElems)
                println(String.format("  %05x  %s", el, symName(el)));
        }
    }

    // ---------------------------------------------------------------------------------- helpers
    /**
     * Per-function constant propagation that keeps EVERY value a register held at an
     * instruction, one entry per visit. SymbolicPropogator.getRegisterValue alone reports one
     * path's value at a join -- a base that is C100 on one path and C200 on the other came back
     * as C100 -- so a reference built from it can be wrong. evaluateContextBefore runs again
     * when a second path reaches an already-visited join, which is what lets this see both.
     *
     * The evaluator is a ContextEvaluatorAdapter, NOT ConstantPropagationContextEvaluator: the
     * latter creates a reference for every constant and every resolved load/store as a side
     * effect of flowConstants -- on every path, ignoring minWord -- so even a dry run wrote refs.
     */
    Flow propagate(Function f) throws Exception {
        Flow flow = new Flow();
        SymbolicPropogator sym = new SymbolicPropogator(currentProgram);
        sym.flowConstants(f.getEntryPoint(), f.getBody(), new ContextEvaluatorAdapter() {
            @Override
            public boolean evaluateContextBefore(VarnodeContext ctx, Instruction instr) {
                Map<Register, Set<Long>> at =
                    flow.seen.computeIfAbsent(instr.getAddress(), x -> new HashMap<>());
                for (Register reg : tracked) {
                    Varnode v = ctx.getRegisterVarnodeValue(reg);
                    at.computeIfAbsent(reg, x -> new HashSet<>())
                        .add(v != null && v.isConstant() ? v.getOffset() : UNKNOWN);
                }
                return false;
            }
        }, false, monitor);
        spreadDisagreement(f, flow);
        return flow;
    }

    /**
     * A second path replays only SymbolicPropogator's MAX_EXTRA_INSTRUCTION_FLOW (16)
     * instructions past a join it has already visited, so a deref further on would record one
     * path's value. From every instruction where the paths disagree about a register, walk the
     * flow forward and mark the register unknown until an instruction overwrites all of it.
     */
    void spreadDisagreement(Function f, Flow flow) {
        AddressSetView body = f.getBody();
        for (Register reg : tracked) {
            Deque<Address> work = new ArrayDeque<>();
            for (Map.Entry<Address, Map<Register, Set<Long>>> e : flow.seen.entrySet()) {
                Set<Long> vals = e.getValue().get(reg);
                if (vals != null && vals.size() > 1) work.add(e.getKey());
            }
            Set<Address> done = new HashSet<>();
            while (!work.isEmpty()) {
                Address a = work.pop();
                if (!done.add(a)) continue;
                flow.seen.computeIfAbsent(a, x -> new HashMap<>())
                    .computeIfAbsent(reg, x -> new HashSet<>()).add(UNKNOWN);
                Instruction ins = lst.getInstructionAt(a);
                if (ins == null || overwrites(ins, reg)) continue;
                Address ft = ins.getFallThrough();
                if (ft != null && body.contains(ft)) work.add(ft);
                if (!ins.getFlowType().isCall())
                    for (Address t : ins.getFlows()) if (body.contains(t)) work.add(t);
            }
        }
    }

    /** True if the instruction's pcode writes a register varnode covering all of `reg`. */
    static boolean overwrites(Instruction ins, Register reg) {
        long lo = reg.getAddress().getOffset(), hi = lo + reg.getMinimumByteSize();
        for (PcodeOp op : ins.getPcode()) {
            Varnode out = op.getOutput();
            if (out != null && out.isRegister() && out.getOffset() <= lo
                    && out.getOffset() + out.getSize() >= hi)
                return true;
        }
        return false;
    }

    static final long UNKNOWN = Long.MIN_VALUE;

    /** Register values seen at each instruction start, across every path that reached it. */
    static class Flow {
        final Map<Address, Map<Register, Set<Long>>> seen = new HashMap<>();

        /** The register's value at `at` if every path agrees on one constant, else null. */
        Long constAt(Address at, Register reg) {
            Map<Register, Set<Long>> m = seen.get(at);
            Set<Long> vals = m == null ? null : m.get(reg);
            if (vals == null || vals.size() != 1) return null;
            long v = vals.iterator().next();
            return v == UNKNOWN ? null : v;
        }
    }

    Long regConst(Flow flow, Address at, String regName) {
        if (flow == null) return null;
        Register reg = currentProgram.getLanguage().getRegister(regName);
        return reg == null ? null : flow.constAt(at, reg);
    }

    /** READ / WRITE / READ_WRITE from the instruction's pcode touching a computed pointer. */
    RefType classify(Instruction ins) {
        boolean load = false, store = false;
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() == PcodeOp.LOAD) load = true;
            if (op.getOpcode() == PcodeOp.STORE) store = true;
        }
        if (load && store) return RefType.READ_WRITE;
        if (store) return RefType.WRITE;
        return RefType.READ;
    }

    String fname(Function f) { return f == null ? "(none)" : f.getName(); }
    String hx(Long v) { return v == null ? "?" : String.format("0x%x", v); }
    String symName(long word) {
        Symbol s = getSymbolAt(wa(word));
        return s == null ? "" : s.getName();
    }

    boolean hasFlag(String f) {
        for (String a : getScriptArgs()) if (a.equalsIgnoreCase(f)) return true;
        return false;
    }

    long wordProp(String key, long dflt) {
        // MCP/headless deliver -Dkey=value as script args, not JVM props (see EmulateStartup).
        for (String a : getScriptArgs()) {
            if (a.startsWith("-D" + key + "=")) return Long.decode(a.substring(("-D" + key + "=").length()).trim());
            if (a.startsWith(key + "=")) return Long.decode(a.substring((key + "=").length()).trim());
        }
        String p = System.getProperty(key);
        return p != null ? Long.decode(p.trim()) : dflt;
    }
}
