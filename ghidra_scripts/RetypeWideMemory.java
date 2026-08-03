// Retype 32-bit and 64-bit memory operands to eliminate CONCAT22/CONCAT44 in decompilation.
//
// THE PROBLEM. Ghidra renders a 4-byte read from memory as CONCAT22(hi, lo) when the base
// symbol at that address is smaller than 4 bytes (typically undefined2, since the default
// auto-analysis leaves a bare 2-byte cell at each accessed word). Both halves render with
// the base symbol name because no distinct symbol exists at address+word — e.g.
//   uVar1 = CONCAT22(DAT_00013a42, DAT_00013a42) & 0xffffff;
// The 8-byte analogue is CONCAT44, appearing for long-long / double loads across two
// adjacent 4-byte cells.
//
// THE FIX. Walk every instruction's p-code. For every LOAD/STORE with a resolved concrete
// address (from Ghidra's constant/DP propagation, surfaced as a READ/WRITE reference) and
// size >= 4, retype the target as undefined4 or undefined8. This makes the decompiler
// render the access as a single symbol (DAT_00013a42 = X) instead of a piecewise concat.
//
// TWO PASSES, LARGEST FIRST. u8 pass runs before u4 so an early u4 retype at address X
// doesn't block a later u8 upgrade at X.
//
// SAFETY. Never overwrites:
//   - non-Undefined data (structs, floats, pointers, anything typed by SetupF28377D or a
//     user — the "startsWith undefined" gate)
//   - a code unit (an instruction lives at the address — impossible for a real global,
//     but a defensive guard against retyping in the middle of a mis-disassembled block)
// Only READ references pair with LOADs and WRITE references pair with STOREs. If the
// instruction emits both a LOAD and a STORE (rare on C28x — read-modify-write forms like
// AND @loc16,#imm), each reference is sized independently.
//
// Properties (-Dname=value):
//   c28x.retype.dryRun  (bool, default false) log intended retypes without applying them
//   c28x.retype.min     (int,  default 4)     minimum size to retype (4 or 8)
//
// Pairs with SetupF28377D (which pre-types known-32-bit peripheral registers) — this
// script fixes RAM globals the setup script doesn't know about.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class RetypeWideMemory extends GhidraScript {

    @Override
    public void run() throws Exception {
        boolean dryRun = Boolean.getBoolean("c28x.retype.dryRun");
        int minSize = Integer.getInteger("c28x.retype.min", 4);

        Listing listing = currentProgram.getListing();
        Map<Address, Integer> hits = new HashMap<>();
        int scanned = 0, refsMatched = 0;

        for (Instruction ins : listing.getInstructions(true)) {
            scanned++;
            PcodeOp[] ops = ins.getPcode();
            if (ops == null || ops.length == 0) continue;

            // Find the largest LOAD and STORE sizes emitted by this instruction. On C28x an
            // instruction typically emits at most one of each; taking the max is defensive
            // against multi-word helpers where a small setup LOAD (e.g. DP fetch) shouldn't
            // shrink our estimate of the main access.
            int loadSize = 0, storeSize = 0;
            for (PcodeOp op : ops) {
                int code = op.getOpcode();
                if (code == PcodeOp.LOAD) {
                    int sz = op.getOutput().getSize();
                    if (sz > loadSize) loadSize = sz;
                } else if (code == PcodeOp.STORE) {
                    int sz = op.getInput(2).getSize();
                    if (sz > storeSize) storeSize = sz;
                }
            }
            if (loadSize < minSize && storeSize < minSize) continue;

            // Pair each reference with the matching op's size.
            for (Reference ref : ins.getReferencesFrom()) {
                RefType rt = ref.getReferenceType();
                int size = 0;
                if (rt.isRead() && loadSize >= minSize) size = loadSize;
                else if (rt.isWrite() && storeSize >= minSize) size = storeSize;
                if (size == 0) continue;
                Address target = ref.getToAddress();
                if (target == null) continue;
                Integer cur = hits.get(target);
                if (cur == null || size > cur) hits.put(target, size);
                refsMatched++;
            }
        }
        println(String.format("scanned %d instructions, %d refs matched, %d unique addrs",
            scanned, refsMatched, hits.size()));

        DataType u4 = Undefined4DataType.dataType;
        DataType u8 = Undefined8DataType.dataType;
        int did4 = 0, did8 = 0, skipped = 0;

        // Sort so ranges apply deterministically (also makes the log easier to scan).
        TreeMap<Address, Integer> sorted = new TreeMap<>(hits);

        // u8 first — a u4 retype would block the u8 upgrade later.
        for (var e : sorted.entrySet()) {
            if (e.getValue() < 8) continue;
            if (apply(e.getKey(), 8, u8, dryRun)) did8++; else skipped++;
        }
        for (var e : sorted.entrySet()) {
            if (e.getValue() < 4 || e.getValue() >= 8) continue;
            if (apply(e.getKey(), 4, u4, dryRun)) did4++; else skipped++;
        }

        println(String.format("%s: %d retyped as u4, %d retyped as u8, %d skipped",
            dryRun ? "DRY RUN" : "done", did4, did8, skipped));
    }

    // Try to retype [a, a+size) as dt. Returns true iff we did (or would have, in dry-run).
    private boolean apply(Address a, int size, DataType dt, boolean dryRun) throws Exception {
        if (a == null || !currentProgram.getMemory().contains(a)) return false;
        // Skip if the target is inside an instruction — this address is code, not data.
        if (currentProgram.getListing().getInstructionAt(a) != null) return false;

        Data existing = currentProgram.getListing().getDataAt(a);
        if (existing != null) {
            String dtName = existing.getDataType().getName();
            // Leave user- or setup-typed data alone (structs, floats, function pointers, etc).
            if (!dtName.startsWith("undefined")) return false;
            // If a wider or equal Undefined is already there, we're done.
            if (existing.getDataType().getLength() >= size) return false;
        }
        Address end;
        try { end = a.add(size - 1); } catch (Exception ex) { return false; }
        if (!currentProgram.getMemory().contains(end)) return false;

        if (dryRun) {
            println(String.format("  would retype @%s as %s (%d bytes)",
                a.toString(), dt.getName(), size));
            return true;
        }
        try {
            currentProgram.getListing().clearCodeUnits(a, end, false);
            currentProgram.getListing().createData(a, dt);
            return true;
        } catch (Exception ex) {
            println(String.format("  skip @%s: %s", a.toString(), ex.getMessage()));
            return false;
        }
    }
}
