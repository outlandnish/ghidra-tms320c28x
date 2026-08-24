// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Recover the callers that hide behind function-pointer tables.
//
// A lot of C28x firmware dispatches through tables of 32-bit function pointers that no
// analyzer claims: MarkJumpTables only takes uniform runs (a real switch table), and the
// interesting ones here are *sparse struct arrays* — mostly NULL, with a code pointer
// every few words at irregular spacing. Nothing references those slots, so the functions
// they name show zero xrefs and read as orphaned even though they plainly run.
//
// WHY NOT JUST APPLY A POINTER TYPE. This is a wordsize=2 space. A stored value like
// 0x000a38c6 is a WORD address, but Ghidra's PointerDataType interprets the raw value as
// an address offset, landing on word 0x51c63 — a silently WRONG reference into the middle
// of unrelated code. So this script converts explicitly (target = value * 2) and creates
// the reference itself. Slots are marked undefined4, which is inert: unlike dword/pointer
// it does not invite the Data Reference analyzer to add a second, wrong reference.
//
// The filter is deliberately strict, because a false pointer invents a caller edge that
// is worse than the missing one. A slot qualifies only when:
//   - it is 2-word aligned and its 4 bytes are not already inside an instruction, and
//   - the value resolves EXACTLY to the entry point of an existing function.
// Exact-function-entry is what makes this safe: arbitrary data almost never equals a
// function entry address, whereas "points somewhere in the code range" matches constantly.
//
// Dry run by default. Args:
//   apply              actually create the references + undefined4 slots
//   0xSTART 0xEND      restrict to a word-address range (default: all initialized flash)
//   insn               relax the target test from "function entry" to "instruction start"
//                      (looser — review the report before trusting it)
//
//@category C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

public class MarkCodePointers extends GhidraScript {

    private static final class Hit {
        Address slot;
        Address target;
        String targetName;
    }

    @Override
    public void run() throws Exception {
        boolean apply = false;
        boolean insnMode = false;
        Long rangeStart = null;
        Long rangeEnd = null;

        for (String a : getScriptArgs()) {
            if (a.equalsIgnoreCase("apply")) {
                apply = true;
            }
            else if (a.equalsIgnoreCase("insn")) {
                insnMode = true;
            }
            else if (a.startsWith("0x") || a.startsWith("0X")) {
                long v = Long.parseLong(a.substring(2), 16);
                if (rangeStart == null) {
                    rangeStart = v;
                }
                else {
                    rangeEnd = v;
                }
            }
        }

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();

        // Valid pointer targets live in the image's own initialized flash.
        long imgLo = Long.MAX_VALUE;
        long imgHi = Long.MIN_VALUE;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized() || !b.isExecute()) {
                continue;
            }
            imgLo = Math.min(imgLo, b.getStart().getOffset() >> 1);
            imgHi = Math.max(imgHi, b.getEnd().getOffset() >> 1);
        }
        if (imgLo > imgHi) {
            println("no initialized executable block found");
            return;
        }
        long scanLo = rangeStart != null ? rangeStart : imgLo;
        long scanHi = rangeEnd != null ? rangeEnd : imgHi;
        println(String.format("image words 0x%x..0x%x ; scanning 0x%x..0x%x ; mode=%s",
                imgLo, imgHi, scanLo, scanHi, insnMode ? "instruction-start" : "function-entry"));

        List<Hit> hits = new ArrayList<>();
        int skippedInCode = 0;
        int skippedHasRef = 0;

        byte[] buf = new byte[4];
        for (long w = (scanLo + 1) & ~1L; w + 1 <= scanHi; w += 2) {
            Address slot = space.getAddress(w << 1);
            if (!mem.contains(slot)) {
                continue;
            }
            try {
                if (mem.getBytes(slot, buf) != 4) {
                    continue;
                }
            }
            catch (Exception e) {
                continue;
            }

            long v = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8)
                   | ((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
            if (v < imgLo || v > imgHi) {
                continue;             // not a plausible in-image word address
            }

            Address target = space.getAddress(v << 1);
            boolean ok = insnMode
                    ? currentProgram.getListing().getInstructionAt(target) != null
                    : getFunctionAt(target) != null;
            if (!ok) {
                continue;
            }

            // The slot must be data, not part of a real instruction.
            CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(slot);
            if (cu instanceof Instruction) {
                skippedInCode++;
                continue;
            }
            if (hasRefTo(slot, target)) {
                skippedHasRef++;
                continue;
            }

            Hit h = new Hit();
            h.slot = slot;
            h.target = target;
            h.targetName = getFunctionAt(target) != null
                    ? getFunctionAt(target).getName() : target.toString();
            hits.add(h);
        }

        println("candidate code pointers: " + hits.size()
                + "  (skipped: " + skippedInCode + " inside instructions, "
                + skippedHasRef + " already referenced)");
        int shown = 0;
        for (Hit h : hits) {
            if (shown++ >= 40) {
                println("   … and " + (hits.size() - 40) + " more");
                break;
            }
            println("   " + h.slot + " -> " + h.target + "  " + h.targetName);
        }

        if (!apply) {
            println("");
            println("DRY RUN -- nothing changed. Re-run with 'apply' to create "
                    + hits.size() + " reference(s).");
            return;
        }

        int refs = 0;
        int typed = 0;
        for (Hit h : hits) {
            // Type FIRST, reference SECOND. clearListing drops every reference in the
            // range it clears, so creating the reference first silently threw it away.
            // The extent is slot..slot+1, not slot+3: this is a wordsize=2 space, so a
            // 4-BYTE undefined4 spans 2 ADDRESSABLE UNITS. Clearing 4 units ran into the
            // next pointer slot and wiped its reference too.
            try {
                if (currentProgram.getListing().getDefinedDataAt(h.slot) == null) {
                    clearListing(h.slot, h.slot.add(1));
                    createData(h.slot, new Undefined4DataType());
                    typed++;
                }
            }
            catch (Exception e) {
                // A slot that will not take a 4-byte type (it overlaps a neighbouring
                // definition) still gets its reference below, which is the point.
            }
            currentProgram.getReferenceManager().addMemoryReference(
                    h.slot, h.target, RefType.DATA, SourceType.ANALYSIS, 0);
            refs++;
        }
        println("");
        println("applied: " + refs + " reference(s) created, " + typed + " slot(s) typed undefined4.");
    }

    private boolean hasRefTo(Address from, Address to) {
        for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(from)) {
            if (r.getToAddress().equals(to)) {
                return true;
            }
        }
        return false;
    }
}
