// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Write the ORIGINAL imported flash block of a program back out as a flat .bin.
//
// WHY. Re-importing a program needs the source image. For a few programs the staged .bin is
// gone (built once from a .bhx and not kept). Rebuilding it from the .bhx risks picking a
// different firmware revision than the one actually analysed -- several revisions ship a
// .bhx with the same name. The program itself still holds the bytes, so dump those: byte-exact
// by construction, no revision ambiguity.
//
// WHICH BLOCK. The import created exactly one block, starting at the image base. Everything
// else (peripheral frames, RAM banks, materialized run regions) was added afterwards by
// SetupF28377D / Materialize*. So the source block is the one whose start == getImageBase().
// Reported alongside the largest initialized block so a mismatch is visible rather than silent.
//
// USAGE. DumpFlashImage <outDir>
//   Writes <outDir>/<programName> -- the program name already carries the base, e.g.
//   "dir_poppy_rwd_23245_swapped_0x00080800.bin". Pass a DIRECTORY, never a path containing
//   '=': analyzeHeadless.bat truncates a script argument at the first '='.
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileOutputStream;

public class DumpFlashImage extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: DumpFlashImage <outDir>");
            return;
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();

        Memory mem = currentProgram.getMemory();
        Address base = currentProgram.getImageBase();

        // The image base is NOT a reliable handle: several of these programs were imported at
        // base 0 and then had set_image_base applied to the block only, so getImageBase() reads
        // 0x0 and a block genuinely starts there (M0_RAM). "Largest initialized" is not reliable
        // either -- on a small CPU2 image a 128K GS RAM bank outweighs a 101K flash image.
        // What holds on every one of these is that the imported block is the largest initialized
        // block in the FLASH window; RAM banks and peripheral frames all sit below it.
        final long FLASH_START = 0x80000L * 2;   // byte offset: this space is wordsize=2
        MemoryBlock source = null;
        MemoryBlock largest = null;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) {
                continue;
            }
            if (largest == null || b.getSize() > largest.getSize()) {
                largest = b;
            }
            if (b.getStart().getOffset() >= FLASH_START
                    && (source == null || b.getSize() > source.getSize())) {
                source = b;
            }
        }
        if (source == null) {
            println("WARN no initialized block in the flash window; falling back to largest");
            source = largest;
        }
        if (source == null) {
            println("ERROR no initialized block");
            return;
        }
        println("imageBase=" + base);
        println("sourceBlock=" + source.getName() + " " + source.getStart() + "-" + source.getEnd()
                + " sizeBytes=" + source.getSize());
        println("largestBlock=" + largest.getName() + " " + largest.getStart()
                + " sizeBytes=" + largest.getSize());

        // Which SetupF28377D arg was used? CPU1 maps device-unique peripherals that CPU2
        // does not, so their presence names the CPU without having to infer it from the base.
        boolean cpu1Only = false;
        StringBuilder marks = new StringBuilder();
        for (MemoryBlock b : mem.getBlocks()) {
            String nm = b.getName().toUpperCase();
            if (nm.startsWith("UPP") || nm.contains("DEV_CFG") || nm.startsWith("USBA")
                    || nm.contains("XBAR")) {
                cpu1Only = true;
                marks.append(b.getName()).append(' ');
            }
        }
        println("cpuProfile=" + (cpu1Only ? "CPU1" : "CPU2") + " evidence=[" + marks.toString().trim() + "]");

        int n = (int) source.getSize();
        byte[] buf = new byte[n];
        int got = mem.getBytes(source.getStart(), buf, 0, n);
        if (got != n) {
            println("ERROR short read " + got + " of " + n);
            return;
        }
        // Use the PROJECT FILE name, not currentProgram.getName(). Several of these were
        // imported as "..._clean_..." and renamed in the project tree afterwards; the Program
        // object keeps the name it was created with, so the two disagree.
        String fileName = currentProgram.getDomainFile() != null
                ? currentProgram.getDomainFile().getName()
                : currentProgram.getName();
        println("domainFile=" + fileName + " programName=" + currentProgram.getName());
        File out = new File(outDir, fileName);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(buf);
        }
        println("WROTE " + out.getAbsolutePath() + " bytes=" + n);
    }
}
