// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Extract every initialized memory block from an analyzed program as a flat
// bytes file + a word-address index, so the fw-parity BOOTSTRAP sweep can
// address materialized-RAM (`.ramfunc`) code the same way it addresses flash.
//
// WHY. The raw firmware `.bin` only contains flash. Ramfuncs live at RAM run
// addresses that are only populated after MaterializeSections /
// MaterializeCopyTable copy them out of the flash load image (RAW case), or
// LZSS-decompress them (compressed case). BFS starting from a CRT seed follows
// LCR call targets into RAM run addresses; the flash-only mode filters those
// out as out-of-range and never covers a single ramfunc.
//
// The dump has two files:
//   image.bin      -- concatenated bytes of every initialized block (flash +
//                     materialized RAM), in the block order returned by
//                     Memory.getBlocks(). Byte order matches memory.
//   image_map.tsv  -- one row per block:
//                     `<word_start_hex>\t<len_words_dec>\t<byte_offset_dec>\t<block_name>`
//
// The orchestrator maps a word address to a byte offset in image.bin by scanning
// the map for the block containing it. This is a small linear scan (usually
// <20 blocks) and doesn't merit a binary search.
//
// Output paths from `-Dc28x.parity.image.bytes=<path>` and
// `-Dc28x.parity.image.map=<path>`; defaults `image.bin` and `image_map.tsv` in
// cwd. Also readable via -D script args (same fallback as DumpFwParitySeeds).
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileOutputStream;
import java.io.FileWriter;

public class DumpFwParityImage extends GhidraScript {

    @Override
    public void run() throws Exception {
        String bytesOut = getProp("c28x.parity.image.bytes", "image.bin");
        String mapOut   = getProp("c28x.parity.image.map",   "image_map.tsv");

        StringBuilder map = new StringBuilder();
        map.append("# word_start\tlen_words\tbyte_offset\tblock_name\n");
        int totalBytes = 0, blocks = 0;
        try (FileOutputStream fos = new FileOutputStream(bytesOut)) {
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                if (!b.isInitialized()) continue;
                long lenBytes = b.getSize();
                if (lenBytes <= 0) continue;
                // Read block in chunks; a single 8MB+ .setBytes read has been
                // observed to trip Ghidra's paging on large flash blocks.
                Address a = b.getStart();
                long remaining = lenBytes;
                int byteOff = totalBytes;
                while (remaining > 0) {
                    int chunk = (int) Math.min(remaining, 1 << 16);
                    byte[] buf = new byte[chunk];
                    b.getBytes(a, buf);
                    fos.write(buf);
                    remaining -= chunk;
                    a = a.add(chunk);
                    totalBytes += chunk;
                }
                long wordStart = b.getStart().getOffset() / 2;
                long lenWords  = lenBytes / 2;
                map.append(String.format("0x%x\t%d\t%d\t%s%n",
                    wordStart, lenWords, byteOff, b.getName()));
                blocks++;
            }
        }
        try (FileWriter fw = new FileWriter(mapOut)) { fw.write(map.toString()); }
        println(String.format("DumpFwParityImage: %d blocks, %d bytes -> %s (+ %s)",
            blocks, totalBytes, bytesOut, mapOut));
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
