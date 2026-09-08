// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Rename named programs in the project. DRY RUN BY DEFAULT.
//
// Why this exists: a re-import lands the new program at the SAME folder and name as the one it
// supersedes whenever the previous migration already fixed the naming. Headless would then
// -overwrite the old program -- destroying the analysis before it can be merged onto the new
// one. Renaming the old programs aside first keeps both, so Phase 4 has something to merge from.
//
// Like DeleteOldPrograms, this is deliberately NOT a pattern matcher: it renames only what is
// listed verbatim, so the change is reviewable before and auditable after.
//
// USAGE. RenamePrograms <listFile> [apply]
//   listFile: one "projectPath|newName" per line, e.g.
//             /2020.8.1_12603_26-65-2/dir_26-65-2_single_0x00082000.bin|dir_..._0x00082000.bin__pre115
//             blank lines and lines starting with '#' are ignored.
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public class RenamePrograms extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: RenamePrograms <listFile> [apply]");
            return;
        }
        boolean apply = args.length > 1 && "apply".equalsIgnoreCase(args[1]);
        List<String> lines = Files.readAllLines(new File(args[0]).toPath(), StandardCharsets.UTF_8);

        int renamed = 0, missing = 0, failed = 0, already = 0;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int bar = line.lastIndexOf('|');
            if (bar < 0) {
                println("BAD LINE (no '|') " + line);
                failed++;
                continue;
            }
            String path = line.substring(0, bar).trim();
            String newName = line.substring(bar + 1).trim();

            DomainFile f = getProjectRootFolder().getProjectData().getFile(path);
            if (f == null) {
                // Already renamed by an earlier run is not an error -- report it as such so a
                // re-run of this script is idempotent rather than alarming.
                DomainFile at = getProjectRootFolder().getProjectData()
                        .getFile(path.substring(0, path.lastIndexOf('/') + 1) + newName);
                if (at != null) {
                    println("already   " + path + "  ->  " + newName);
                    already++;
                } else {
                    println("MISSING   " + path);
                    missing++;
                }
                continue;
            }
            if (f.isOpen()) {
                println("SKIP (open) " + path);
                failed++;
                continue;
            }
            if (!apply) {
                println("would rename  " + path + "  ->  " + newName);
                renamed++;
                continue;
            }
            try {
                f.setName(newName);
                println("renamed   " + path + "  ->  " + newName);
                renamed++;
            } catch (Exception e) {
                println("FAILED    " + path + " : " + e.getMessage());
                failed++;
            }
        }
        println(String.format("%s: %d renamed, %d already, %d missing, %d failed",
                apply ? "APPLIED" : "DRY RUN", renamed, already, missing, failed));
    }
}
