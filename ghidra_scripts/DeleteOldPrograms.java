// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Delete named programs (and then-empty folders) from the project. DRY RUN BY DEFAULT.
//
// Deliberately NOT a pattern matcher: it deletes only paths listed verbatim in a file, one per
// line, so what gets removed is reviewable before and auditable after. A path that does not
// resolve is reported and skipped, never guessed at.
//
// USAGE. DeleteOldPrograms <listFile> [apply]
//   listFile: one project path per line, e.g. /12603_gen26/dir_26_65_2_swapped_0x00082000.bin
//             blank lines and lines starting with '#' are ignored.
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DeleteOldPrograms extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: DeleteOldPrograms <listFile> [apply]");
            return;
        }
        boolean apply = args.length > 1 && "apply".equalsIgnoreCase(args[1]);
        List<String> lines = Files.readAllLines(new File(args[0]).toPath(), StandardCharsets.UTF_8);

        int deleted = 0, missing = 0, failed = 0;
        Set<String> parents = new LinkedHashSet<>();
        for (String raw : lines) {
            String path = raw.trim();
            if (path.isEmpty() || path.startsWith("#")) {
                continue;
            }
            DomainFile f = getProjectRootFolder().getProjectData().getFile(path);
            if (f == null) {
                println("MISSING  " + path);
                missing++;
                continue;
            }
            if (f.isOpen()) {
                println("SKIP (open) " + path);
                failed++;
                continue;
            }
            parents.add(f.getParent().getPathname());
            if (!apply) {
                println("would delete  " + path);
                deleted++;
                continue;
            }
            try {
                f.delete();
                println("deleted  " + path);
                deleted++;
            } catch (Exception e) {
                println("FAILED   " + path + " : " + e.getMessage());
                failed++;
            }
        }

        // Remove folders the deletions emptied -- never a folder that still holds anything.
        int folders = 0;
        for (String p : parents) {
            DomainFolder d = getProjectRootFolder().getProjectData().getFolder(p);
            if (d == null || d.getFiles().length > 0 || d.getFolders().length > 0) {
                continue;
            }
            if (!apply) {
                println("would remove empty folder  " + p);
                folders++;
                continue;
            }
            try {
                d.delete();
                println("removed empty folder  " + p);
                folders++;
            } catch (Exception e) {
                println("FAILED folder " + p + " : " + e.getMessage());
            }
        }
        println(String.format("%s: %d program(s), %d empty folder(s), %d missing, %d failed",
                apply ? "DELETED" : "DRY RUN", deleted, folders, missing, failed));
    }
}
