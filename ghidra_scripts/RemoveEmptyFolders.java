// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Remove project folders left empty by a deletion pass. DRY RUN BY DEFAULT.
//
// Only ever removes a folder holding no files AND no subfolders, so nothing can be lost by it.
// Repeats until a pass removes nothing, which cleans nested empties bottom-up.
//
// Takes an explicit ALLOW LIST of folder paths (one per line, '#' comments ignored) so a
// cleanup only touches the folders THIS pass emptied. A project accumulates empty folders for
// all sorts of reasons; sweeping them all up is a decision for whoever owns the project, not a
// side effect of deleting programs.
//
// USAGE. RemoveEmptyFolders <listFile> [apply]
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RemoveEmptyFolders extends GhidraScript {

    private Set<String> allowed = new HashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR usage: RemoveEmptyFolders <listFile> [apply]");
            return;
        }
        for (String raw : Files.readAllLines(new File(args[0]).toPath(), StandardCharsets.UTF_8)) {
            String p = raw.trim();
            if (!p.isEmpty() && !p.startsWith("#")) {
                allowed.add(p);
            }
        }
        boolean apply = args.length > 1 && "apply".equalsIgnoreCase(args[1]);

        int total = 0;
        for (int round = 1; round <= 8; round++) {
            List<DomainFolder> empties = new ArrayList<>();
            collectEmpty(getProjectRootFolder(), empties);
            if (empties.isEmpty()) {
                break;
            }
            for (DomainFolder f : empties) {
                if (!apply) {
                    println("would remove  " + f.getPathname());
                    total++;
                    continue;
                }
                try {
                    String p = f.getPathname();
                    f.delete();
                    println("removed  " + p);
                    total++;
                } catch (Exception e) {
                    println("FAILED   " + f.getPathname() + " : " + e.getMessage());
                }
            }
            if (!apply) {
                break;      // a dry run cannot cascade, so one pass is all it can report
            }
        }
        println((apply ? "REMOVED " : "DRY RUN ") + total + " empty folder(s)");
    }

    private void collectEmpty(DomainFolder folder, List<DomainFolder> out) {
        for (DomainFolder sub : folder.getFolders()) {
            collectEmpty(sub, out);
            if (sub.getFiles().length == 0 && sub.getFolders().length == 0
                    && allowed.contains(sub.getPathname())) {
                out.add(sub);
            }
        }
    }
}
