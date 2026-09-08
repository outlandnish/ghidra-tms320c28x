// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Print the whole project tree (folders + program files) once, regardless of how many
// programs the headless run iterates over. Read-only.
//
// USAGE. ListProjectTree [prefixFilter]
//   prefixFilter: optional project path prefix, e.g. /tesla -- only that subtree is printed.
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;

public class ListProjectTree extends GhidraScript {

    // The headless runner invokes the script once per processed program; the tree does not
    // change between those calls, so print it on the first one only.
    private static boolean printed = false;

    @Override
    public void run() throws Exception {
        if (printed) {
            return;
        }
        printed = true;
        String[] args = getScriptArgs();
        String prefix = args.length > 0 ? args[0] : "/";
        walk(getProjectRootFolder().getProjectData().getRootFolder(), prefix);
        println("TREE DONE");
    }

    private void walk(DomainFolder dir, String prefix) {
        String p = dir.getPathname();
        // Print a folder when it is inside the requested subtree, or on the path down to it.
        if (p.startsWith(prefix) || prefix.startsWith(p)) {
            DomainFile[] files = dir.getFiles();
            if (p.startsWith(prefix)) {
                println(String.format("DIR  %-58s files=%d subdirs=%d",
                        p, files.length, dir.getFolders().length));
                for (DomainFile f : files) {
                    println(String.format("FILE %s|%s|%s", p, f.getName(), f.getContentType()));
                }
            }
            for (DomainFolder sub : dir.getFolders()) {
                walk(sub, prefix);
            }
        }
    }
}
