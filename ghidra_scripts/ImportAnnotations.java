// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Re-apply annotations exported by ExportAnnotations.java to a freshly imported program.
//
// The other half of the language-version round trip. Import the raw image again, re-run the
// setup/seed pipeline, then point this at the JSON to get the names, comments, labels and
// prototypes back.
//
// DRY RUN BY DEFAULT -- pass "apply" as the second argument to actually write. The dry run
// prints exactly what would happen, including every collision and every miss, so you can see
// what a re-pipe cost you before committing to it.
//
// THREE OUTCOMES PER ITEM, and the middle one is the interesting one:
//
//   exact    the address still holds the same kind of thing; applied verbatim.
//   rehomed  no function starts at the recorded entry, but one CONTAINS it -- so the
//            annotation is applied to that function's real entry instead, with a
//            "[entry corrected: <old>]" line prepended to its plate comment so the move is
//            never silent. This is the normal outcome when the export came from a program
//            seeded by an older SeedFunctions: the fixed seeder puts the entry one or more
//            words EARLIER, so the old address now lands inside the body.
//   missing  nothing at or around the address. Reported, never invented, unless you pass
//            "create" (third argument), which disassembles and creates a function first.
//
// NEVER CLOBBERS. A name already set by hand is left alone and reported as a collision --
// re-running an import must not overwrite work done since the export. Comments are only
// written where there is no comment already, for the same reason. Both are safe to re-run.
//
// TWO NAMES ONTO ONE FUNCTION is a real case, not an error: if the export came from a
// program where an offcut twin had also been named by hand, both records rehome to the same
// entry. The second one is attached as a secondary LABEL plus a note in the plate comment,
// so nothing is lost and the conflict is visible for a human to resolve.
//
// DATA TYPES. Records naming a user-defined type only apply if that type already exists in
// the program -- import the .gdt archive first. Unresolved types are counted and listed.
//
// USAGE. ImportAnnotations <annotations.json> [apply] [create]
//
// @category Annotations
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class ImportAnnotations extends GhidraScript {

    private boolean apply, create;
    private Listing listing;
    private FunctionManager fm;
    private SymbolTable st;

    // per-category tallies
    private int fnExact, fnRehomed, fnMissing, fnCollide, fnSecondary;
    private int cmtSet, cmtKept, cmtMissing;
    private int lblSet, lblPresent;
    private int dataNamed, dataTyped, dataUnresolved, dataMissing;
    private int sigOk, sigFailed;
    private int varOk, varSkipped;
    private int bmSet;
    private final List<String> notes = new ArrayList<>();
    private final Set<Long> claimedEntries = new HashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args[0].isBlank()) {
            println("usage: ImportAnnotations <annotations.json> [apply] [create]");
            return;
        }
        for (int i = 1; i < args.length; i++) {
            if ("apply".equalsIgnoreCase(args[i])) apply = true;
            if ("create".equalsIgnoreCase(args[i])) create = true;
        }
        listing = currentProgram.getListing();
        fm = currentProgram.getFunctionManager();
        st = currentProgram.getSymbolTable();

        JsonObject root;
        try (Reader r = new InputStreamReader(Files.newInputStream(Paths.get(args[0])),
                                              StandardCharsets.UTF_8)) {
            root = JsonParser.parseReader(r).getAsJsonObject();
        }

        JsonObject hdr = root.getAsJsonObject("program");
        println("source program : " + str(hdr, "name") + "  (" + str(hdr, "path") + ")");
        println("source language: " + str(hdr, "languageId") + " v" + str(hdr, "languageVersion"));
        println("target program : " + currentProgram.getName() + "  ("
            + currentProgram.getLanguageID().getIdAsString() + " v"
            + currentProgram.getLanguage().getVersion() + "."
            + currentProgram.getLanguage().getMinorVersion() + ")");
        String srcBase = str(hdr, "imageBase");
        String dstBase = currentProgram.getImageBase().toString();
        if (srcBase != null && !srcBase.equals(dstBase))
            println("  !! IMAGE BASE DIFFERS: export " + srcBase + " vs target " + dstBase
                + " -- every address below will be wrong. Set the base first.");
        if (!apply) println("*** DRY RUN -- pass \"apply\" to write ***");
        println("");

        applyFunctions(root.getAsJsonArray("functions"));
        applyLabels(root.getAsJsonArray("labels"));
        applyData(root.getAsJsonArray("data"));
        applyComments(root.getAsJsonArray("comments"));
        applyBookmarks(root.getAsJsonArray("bookmarks"));

        JsonArray dts = root.getAsJsonArray("dataTypes");
        if (dts != null && dts.size() > 0)
            println("source had " + dts.size() + " user data type(s); import the .gdt archive "
                + "separately if any are unresolved below.");

        println("");
        println("functions : exact " + fnExact + ", rehomed " + fnRehomed + ", collided " + fnCollide
            + ", secondary-label " + fnSecondary + ", MISSING " + fnMissing);
        println("signatures: restored " + sigOk + ", unparseable " + sigFailed);
        println("variables : renamed " + varOk + ", skipped " + varSkipped);
        println("comments  : set " + cmtSet + ", kept existing " + cmtKept + ", no code unit " + cmtMissing);
        println("labels    : created " + lblSet + ", already present " + lblPresent);
        println("data      : named " + dataNamed + ", typed " + dataTyped
            + ", type unresolved " + dataUnresolved + ", no data at addr " + dataMissing);
        println("bookmarks : " + bmSet);
        if (!notes.isEmpty()) {
            println("");
            println("--- items needing a human ---");
            for (String n : notes) println("  " + n);
        }
        if (!apply) println("\n*** DRY RUN -- nothing was written ***");
    }

    // ---------------------------------------------------------------- functions
    private void applyFunctions(JsonArray arr) {
        if (arr == null) return;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            Address want = addr(str(o, "entry"));
            if (want == null) { fnMissing++; continue; }
            String name = str(o, "name");
            boolean named = !"DEFAULT".equals(str(o, "source"));

            Function f = fm.getFunctionAt(want);
            String provenance = null;
            if (f == null) {
                Function host = fm.getFunctionContaining(want);
                if (host != null) {
                    f = host;
                    provenance = "[entry corrected: " + want + " -> " + host.getEntryPoint() + "]";
                    fnRehomed++;
                } else if (create) {
                    if (apply) {
                        new DisassembleCommand(want, null, true).applyTo(currentProgram, monitor);
                        new CreateFunctionCmd(want).applyTo(currentProgram, monitor);
                    }
                    f = fm.getFunctionAt(want);
                    if (f == null) { fnMissing++; note("MISSING (create failed) " + want + "  " + name); continue; }
                    fnExact++;
                } else {
                    fnMissing++;
                    note("MISSING function " + want + "  " + name);
                    continue;
                }
            } else {
                fnExact++;
            }

            long key = f.getEntryPoint().getOffset();
            boolean alreadyClaimed = !claimedEntries.add(key);

            if (named && name != null) {
                Symbol s = f.getSymbol();
                boolean targetNamed = s != null && s.getSource() != SourceType.DEFAULT;
                if (targetNamed && !name.equals(f.getName())) {
                    // Something already named this function. Never overwrite: attach the
                    // exported name as a secondary label so both survive, and say so.
                    fnCollide++;
                    fnSecondary++;
                    note("COLLISION @" + f.getEntryPoint() + ": target is \"" + f.getName()
                        + "\", export says \"" + name + "\" -> kept target, added label");
                    if (apply) tryLabel(f.getEntryPoint(), name);
                    appendPlate(f, "ALTERNATE NAME: " + name
                        + (alreadyClaimed ? " (a second exported record rehomed onto this entry)" : ""));
                } else if (!targetNamed) {
                    if (apply) {
                        try { f.setName(name, SourceType.USER_DEFINED); }
                        catch (Exception e) { note("rename failed @" + f.getEntryPoint() + ": " + e.getMessage()); }
                    }
                }
            }

            String plate = str(o, "plate");
            if (plate != null) {
                String text = provenance == null ? plate : provenance + "\n" + plate;
                setPlate(f, text);
            } else if (provenance != null) {
                appendPlate(f, provenance);
            }
            String rep = str(o, "repeatable");
            if (rep != null && apply && f.getRepeatableComment() == null) f.setRepeatableComment(rep);

            if (o.has("noReturn") && o.get("noReturn").getAsBoolean() && apply && !f.hasNoReturn())
                f.setNoReturn(true);

            if (o.has("tags")) for (JsonElement t : o.getAsJsonArray("tags"))
                if (apply) try { f.addTag(t.getAsString()); } catch (Exception ignored) {}

            if (!"DEFAULT".equals(str(o, "signatureSource"))) restoreSignature(f, str(o, "prototype"));
            if (o.has("vars")) restoreVars(f, o.getAsJsonArray("vars"));
        }
    }

    private void restoreSignature(Function f, String proto) {
        if (proto == null) return;
        if (!apply) { sigOk++; return; }
        try {
            FunctionSignatureParser p =
                new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
            ghidra.program.model.data.FunctionDefinitionDataType sig =
                (ghidra.program.model.data.FunctionDefinitionDataType) p.parse(null, proto);
            new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                f.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
            sigOk++;
        } catch (Exception e) {
            sigFailed++;
            note("signature not restored @" + f.getEntryPoint() + ": " + proto);
        }
    }

    private void restoreVars(Function f, JsonArray vars) {
        Map<String, Variable> byStorage = new HashMap<>();
        for (Variable v : f.getAllVariables()) byStorage.put(v.getVariableStorage().toString(), v);
        for (JsonElement el : vars) {
            JsonObject o = el.getAsJsonObject();
            Variable v = byStorage.get(str(o, "storage"));
            String nm = str(o, "name");
            if (v == null || nm == null) { varSkipped++; continue; }
            if (v.getSource() != SourceType.DEFAULT) { varSkipped++; continue; }
            if (apply) {
                try {
                    v.setName(nm, SourceType.USER_DEFINED);
                    DataType dt = resolveType(str(o, "type"));
                    if (dt != null) v.setDataType(dt, SourceType.USER_DEFINED);
                    String c = str(o, "comment");
                    if (c != null) v.setComment(c);
                } catch (Exception e) { varSkipped++; continue; }
            }
            varOk++;
        }
    }

    // ---------------------------------------------------------------- labels
    private void applyLabels(JsonArray arr) {
        if (arr == null) return;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            Address a = addr(str(o, "addr"));
            String nm = str(o, "name");
            if (a == null || nm == null) continue;
            boolean present = false;
            for (Symbol s : st.getSymbols(a)) if (nm.equals(s.getName())) { present = true; break; }
            if (present) { lblPresent++; continue; }
            if (apply) tryLabel(a, nm);
            lblSet++;
        }
    }

    private void tryLabel(Address a, String nm) {
        try { st.createLabel(a, nm, SourceType.USER_DEFINED); }
        catch (Exception e) { note("label failed @" + a + " " + nm + ": " + e.getMessage()); }
    }

    // ---------------------------------------------------------------- data
    private void applyData(JsonArray arr) {
        if (arr == null) return;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            Address a = addr(str(o, "addr"));
            if (a == null) continue;
            String nm = str(o, "name");
            if (nm != null) {
                boolean present = false;
                for (Symbol s : st.getSymbols(a)) if (nm.equals(s.getName())) { present = true; break; }
                if (!present) { if (apply) tryLabel(a, nm); dataNamed++; }
            }
            String typeName = str(o, "type");
            if (typeName == null) continue;
            DataType dt = resolveType(typeName);
            if (dt == null) { dataUnresolved++; note("type not found: " + typeName + " @" + a); continue; }
            if (listing.getDataAt(a) == null) { dataMissing++; continue; }
            if (apply) {
                try {
                    listing.clearCodeUnits(a, a.add(Math.max(0, dt.getLength() - 1)), false);
                    listing.createData(a, dt);
                } catch (Exception e) { note("data type failed @" + a + ": " + e.getMessage()); continue; }
            }
            dataTyped++;
        }
    }

    // Resolve a type by the path string ExportAnnotations wrote. Four steps, because a
    // program's own type manager is not the only place a type can live:
    //   1. the program's DTM -- user structs/enums and anything already applied;
    //   2. the BUILT-IN manager -- a builtin the program has never used is absent from (1),
    //      which is why "/float4" comes back null on a freshly imported program;
    //   3. bare-name search in both, for a type that moved category;
    //   4. an "X[N]" suffix -- arrays are not registered under a path at all, so the element
    //      type is resolved and the array rebuilt.
    private DataType resolveType(String path) {
        if (path == null) return null;
        DataType dt = lookupType(path);
        if (dt != null) return dt;

        int slash = path.lastIndexOf('/');
        String bare = slash >= 0 ? path.substring(slash + 1) : path;

        int lb = bare.lastIndexOf('[');
        if (lb > 0 && bare.endsWith("]")) {
            String elemName = bare.substring(0, lb);
            String countStr = bare.substring(lb + 1, bare.length() - 1);
            try {
                int count = Integer.parseInt(countStr.trim());
                DataType elem = lookupType(elemName);
                if (elem == null) elem = lookupType("/" + elemName);
                if (elem != null && count > 0)
                    return new ArrayDataType(elem, count, elem.getLength());
            } catch (NumberFormatException ignored) { }
        }
        return lookupType(bare);
    }

    private DataType lookupType(String name) {
        String path = name.startsWith("/") ? name : "/" + name;
        String bare = name.startsWith("/") ? name.substring(1) : name;

        DataType dt = currentProgram.getDataTypeManager().getDataType(path);
        if (dt != null) return dt;

        DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        dt = builtIn.getDataType(path);
        if (dt != null) return dt;

        List<DataType> hits = new ArrayList<>();
        currentProgram.getDataTypeManager().findDataTypes(bare, hits);
        if (!hits.isEmpty()) return hits.get(0);
        hits.clear();
        builtIn.findDataTypes(bare, hits);
        return hits.isEmpty() ? null : hits.get(0);
    }

    // ---------------------------------------------------------------- comments
    private void applyComments(JsonArray arr) {
        if (arr == null) return;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            Address a = addr(str(o, "addr"));
            String text = str(o, "text");
            if (a == null || text == null) continue;
            CommentType ct;
            try { ct = CommentType.valueOf(str(o, "type")); }
            catch (Exception e) { continue; }
            if (listing.getCodeUnitContaining(a) == null) { cmtMissing++; continue; }
            String have = listing.getComment(ct, a);
            if (have != null && !have.isEmpty()) {
                if (!have.contains(text)) cmtKept++;
                continue;
            }
            if (apply) listing.setComment(a, ct, text);
            cmtSet++;
        }
    }

    // ---------------------------------------------------------------- bookmarks
    private void applyBookmarks(JsonArray arr) {
        if (arr == null) return;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            Address a = addr(str(o, "addr"));
            if (a == null) continue;
            if (apply) currentProgram.getBookmarkManager().setBookmark(
                a, str(o, "type"), str(o, "category"), str(o, "comment"));
            bmSet++;
        }
    }

    // ---------------------------------------------------------------- helpers
    private void setPlate(Function f, String text) {
        String have = f.getComment();
        if (have != null && have.contains(text)) return;
        if (have != null && !have.isEmpty()) { appendPlate(f, text); return; }
        if (apply) f.setComment(text);
    }

    private void appendPlate(Function f, String line) {
        String have = f.getComment();
        if (have != null && have.contains(line)) return;
        if (apply) f.setComment(have == null || have.isEmpty() ? line : have + "\n" + line);
    }

    private void note(String s) { if (notes.size() < 200) notes.add(s); }

    private String str(JsonObject o, String k) {
        if (o == null || !o.has(k) || o.get(k).isJsonNull()) return null;
        return o.get(k).getAsString();
    }

    private Address addr(String s) {
        if (s == null) return null;
        try { return currentProgram.getAddressFactory().getAddress(s); }
        catch (Exception e) { return null; }
    }
}
