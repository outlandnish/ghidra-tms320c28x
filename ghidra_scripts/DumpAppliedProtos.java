// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Dump SPRU-priority storage as it looks after Ghidra's real signature-application
// path: construct a FunctionDefinitionDataType for each fixture, apply it to the
// matching function via ApplyFunctionSignatureCmd, then run
// TMS320C28xAbiAnalyzer.added() on that function's body and dump the resulting
// return + parameter storage.
//
// This is the end-to-end complement to DumpAbiAnalyzer.java (which unit-tests the
// pure allocator) and DumpProtos.java (which unit-tests the cspec via
// PrototypeModel.getStorageLocations). Only this path can exercise:
//   - varargs -- FunctionSignature.setVarArgs(true) round-trips into
//     Function.hasVarArgs(), which the analyzer honors to force the last named
//     arg to the stack (SPRU §7.3.1 rule for va_list contiguity).
//   - hidden struct-return pointer -- ApplyFunctionSignatureCmd is the only path
//     that consults the cspec's <pentry storage="hiddenret"> for oversized returns.
//
// The analyzer is invoked explicitly (not left to headless analyzer scheduling)
// so the dump is deterministic and independent of AutoAnalysisManager ordering.
//
// Output format matches DumpAbiAnalyzer.java's shape (diffable):
//    NAME: return=<storage> ; params=[<storage>, ...]  (varargs=true when set)
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.TMS320C28xAbiAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class DumpAppliedProtos extends GhidraScript {

    private DataType i16, i32, i64, f32, ptr;
    private DataType s3;

    @Override
    protected void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        i16 = AbstractIntegerDataType.getSignedDataType(2, dtm);
        i32 = AbstractIntegerDataType.getSignedDataType(4, dtm);
        i64 = AbstractIntegerDataType.getSignedDataType(8, dtm);
        f32 = AbstractFloatDataType.getFloatDataType(4, dtm);
        ptr = dtm.getPointer(i16);

        StructureDataType s = new StructureDataType("S3", 0, dtm);
        s.add(i16, "a", null);
        s.add(i16, "b", null);
        s.add(i16, "c", null);
        s3 = s;

        TMS320C28xAbiAnalyzer analyzer = new TMS320C28xAbiAnalyzer();

        println("=== DUMPAPPLIEDPROTOS ===");

        // Argument-placement probes, mirrored from DumpAbiAnalyzer + DumpProtos.
        probe(analyzer, "abi_int1",         i16, dt(i16),                pn("a"),           false);
        probe(analyzer, "abi_int2",         i16, dt(i16, i16),           pn("a","b"),       false);
        probe(analyzer, "abi_int3",         i16, dt(i16, i16, i16),      pn("a","b","c"),   false);
        probe(analyzer, "abi_int4",         i16, dt(i16, i16, i16, i16), pn("a","b","c","d"), false);
        probe(analyzer, "abi_long_int",     i32, dt(i32, i16),           pn("a","b"),       false);
        probe(analyzer, "abi_ptrs",         i16, dt(ptr, ptr),           pn("p","q"),       false);
        probe(analyzer, "abi_ptr_int",      i16, dt(ptr, i16),           pn("p","a"),       false);
        probe(analyzer, "abi_float4",       f32, dt(f32, f32, f32, f32), pn("a","b","c","d"), false);
        probe(analyzer, "abi_float_int",    f32, dt(f32, i16),           pn("a","b"),       false);
        probe(analyzer, "abi_longlong_int", i64, dt(i64, i16),           pn("a","b"),       false);
        probe(analyzer, "abi_spec_example", i32, dt(i32, i64, i16, ptr), pn("a","b","c","d"), false);
        // NOTE: abi_int_int_long is deliberately absent -- the checked-in
        // abi_probe.obj predates that C source addition, so the symbol isn't
        // in the ELF. Its allocator behavior is already covered by
        // DumpAbiAnalyzer.java; regenerating the .obj is out of scope here.

        // The two cases that only this harness can exercise.
        probe(analyzer, "abi_vararg",       i16, dt(i16, i16, i16),      pn("a","b","c"),   true);
        probe(analyzer, "abi_ret_struct",   s3,  dt(),                   pn(),              false);

        println("=== END ===");
    }

    private static DataType[] dt(DataType... types) { return types; }
    private static String[] pn(String... names)      { return names; }

    /**
     * Look up the target function, apply the signature, kick the analyzer against
     * that function's body, and print the resulting storage.
     */
    private void probe(TMS320C28xAbiAnalyzer analyzer, String name, DataType ret,
                       DataType[] paramTypes, String[] paramNames, boolean varargs)
            throws Exception {
        Function fn = findFunction(name);
        if (fn == null) {
            println(String.format("%-20s FUNCTION_NOT_FOUND", name));
            return;
        }

        FunctionDefinitionDataType sig = new FunctionDefinitionDataType(name);
        sig.setReturnType(ret);
        ParameterDefinition[] pds = new ParameterDefinition[paramTypes.length];
        for (int i = 0; i < paramTypes.length; i++) {
            pds[i] = new ParameterDefinitionImpl(paramNames[i], paramTypes[i], null);
        }
        sig.setArguments(pds);
        if (varargs) {
            sig.setVarArgs(true);
        }

        ApplyFunctionSignatureCmd cmd =
            new ApplyFunctionSignatureCmd(fn.getEntryPoint(), sig, SourceType.USER_DEFINED);
        if (!cmd.applyTo(currentProgram)) {
            println(String.format("%-20s APPLY_FAILED %s", name, cmd.getStatusMsg()));
            return;
        }

        // Explicit analyzer invocation -- deterministic, not dependent on
        // AutoAnalysisManager scheduling in headless.
        analyzer.added(currentProgram, new AddressSet(fn.getBody()),
                       TaskMonitor.DUMMY, new MessageLog());

        // Re-fetch: updateFunction may have replaced the Function-backed object.
        fn = getFunctionAt(fn.getEntryPoint());
        VariableStorage retSt = fn.getReturn().getVariableStorage();
        Parameter[] params = fn.getParameters();

        List<String> ps = new ArrayList<>();
        for (Parameter p : params) {
            ps.add(fmt(p.getVariableStorage(), p.isAutoParameter()));
        }
        String tag = varargs ? " varargs=true" : "";
        println(String.format("%-20s return=%-20s params=%s%s",
            name, fmt(retSt, false), ps, tag));
    }

    private Function findFunction(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (name.equals(f.getName())) {
                return f;
            }
        }
        return null;
    }

    private String fmt(VariableStorage vs, boolean isAuto) {
        if (vs == null || vs.isUnassignedStorage() || vs.isBadStorage()) {
            return String.valueOf(vs);
        }
        StringBuilder sb = new StringBuilder();
        boolean auto = isAuto || vs.isAutoStorage();
        if (auto) sb.append("AUTO(");
        if (vs.isRegisterStorage()) {
            sb.append(vs.getRegister().getName());
        }
        else if (vs.isCompoundStorage()) {
            var varnodes = vs.getVarnodes();
            for (int i = 0; i < varnodes.length; i++) {
                if (i > 0) sb.append(":");
                var r = currentProgram.getRegister(varnodes[i]);
                sb.append(r != null ? r.getName() : varnodes[i].toString());
            }
        }
        else if (vs.isStackStorage()) {
            sb.append(String.format("Stack[%+d]:%d", vs.getStackOffset(), vs.size()));
        }
        else {
            sb.append(vs.toString());
        }
        if (auto) sb.append(")");
        return sb.toString();
    }
}
