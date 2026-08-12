// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Dump the SPRU-priority allocator's storage decisions for the same ABI probe
// signatures DumpProtos.java uses -- so tests/run_abi_analyzer_check.sh can
// diff them against SPRU-truth after any allocator change.
//
// This exercises TMS320C28xAbiAllocator directly rather than going through
// Function.updateFunction, matching how DumpProtos calls PrototypeModel
// directly rather than through Function analysis. Both are unit-style probes.
//
// Output format (one line per test), stable and diffable:
//    NAME: params=[<storage>, <storage>, ...]
// where <storage> is the same rendering used by DumpProtos.
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.plugin.core.analysis.TMS320C28xAbiAllocator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.VariableStorage;

import java.util.ArrayList;
import java.util.List;

public class DumpAbiAnalyzer extends GhidraScript {

    private DataType i16, i32, i64, f32, ptr;

    @Override
    protected void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        i16 = AbstractIntegerDataType.getSignedDataType(2, dtm);
        i32 = AbstractIntegerDataType.getSignedDataType(4, dtm);
        i64 = AbstractIntegerDataType.getSignedDataType(8, dtm);
        f32 = AbstractFloatDataType.getFloatDataType(4, dtm);
        ptr = dtm.getPointer(i16);

        println("=== DUMPABIANALYZER ===");

        probe("abi_int1",         new DataType[]{i16});
        probe("abi_int2",         new DataType[]{i16, i16});
        probe("abi_int3",         new DataType[]{i16, i16, i16});
        probe("abi_int4",         new DataType[]{i16, i16, i16, i16});
        probe("abi_long_int",     new DataType[]{i32, i16});
        probe("abi_ptrs",         new DataType[]{ptr, ptr});
        probe("abi_ptr_int",      new DataType[]{ptr, i16});
        probe("abi_float4",       new DataType[]{f32, f32, f32, f32});
        probe("abi_float_int",    new DataType[]{f32, i16});
        probe("abi_longlong_int", new DataType[]{i64, i16});
        probe("abi_spec_example", new DataType[]{i32, i64, i16, ptr});

        // The two SPRU cross-class-reservation cases this analyzer exists to fix.
        probe("abi_int_int_long", new DataType[]{i16, i16, i32});

        println("=== END ===");
    }

    private void probe(String name, DataType[] paramTypes) {
        VariableStorage[] locs;
        try {
            locs = TMS320C28xAbiAllocator.computeParamStorage(currentProgram, paramTypes);
        }
        catch (Exception e) {
            println(String.format("%-20s ERROR %s", name, e.getMessage()));
            return;
        }
        List<String> ps = new ArrayList<>();
        for (VariableStorage vs : locs) {
            ps.add(fmt(vs));
        }
        println(String.format("%-20s params=%s", name, ps));
    }

    // Kept identical to DumpProtos.fmt() so the two harnesses render storage
    // the same way -- makes diffing between them straightforward.
    private String fmt(VariableStorage vs) {
        if (vs == null || vs.isUnassignedStorage() || vs.isBadStorage()) {
            return String.valueOf(vs);
        }
        StringBuilder sb = new StringBuilder();
        if (vs.isAutoStorage()) {
            sb.append("AUTO(");
        }
        if (vs.isRegisterStorage()) {
            sb.append(vs.getRegister().getName());
        } else if (vs.isCompoundStorage()) {
            var varnodes = vs.getVarnodes();
            for (int i = 0; i < varnodes.length; i++) {
                if (i > 0) sb.append(":");
                var reg = currentProgram.getRegister(varnodes[i]);
                sb.append(reg != null ? reg.getName() : varnodes[i].toString());
            }
        } else if (vs.isStackStorage()) {
            sb.append(String.format("Stack[%+d]:%d", vs.getStackOffset(), vs.size()));
        } else {
            sb.append(vs.toString());
        }
        if (vs.isAutoStorage()) sb.append(")");
        return sb.toString();
    }
}
