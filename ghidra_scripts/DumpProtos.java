// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
//
// Dump the cspec's storage decisions for a fixed set of ABI probe signatures,
// so a regression harness can diff them against the SPRU514 / SPRAC71 truth.
//
// This script does NOT trust function-body analysis. It calls
// PrototypeModel.getStorageLocations() directly with concrete DataType[]
// arrays -- exactly the mechanism Ghidra uses when it lays out a function
// whose C signature is known -- so the output is a pure test of the .cspec.
//
// Output format (one line per test), stable and diffable:
//    NAME: return=<storage> ; params=[<storage>, <storage>, ...]
// where <storage> is either "<reg>" (name of the register file view) or the
// VariableStorage.toString() form for stack / hidden / joined cases.
//
// @category TMS320C28x
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.VariableStorage;

import java.util.ArrayList;
import java.util.List;

public class DumpProtos extends GhidraScript {

    // Convenience: the exact-size signed types the C28x cspec produces for the
    // C small-integer types on this target (integer_size=2, long_size=4,
    // long_long_size=8, pointer_size=4).
    private DataType i16, i32, i64, f32, ptr;

    // Small struct return probe -- 3-word struct, matches abi_ret_struct in the
    // fixture. Anything larger than a register triggers the "hidden ret ptr"
    // path per the cspec.
    private DataType s3;

    @Override
    protected void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CompilerSpec cs = currentProgram.getCompilerSpec();
        PrototypeModel model = cs.getDefaultCallingConvention();

        // Use exact-size types -- NOT ShortDataType/IntegerDataType/LongDataType,
        // whose widths track the target's data_organization (int=2 on C28x!).
        // getSignedDataType(N, dtm) returns a signed integer of exactly N bytes.
        i16 = AbstractIntegerDataType.getSignedDataType(2, dtm);
        i32 = AbstractIntegerDataType.getSignedDataType(4, dtm);
        i64 = AbstractIntegerDataType.getSignedDataType(8, dtm);
        f32 = AbstractFloatDataType.getFloatDataType(4, dtm);
        ptr = dtm.getPointer(i16); // int* -- pointer_size=4 in the cspec, size follows from the DTM

        // Small aggregate: 3 x int16 = 6 bytes -> bigger than any register.
        StructureDataType s = new StructureDataType("S3", 0, dtm);
        s.add(i16, "a", null);
        s.add(i16, "b", null);
        s.add(i16, "c", null);
        s3 = s;

        println("=== DUMPPROTOS ===");
        // Emit each probe result as its OWN println so Ghidra's headless output
        // prefixes every line with "DumpProtos.java> " -- the harness filter
        // relies on the prefix to reject interleaved INFO / WARN lines.

        // --- argument passing probes -----------------------------------------
        probe(model, "abi_int1",         i16, new DataType[]{i16});
        probe(model, "abi_int2",         i16, new DataType[]{i16, i16});
        probe(model, "abi_int3",         i16, new DataType[]{i16, i16, i16});
        probe(model, "abi_int4",         i16, new DataType[]{i16, i16, i16, i16});
        probe(model, "abi_long_int",     i32, new DataType[]{i32, i16});
        probe(model, "abi_ptrs",         i16, new DataType[]{ptr, ptr});
        probe(model, "abi_ptr_int",      i16, new DataType[]{ptr, i16});
        probe(model, "abi_float4",       f32, new DataType[]{f32, f32, f32, f32});
        probe(model, "abi_float_int",    f32, new DataType[]{f32, i16});
        probe(model, "abi_longlong_int", i64, new DataType[]{i64, i16});
        probe(model, "abi_spec_example", i32, new DataType[]{i32, i64, i16, ptr});
        probe(model, "abi_vararg_3",     i16, new DataType[]{i16, i16, i16});

        // SPRU rule-f cross-class reservation. Compiler-truth for this signature
        // is (AR4, AR5, AH:AL) -- `long c` claims ACC first (class 5), which
        // forces the two 16-bit ints out of AL/AH into XAR4/XAR5. Ghidra's
        // declaration-order pentry model can't express that pre-emption; this
        // probe records what the cspec DOES produce, as a regression floor.
        probe(model, "abi_int_int_long", i32, new DataType[]{i16, i16, i32});

        // --- return-value probes ---------------------------------------------
        probe(model, "abi_ret_i16",      i16, new DataType[]{});
        probe(model, "abi_ret_i32",      i32, new DataType[]{});
        probe(model, "abi_ret_i64",      i64, new DataType[]{});
        probe(model, "abi_ret_ptr",      ptr, new DataType[]{});
        probe(model, "abi_ret_float",    f32, new DataType[]{});
        probe(model, "abi_ret_struct",   s3,  new DataType[]{});

        println("=== END ===");
    }

    /**
     * Ask the cspec where <ret fn(params...)> would place its return and each
     * parameter, print a diffable line. Auto-injected slots (this / hidden
     * struct-return pointer) are surfaced with an "AUTO(...)" tag so a diff
     * catches them appearing or disappearing.
     */
    private void probe(PrototypeModel model, String name,
                       DataType retType, DataType[] paramTypes) {
        DataType[] types = new DataType[paramTypes.length + 1];
        types[0] = retType;
        System.arraycopy(paramTypes, 0, types, 1, paramTypes.length);

        VariableStorage[] locs = model.getStorageLocations(currentProgram, types, true);
        // locs[0] = return; locs[1..] = params, with auto-params (hidden ret
        // ptr / this) injected before user params if applicable.
        String ret = fmt(locs[0]);
        List<String> ps = new ArrayList<>();
        for (int i = 1; i < locs.length; i++) ps.add(fmt(locs[i]));

        println(String.format("%-20s return=%-20s params=%s", name, ret, ps));
    }

    /**
     * Render VariableStorage as a short stable string:
     *   XAR4              (single register)
     *   AH:AL             (join of two registers -- printed high:low)
     *   Stack[+2]:2       (stack slot with size)
     *   AUTO(<hidden>)    (hidden ret pointer / this)
     * Falls back to VariableStorage.toString() for anything unusual so we don't
     * silently paper over a case.
     */
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
            // e.g. ACC:P -- print constituent registers high-to-low
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
