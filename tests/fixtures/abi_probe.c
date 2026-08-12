/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Nishanth Samala
 *
 * ABI probe fixture -- one function per SPRU514 §7.3.1 argument-placement rule
 * plus a matching set of return-value probes for §7.3.2. Compile with:
 *
 *   cl2000 -v28 --abi=eabi --float_support=fpu32 -O0 -k \
 *          --gen_func_subsections=on -c abi_probe.c \
 *          -z --output_file=abi_probe.out
 *
 * -k keeps the .asm listing, which is used as the compiler-truth for what
 * register each argument actually lands in. The .out is loaded into Ghidra
 * headless by run_abi_check.sh, and DumpProtos.java prints Ghidra's inferred
 * parameter storage so we can diff against the spec.
 *
 * All prototypes are `noinline` so the compiler can't fold them away at -O0
 * (belt-and-braces -- -O0 already forbids inlining but this survives -O2 too).
 */

#pragma FUNC_CANNOT_INLINE (abi_int1)
#pragma FUNC_CANNOT_INLINE (abi_int2)
#pragma FUNC_CANNOT_INLINE (abi_int3)
#pragma FUNC_CANNOT_INLINE (abi_int4)
#pragma FUNC_CANNOT_INLINE (abi_long_int)
#pragma FUNC_CANNOT_INLINE (abi_ptrs)
#pragma FUNC_CANNOT_INLINE (abi_ptr_int)
#pragma FUNC_CANNOT_INLINE (abi_float4)
#pragma FUNC_CANNOT_INLINE (abi_float_int)
#pragma FUNC_CANNOT_INLINE (abi_longlong_int)
#pragma FUNC_CANNOT_INLINE (abi_spec_example)
#pragma FUNC_CANNOT_INLINE (abi_ret_i16)
#pragma FUNC_CANNOT_INLINE (abi_ret_i32)
#pragma FUNC_CANNOT_INLINE (abi_ret_i64)
#pragma FUNC_CANNOT_INLINE (abi_ret_ptr)
#pragma FUNC_CANNOT_INLINE (abi_ret_float)
#pragma FUNC_CANNOT_INLINE (abi_ret_struct)
#pragma FUNC_CANNOT_INLINE (abi_vararg)
#pragma FUNC_CANNOT_INLINE (abi_int_int_long)

/* Global sinks so the compiler must materialize each arg. */
volatile int          g_i16;
volatile long         g_i32;
volatile long long    g_i64;
volatile float        g_f32;
volatile int         *g_p;

/* Rule 7 -- 16-bit args land in AL, AH, XAR4, XAR5 (in that order). */
int  abi_int1(int a)                             { return a; }                 /* AL */
int  abi_int2(int a, int b)                      { g_i16 = a; return b; }      /* AL, AH */
int  abi_int3(int a, int b, int c)               { g_i16 = a+b; return c; }    /* AL, AH, XAR4 */
int  abi_int4(int a, int b, int c, int d)        { g_i16 = a+b+c; return d; }  /* AL, AH, XAR4, XAR5 */

/* Rule 5 vs 7 collision -- long a takes ACC (AH:AL), so int b must land in XAR4
 * (AL / AH unavailable). SPRU §7.3.1 example 2: `func1(long a, int b, long c)`
 * -> AH/AL, XAR4, stack. */
long abi_long_int(long a, int b)                 { g_i32 = a; return b; }

/* Rule 6 -- first two pointers in XAR4, XAR5. */
int  abi_ptrs(int *p, int *q)                    { *p = 1; return *q; }
int  abi_ptr_int(int *p, int a)                  { *p = a; return a; }         /* p=XAR4, a=AL */

/* Rule 2 -- first four floats in R0H..R3H. */
float abi_float4(float a, float b, float c, float d)   { return a+b+c+d; }
float abi_float_int(float a, int b)                    { g_i16 = b; return a; } /* a=R0H, b=AL */

/* Rule 4 -- first long long in ACC:P. Second int would then have AL/AH taken
 * (long long uses full ACC), so it must land in XAR4. */
long long abi_longlong_int(long long a, int b)   { g_i16 = b; return a; }

/* SPRU §7.3.1 named example: `func1(long a, long long b, int c, int* d)`
 * -> a=stack, b=ACC:P, c=XAR5, d=XAR4. Interesting because it forces every
 * class-priority rule at once. */
long abi_spec_example(long a, long long b, int c, int *d) {
    *d = c;
    g_i64 = b;
    return a;
}

/* SPRU §7.3.1 second example: `f(int a, int b, long c)` -> XAR4, XAR5, AH:AL.
 * Tests the CROSS-CLASS RESERVATION rule that Ghidra's pentry model can't
 * express: `long c` claims AH:AL first (class 5 priority), which forces the
 * two 16-bit ints out of AL/AH into XAR4/XAR5. Left in the fixture as a
 * reference case even though we know the cspec produces a different (wrong)
 * placement -- the compiler-truth here is what the real code does. */
long abi_int_int_long(int a, int b, long c) {
    g_i16 = a + b;
    return c;
}

/* Return-value probes (SPRU §7.3.2 step 6). Each has a unique constant so the
 * asm listing shows the register that constant is loaded into. */
int         abi_ret_i16(void)     { return 0x1234; }         /* -> AL */
long        abi_ret_i32(void)     { return 0x12345678L; }    /* -> ACC */
long long   abi_ret_i64(void)     { return 0x0123456789abcdefLL; } /* -> ACC:P */
int        *abi_ret_ptr(void)     { return (int *)&g_i16; }  /* -> XAR4 */
float       abi_ret_float(void)   { return 3.14159f; }       /* -> R0H */

/* Struct-return probe: caller allocates, passes hidden pointer in XAR6. */
struct S3 { int a, b, c; };
struct S3 abi_ret_struct(void) {
    struct S3 s;
    s.a = 1; s.b = 2; s.c = 3;
    return s;
}

/* Vararg -- last explicit arg goes on stack per §7.3.1. */
int abi_vararg(int a, int b, int c, ...)         { return a + b + c; }
