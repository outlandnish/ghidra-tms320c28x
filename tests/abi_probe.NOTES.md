# ABI probe — known cspec limitations

The 19-line `abi_probe.expected.txt` records what
`PrototypeModel.getStorageLocations()` produces for a set of C signatures
under the current `tms320c28x.cspec`. **15 of 19 lines are correct** per
SPRU514 §7.3 / SPRAC71 EABI. The 4 that differ from SPRU-truth are recorded
as-is to serve as a regression floor; they represent either a Ghidra cspec
model limitation or a probe limitation, not a bug we can fix by editing the
cspec.

**Cases 1 and 2 below are now corrected on real functions by
`TMS320C28xAbiAnalyzer`** — see `abi_analyzer.expected.txt` +
`run_abi_analyzer_check.{sh,ps1}` for the analyzer probe.
`abi_probe.expected.txt` continues to record the raw cspec output because
the analyzer can't hook `PrototypeModel.getStorageLocations()` — it
installs SPRU storage via `Function.updateFunction(..., CUSTOM_STORAGE,
...)` after signatures are known (issue #31).

**Case 3 (vararg) is now corrected end-to-end** by the analyzer's
`fn.hasVarArgs()` check — see `abi_applied.expected.txt` +
`run_abi_applied_check.{sh,ps1}` for the applied-signature probe. **Case 4
(hidden struct return) remains broken end-to-end** (see below); needs a
follow-up analyzer patch that synthesizes the XAR6 auto-parameter.

## The four "wrong but recorded" cases

### 1. `abi_int_int_long(int, int, long)` — fixed by analyzer
- SPRU-truth (from `cl2000 -k` DWARF):     `[AR4, AR5, AH:AL]`
- What the cspec alone produces:           `[AL, AH, XAR4]`
- What `TMS320C28xAbiAnalyzer` produces:   `[AR4, AR5, AH:AL]` ✓

Per SPRU §7.3.1 rule d, `long c` is class 5 (32-bit int) and pre-empts `ACC`
(AH:AL) even though it's declared last. That forces `int a` / `int b` out of
AL / AH and into XAR4 / XAR5 (as their 16-bit low halves AR4 / AR5) per rule
f's "if they are available" clause.

Ghidra's pentry model walks arguments in **declaration order** and has no
mechanism to express "a later argument of class X pre-reserves a register
from an earlier argument of class Y." Ghidra 12.x also has no cspec hook to
plug in a custom `PrototypeModel` subclass — the `<resolveprototype>` XML
tag only selects among named pentry-based prototypes, it does not delegate
to custom Java (verified against `BasicCompilerSpec.addPrototypeModel`).
The analyzer route bypasses cspec allocation by writing `CUSTOM_STORAGE`
on the function post-signature.

### 2. `abi_spec_example(long, long long, int, int*)` — fixed by analyzer
- SPRU-truth:                              `[Stack, ACC:P, XAR5, XAR4]`
- What the cspec alone produces:           `[AH:AL, Stack[+494]:8, AR4, XAR5]`
- What `TMS320C28xAbiAnalyzer` produces:   `[Stack[+2]:4, AH:AL:PH:PL, AR5, XAR4]` ✓

Same class-priority reservation problem, one level deeper (`long long` in
class 4 pre-empts `long` in class 5 which pre-empts `int` in class 6). The
analyzer's rendering differs cosmetically from the hand-abbreviated
"SPRU-truth" line — `AH:AL:PH:PL` is the same 8 bytes as `ACC:P` just as
four sub-piece varnodes, and the correct 2-byte narrowing of the
transcribed `XAR5` is `AR5`. Semantically identical to what `cl2000
--abi=eabi` emits.

### 3. `abi_vararg_3(int, int, int, ...)` — fixed by analyzer
- SPRU-truth (last named arg must be on stack for `va_list` to work): `[AL, AH, Stack]`
- What the cspec alone produces (`abi_probe.expected.txt`):           `[AL, AH, AR4]`
- What `TMS320C28xAbiAnalyzer` produces on an applied signature:      `[AL, AH, Stack[+2]:2]` ✓

The cspec probe is a **probe limitation** — `getStorageLocations(DataType[])`
has no way to signal an ellipsis, so the entry in `abi_probe.expected.txt`
records the not-actually-broken (but not vararg-aware) cspec output as a
regression floor. The end-to-end path (`ApplyFunctionSignatureCmd` →
`Function.hasVarArgs()` → analyzer) IS vararg-aware: the analyzer detects
the ellipsis and forces the last named arg to the stack per SPRU §7.3.1's
`va_list` contiguity rule. See `abi_applied.expected.txt`.

### 4. `abi_ret_struct`  → `struct S3`  (6 bytes) — end-to-end broken, needs follow-up
- SPRU-truth: `return=AUTO(XAR6)` with a synthetic hidden first parameter
- What the cspec produces (`abi_probe.expected.txt`): `return=<UNASSIGNED>` with empty `params`
- What `ApplyFunctionSignatureCmd` produces end-to-end (`abi_applied.expected.txt`): same — `<UNASSIGNED>` / `[]`

The applied-signature probe confirms this is **not** just a probe limitation:
Ghidra's real signature-application path does not consult the cspec's
`<pentry storage="hiddenret">` for oversized returns either. The analyzer
would need to synthesize the XAR6 auto-parameter itself. That's non-trivial
under `CUSTOM_STORAGE` — `AutoParameterImpl` requires a `VariableStorage`
constructed with an internal auto-flag that no public API exposes. Deferred
to a follow-up: allocator + analyzer extension that emits a hidden ret ptr
via whichever `updateFunction` mode preserves auto-parameter tagging.

## Regenerating the expected file

After a deliberate cspec change, verify the new output by hand, then:

```powershell
pwsh -File tests/run_abi_check.ps1 -Update
```

That rewrites `abi_probe.expected.txt` from the current cspec's output.
Never do this without eyeballing the diff first — the file is the source
of truth for the next reviewer.

## Regenerating the fixture .obj

The `abi_probe.obj` is compiled once and checked in (small, deterministic).
To rebuild:

```sh
# From a Windows-local dir (cl2000 can't spawn its child tools from a WSL UNC path):
cp tests/fixtures/abi_probe.c /mnt/c/Users/you/AppData/Local/Temp/c28x-abi/
cd /mnt/c/Users/you/AppData/Local/Temp/c28x-abi
CGT=/mnt/c/path/to/ti-cgt-c2000_25.11.0.LTS
cmd.exe /c "set PATH=$(wslpath -w $CGT/bin);%PATH% && \
    cl2000.exe -v28 --abi=eabi --float_support=fpu32 --opt_level=0 \
               --symdebug:none -c abi_probe.c"
cp abi_probe.obj $REPO/tests/fixtures/
```

`--symdebug:none` is important: with DWARF present Ghidra imports parameter
storage from the debug info directly, defeating the point of testing the
cspec. `-k` (keep .asm listing) is useful when re-generating so you can
grep the `DW_TAG_formal_parameter ... DW_AT_location[DW_OP_reg<n>]` entries
for compiler-truth on each probe.
