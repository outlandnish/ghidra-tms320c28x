# Device profiles

PIE vector identities, one JSON per device. `MarkComponentRegistry.java` (pipeline
step 4d) reads these to name interrupt handlers it roots from the vector table's
flash initializer, turning `FUN_00095de5` into `CANB0_INT`.

An ISR name identifies the peripheral that raises it, which is usually the fastest
route into an unknown subsystem — so this is the highest-leverage naming surface a
stripped image has.

## Generating

Slot order is a hardware fact, published as the member order of
`struct PIE_VECT_TABLE` in TI's `<device>_pievect.h`. Nothing here is
hand-transcribed:

```sh
tools/generate_pie_profile.py \
    /path/to/C2000Ware/.../F2837xD_pievect.h \
    -o data/device_profiles/f2837xd.json --profile-name F2837xD
```

The header itself is **not** redistributed here — bring your own C2000Ware install.
The generated profile records the source file's SHA-256 so a regenerated profile can
be tied back to the exact header it came from.

## Which profile is used

By language variant, the same way the `Setup*` scripts dispatch:
`TMS320C28x:LE:32:f2812` → `f2812.json`, everything else → `f2837xd.json`.
Override with `-Dc28x.reg.pieProfile=<path>`. A missing profile is not an error —
handlers keep their `FUN_` names.

## The alignment check

Naming assumes table entry N is profile slot N. When that is off by even one, every
name is confidently wrong, which is worse than no name at all. Before naming
anything, step 4d checks that no live handler has landed on a slot TI marks
`RESERVED`; if one has, it names nothing and says why. Entry 0 is exempt, because
the boot ROM keeps boot variables in the first slots and images are observed putting
the entry point there.

The check is a sanity test, not a proof — an alignment can be wrong and still put
every handler on a non-reserved slot. To pin it exactly on a given image, find the
code that copies the initializer to the PIE table at word `0x0D00` and read the
source/destination offsets: TI's stock `InitPieVectTable` skips the first three
slots on both sides, while an image doing a straight `memcpy` of its own table does
not.

## Licensing

The identifiers and one-line descriptions come from TI C2000Ware device headers and
are TI-derived, under TI's BSD-3-Clause terms reproduced in [NOTICE](../../NOTICE).
Slot order and vector assignments are facts about the hardware. See
[THIRD-PARTY.md](../../THIRD-PARTY.md).
