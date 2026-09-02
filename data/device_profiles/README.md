# Device profiles

PIE vector identities, one JSON per device. `MarkComponentRegistry.java` (step 4d)
reads these to name interrupt handlers it roots from the vector table's flash
initializer — `FUN_00095de5` becomes `CANB0_INT`.

## Generating

Slot order is the member order of `struct PIE_VECT_TABLE` in TI's
`<device>_pievect.h`, so nothing is hand-transcribed:

```sh
tools/generate_pie_profile.py /path/to/C2000Ware/.../F2837xD_pievect.h \
    -o data/device_profiles/f2837xd.json --profile-name F2837xD
```

The header is not redistributed here; the profile records its SHA-256.

## Selection

By language variant: `…:f2812` → `f2812.json`, else `f2837xd.json`. Override with
`-Dc28x.reg.pieProfile=<path>`. A missing profile is not an error — handlers keep
their `FUN_` names.

## Alignment check

Naming assumes table entry N is profile slot N; off by one and every name is
confidently wrong. Before naming, step 4d rejects the profile if any live handler
lands on a slot TI marks `RESERVED` (entry 0 is exempt — boot variables live there).

That is a sanity check, not a proof. To pin alignment on a new image, find the code
copying the initializer to the PIE table at word `0x0D00`: TI's stock
`InitPieVectTable` skips the first three slots on both sides, a straight `memcpy`
of an image's own table does not.

## Licensing

Names and descriptions are TI identifiers under BSD-3-Clause (see
[NOTICE](../../NOTICE)); slot order is a hardware fact. See
[THIRD-PARTY.md](../../THIRD-PARTY.md).
