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
lands on a slot TI marks `RESERVED`.

**Only a real handler counts as evidence**, or the check condemns aligned tables.
Three things are exempt:

- entry 0 — boot variables live there, and images put the reset vector in it;
- a target occupying several slots — a shared stub is a second fill value, and the
  naming code declines to name it for the same reason;
- a target that is not a function **entry**. Both F28377D images tested carry a
  secondary unused-interrupt stub at `TIMER2_INT+93`, sitting in 4–6 slots of which
  3–4 are reserved. Reading it as a live handler rejected a table that was provably
  aligned: entry 0 held the reset vector and 1–12 the default fill — exactly the 13
  reserved entries `struct PIE_VECT_TABLE` opens with — while every other occupied
  slot named a peripheral the ECU plainly has (TIMER2, NMI, ADCB1, EPWM2 as a D0-RAM
  ramfunc, CLA1_2, IPC1/IPC2, CANA0/CANB0).

A vector pointing *into* a function is reported as a missed function boundary rather
than counted: two routines emitted back to back and seeded as one.

That is a sanity check, not a proof. To pin alignment on a new image, find the code
copying the initializer to the PIE table at word `0x0D00`: TI's stock
`InitPieVectTable` skips the first three slots on both sides, a straight `memcpy`
of an image's own table does not.

## Licensing

Names and descriptions are TI identifiers under BSD-3-Clause (see
[NOTICE](../../NOTICE)); slot order is a hardware fact. See
[THIRD-PARTY.md](../../THIRD-PARTY.md).
