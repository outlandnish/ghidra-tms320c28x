# TMS320F2812 (F281x) memory map & peripheral register map

Ground-truth record for the **F2812** target (also covers the memory-compatible
**F2810/F2811**). All addresses are **word addresses** (the C28x is word-addressable —
1 address = 16 bits). Consumed by [`ghidra_scripts/SetupF2812.java`](../../ghidra_scripts/SetupF2812.java)
and the `TMS320C28x:LE:32:f2812` language variant
([`tms320c28x_f2812.pspec`](../../data/languages/tms320c28x_f2812.pspec)).

**Sources (verified, not recalled):**
- Memory map + peripheral register addresses — TI datasheet **SPRS174V**
  (TMS320F2810/F2811/F2812): *Memory Map* Figure 9-13, and the per-peripheral register
  tables 9-3 (CPU-timers), 9-5 (EVA), 9-6 (ADC), 9-8 (eCAN), 9-9 (McBSP), 9-10/9-11
  (SCI-A/B), 9-12 (SPI), 9-13/9-14 (GPIO), 9-18/9-19/9-20 (frame ranges), 9-22 (XINTF).
  Every EVA/EVB/ADC/eCAN/McBSP/SCI/SPI/GPIO/XINTF field offset here is cross-checked
  against those tables (this caught two WebFetch-header errors: XINTF timing-register
  offsets, and `CANTSC` at 0x602E which a header parse had mislabeled).
- SysCtrl / PIE / XINT / CSM field offsets — TI **DSP281x** header structs, consistent
  with the datasheet frame ranges (the datasheet defers their bit-level detail to the
  *System Control and Interrupts Reference Guide*, SPRU078).

## Why F2812 is a variant, not a rewrite

The F2812 is the *original* fixed-point C28x. Its instruction set is a **strict subset**
of what the SLEIGH core already decodes — it has **no FPU, TMU, VCU, or CLA**. So the
`.sla` is reused unchanged; only the **device map** differs from the F28377D default:
a different peripheral *set* (Event Managers, eCAN, older ADC, McBSP — not
ePWM/eCAP/eQEP/D_CAN) at F281x addresses, and F281x interrupt vectors.

## Memory map (word addresses)

| Region | Start | End | Size | Notes |
|---|---|---|---|---|
| M0 SARAM | `0x000000` | `0x0003FF` | 1K×16 | `0x00–0x3F` = M0 vector RAM if VMAP=0 |
| M1 SARAM | `0x000400` | `0x0007FF` | 1K×16 | |
| Peripheral Frame 0 | `0x000800` | `0x000CFF` | — | DevEmu, Flash/OTP cfg, CSM, XINTF cfg, CPU timers, PIE ctrl |
| PIE vector RAM | `0x000D00` | `0x000DFF` | 256×16 | live vectors when VMAP=1, ENPIE=1 |
| XINTF Zone 0 | `0x002000` | `0x003FFF` | 8K×16 | external, XZCS0AND1 |
| XINTF Zone 1 | `0x004000` | `0x005FFF` | 8K×16 | external, XZCS0AND1 (protected) |
| Peripheral Frame 1 | `0x006000` | `0x006FFF` | — | eCAN-A (protected) |
| Peripheral Frame 2 | `0x007000` | `0x007FFF` | — | SysCtrl, SPI-A, SCI-A, XINT, GPIO, ADC, EV-A, EV-B, SCI-B, McBSP-A (protected) |
| L0 SARAM | `0x008000` | `0x008FFF` | 4K×16 | secure block |
| L1 SARAM | `0x009000` | `0x009FFF` | 4K×16 | secure block |
| XINTF Zone 2 | `0x080000` | `0x0FFFFF` | 0.5M×16 | external, XZCS2 |
| XINTF Zone 6 | `0x100000` | `0x17FFFF` | 0.5M×16 | external, XZCS6AND7 |
| OTP | `0x3D7800` | `0x3D7BFF` | 1K×16 | secure block (`0x3D7C00–0x3D7FFF` reserved) |
| FLASH | `0x3D8000` | `0x3F7FFF` | 128K×16 | secure block |
| CSM password (128-bit) | `0x3F7FF8` | `0x3F7FFF` | 8×16 | last 8 words of FLASH |
| H0 SARAM | `0x3F8000` | `0x3F9FFF` | 8K×16 | common `.ramfunc` target (copied from flash at boot) |
| XINTF Zone 7 | `0x3FC000` | `0x3FFFFF` | 16K×16 | external, XZCS6AND7 — **enabled only if MP/MC=1** |
| Boot ROM | `0x3FF000` | `0x3FFFFF` | 4K×16 | on-chip — **enabled only if MP/MC=0** |
| BROM reset vector | `0x3FFFC0` | | | reset vector fetch (VMAP=1, MP/MC=0, ENPIE=0) |

> **Boot ROM vs XINTF Zone 7 are mutually exclusive** (selected by the MP/MC pin) and
> overlap at `0x3FF000–0x3FFFFF`. `SetupF2812.java` asks which to map; flash firmware is
> almost always Microcomputer mode (on-chip Boot ROM).

## Peripheral frame bases (`DSP281x_Headers_nonBIOS.cmd`)

| Peripheral | Base | Words | Frame |
|---|---|---|---|
| DevEmuRegs | `0x000880` | 0x180 | PF0 |
| FlashRegs | `0x000A80` | 0x060 | PF0 |
| CsmRegs | `0x000AE0` | 0x010 | PF0 |
| XintfRegs | `0x000B20` | 0x020 | PF0 |
| CpuTimer0/1/2Regs | `0x000C00`/`0x000C08`/`0x000C10` | 0x008 ea | PF0 |
| PieCtrlRegs | `0x000CE0` | 0x020 | PF0 |
| PieVectTable | `0x000D00` | 0x100 | — (RAM) |
| ECanaRegs | `0x006000` | 0x040 | PF1 |
| ECana LAM / MOTS / MOTO | `0x006040` / `0x006080` / `0x0060C0` | 0x040 ea | PF1 |
| ECanaMboxes | `0x006100` | 0x100 | PF1 — 32 mailboxes × 8 words |
| SysCtrlRegs | `0x007010` | 0x020 | PF2 |
| SpiaRegs | `0x007040` | 0x010 | PF2 |
| SciaRegs | `0x007050` | 0x010 | PF2 |
| XIntruptRegs | `0x007070` | 0x010 | PF2 |
| GpioMuxRegs | `0x0070C0` | 0x020 | PF2 |
| GpioDataRegs | `0x0070E0` | 0x020 | PF2 |
| AdcRegs | `0x007100` | 0x020 | PF2 |
| EvaRegs | `0x007400` | 0x040 | PF2 |
| EvbRegs | `0x007500` | 0x040 | PF2 |
| ScibRegs | `0x007750` | 0x010 | PF2 |
| McbspaRegs | `0x007800` | 0x040 | PF2 |

Field-level register names (per struct) are encoded in `SetupF2812.java` for every frame
above, **including McBSP-A** (Table 9-9: data/control/multichannel regs + the FIFO block
`MFFTX`–`MFFST` at `0x20`–`0x24`). eCAN-A control registers are all 32-bit (2 words each);
each mailbox is 8 words: `MSGID`, `MSGCTRL`, `CANMDL`, `CANMDH` (all 32-bit).

## What the F2812 does *not* have (vs the F28377D default)

No FPU / TMU / VCU / CLA / DMA; no ePWM / eCAP / eQEP (it has **Event Managers** EV-A/EV-B
instead); D_CAN is replaced by **eCAN**; a single older **ADC**, one **SPI-A**, one
**McBSP-A**, **SCI-A/B**. These simply never appear in F2812 code, so the superset ISA in
the shared `.sla` decodes it correctly with no changes.
