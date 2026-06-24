# Plan: full per-register peripheral labeling in `SetupF28377D.java`

**Goal.** Extend `ghidra_scripts/SetupF28377D.java` so EVERY F2837xD peripheral gets
**field-level register labels** (offset → register name), the way only CAN does today. After
running the script on an imported image, an MMIO access like `MOV AL, *(0x7048)` should read
as `EQEP1_QPOSCNT`, not a bare address — for all peripherals, not just CANA/CANB.

This is a self-contained task. The instruction-set / decompilation work is done and committed
(see `git log`); this is purely peripheral metadata. No SLEIGH recompile is needed — the
script only creates labels + memory blocks.

## Current state (what exists)

`SetupF28377D.java` already:
- Maps every peripheral **frame** as a volatile MMIO block + a single **base label**
  (`PERIPHS[]` table, ~44 frames: EPWM1-12, ECAP/EQEP, ADCA-D, SCI/SPI/I2C, GPIO, PIE,
  sysctl, timers, DMA, XBAR…).
- Labels **CANA/CANB field-by-field** via `CAN_REGS[]` + `labelCan(mod, base)` — THIS is the
  pattern to generalize.
- Maps dual-core RAM regions (`RAM_REGIONS[]`).

So the frame map + the per-register idiom both already exist. The task is to add a
`*_REGS[]` offset table for each remaining peripheral and call a generic labeler.

## Source of truth — the TRM

**`spruhm8k.pdf`** — *TMS320F2837xD Dual-Core Microcontrollers Technical Reference Manual*
— is in `C:\Users\nisha\Downloads\spruhm8k.pdf` (user-provided). Each peripheral chapter ends
with a **"<PERIPH> Registers"** / **"<PERIPH> Base Address Table"** + a per-register
**Register Offset** table (columns: Offset, Acronym, Register Name). Those offset tables are
the data to extract.

⚠️ **Addressing: all offsets in this module are WORD offsets** (the C28x is word-addressable;
1 address = 16 bits). The TRM lists register offsets in **words** for C28x peripherals — use
them as-is (do NOT divide/multiply by 2). 32-bit registers occupy **2 word-offsets** (e.g. a
reg at offset 0x0A spans 0x0A-0x0B); label the base offset. Sanity-check against the CAN table
already in the script (CAN offsets there are word offsets) and against `docs/c28x/
f2837xd_peripherals.md` (frame bases, word addresses).

## Extraction workflow (mirror the SPRU430F/spruhs1c flow)

1. **Find each peripheral's register-table page range.** Use the PDF bookmarks / table of
   contents: `pdftotext -f 1 -l 40 -layout spruhm8k.pdf /tmp/toc.txt` then grep for
   "Registers" sections. Note **PDF page = printed page + front-matter offset** (verify the
   offset once on a known table, as we did for SPRU430F).
2. **Extract each register table** with poppler:
   ```sh
   pdftotext -f <first> -l <last> -layout /mnt/c/Users/nisha/Downloads/spruhm8k.pdf /tmp/<periph>.txt
   ```
   Layout mode preserves the Offset/Acronym columns. The rows look like
   `0x0000  GPACTRL  GPIO A Control Register`.
3. **Parse offset+acronym** per peripheral into `{offsetWord, "ACRONYM"}` rows. A small python
   helper (regex `^\s*0x([0-9A-Fa-f]+)\s+(\w+)`) over each `/tmp/<periph>.txt` emits the Java
   array literal. Keep the acronym (short), drop the long description.
4. **Spot-check** a few offsets against the TRM text AND against real firmware: pick an MMIO
   address the firmware accesses, confirm the label that lands there matches what the code is
   clearly doing (e.g. a write to `GPxSET` near a GPIO toggle). dis2000/Ghidra disasm of the
   access site is the cross-check.

## Code change in `SetupF28377D.java`

Generalize the CAN labeler into one reusable method, then add a table per peripheral:

```java
// generic field-level labeler (CAN's labelCan, generalized)
private void labelRegs(String mod, long base, Object[][] regs) throws Exception {
    for (Object[] r : regs) {
        long off = (Long) r[0];
        createLabel(toAddr(base + off), mod + "_" + (String) r[1], true,
                    SourceType.USER_DEFINED);
    }
}
```
Then one `Object[][]` per peripheral type (share tables across instances — all 12 EPWMs use
the SAME `EPWM_REGS`, all 4 ADCs the SAME `ADC_REGS`, all 4 SCIs the SAME `SCI_REGS`, etc.),
and in `run()` loop the instances:
```java
private static final Object[][] EPWM_REGS = { {0x00L,"TBCTL"},{0x01L,"TBCTL2"}, ... };
private static final Object[][] ADC_REGS  = { ... };
// ... GPIO, SCI, SPI, I2C, TIMER, EQEP, ECAP, DMA, PIE, sysctl(DEV_CFG/CLK_CFG) ...
// in run(), after the frame map:
String[][] epwms = {{"EPWM1","0x6000"},{"EPWM2","0x6100"}, ...};
for (String[] e : epwms) labelRegs(e[0], Long.decode(e[1]), EPWM_REGS);
// same for ADCA-D, SCIA-D, SPIA-C, I2CA/B, CPU_TIMER0-2, EQEP1-3, ECAP1-3, ...
```
Reuse the existing `PERIPHS[]` bases for the instance loop (they're already correct word
addresses) instead of re-typing addresses.

### Register tables to add (peripherals already frame-mapped; need field tables)

Motor-control + comms first (highest RE value), then the rest:
- **EPWM** (shared, 12 instances) — TBCTL/TBCTL2/CMPA/CMPB/AQCTLA/DBCTL/PCCTL/ETSEL/ETPS/…
- **ADC** (shared, A-D) — ADCCTL1/2, ADCSOCxCTL, ADCRESULTx (result regs are a sub-frame),
  INTSEL, SOCPRICTL…
- **EQEP** (shared, 1-3) — QPOSCNT/QPOSINIT/QCTL/QEPCTL/QFLG/QCLR/QPOSLAT…
- **ECAP** (shared, 1-3) — TSCTR/CTRPHS/CAP1-4/ECCTL1-2/ECFLG/ECCLR…
- **SCI** (shared, A-D) — SCICCR/SCICTL1/2/SCIHBAUD/SCILBAUD/SCIRXBUF/SCITXBUF/SCIFFTX/RX…
- **SPI** (shared, A-C) — SPICCR/SPICTL/SPIBRR/SPIRXBUF/SPITXBUF/SPIFFTX/RX/CT…
- **I2C** (shared, A/B) — I2COAR/I2CIER/I2CSTR/I2CCLKL/H/I2CCNT/I2CDRR/I2CSAR/I2CDXR/I2CMDR…
- **GPIO** — split: GPIO_CTRL frame (GPACTRL/GPADIR/GPAPUD/GPAMUX1-2/GPAGMUX1-2/GPAQSEL…
  per A/B/C/D/E/F group) + GPIO_DATA frame (GPxDAT/SET/CLEAR/TOGGLE).
- **CPU_TIMER0-2** (shared) — TIM/PRD/TCR/TPR/TPRH.
- **PIE_CTRL** — PIECTRL/PIEACK/PIEIERx/PIEIFRx.
- **sysctl** — DEV_CFG (DEVCFGLOCK, PARTIDL/H, REVID, …) + CLK_CFG (CLKSEM/CLKCFGLOCK/
  SYSPLLCTL/SYSCLKDIVSEL/PERxCLKDIVSEL/PCLKCRx clock-enables — the PCLKCR gating regs are
  high-value for "what's enabled").
- **DMA** — per-channel CONTROL/SRC/DST/BURST/TRANSFER + global DMACTRL/PRIORITYCTRL.
- **XBAR / INPUT_XBAR**, **DCSM** — lower priority; add if time permits.

Leave CANA/CANB as-is (already done). Keep the `ensureBlock` frame map; field labels go on top.

## Validation

- Script runs without exceptions on an imported F28377D image (PMR or DIR `*_swapped` base
  0x80800, or any raw F2837xD `.bin`); prints a per-peripheral "labeled N regs" summary.
- Spot-check 3-4 labels vs the TRM offset tables (exact offset → acronym).
- Spot-check 2-3 against firmware XREFs: a labeled register should sit where the code's intent
  matches (e.g. an `EPWMx_CMPA` write inside a PWM-duty update; a `PCLKCR*` write in init).
- `createLabel` is idempotent-ish but may warn on collisions — if two tables overlap an
  address, the more specific one should win; log collisions rather than failing.

## Notes / gotchas

- **Word vs byte:** `toAddr(x)` in this script takes the WORD address directly (it's how the
  existing CAN/frame code works — confirm by reading the current `labelCan`). Don't reintroduce
  a ×2. (Separately, when SCRIPTING via the API elsewhere, `Address.getOffset()` returns BYTE
  = word×2 — but `toAddr`/`createLabel` here are already in word terms.)
- **32-bit registers** span two word offsets; label the low word only.
- **Shared vs per-instance offset:** ADC has a separate RESULT register frame at a different
  base than the control frame on some F2837xD parts — check the TRM (ADCRESULT base vs ADC
  control base) and map both.
- Keep acronyms TI-canonical (match the TRM) so they're greppable against TI headers.
- This is a PUBLIC repo; the TRM data (TI register names/offsets) is fine to commit. No
  vehicle/ECU-specific material goes in here.

## Done when

`SetupF28377D.java` labels every frame in `PERIPHS[]` field-by-field (not just CAN), verified
against `spruhm8k.pdf`, and a run on a real image makes peripheral MMIO accesses across the
board read as `<PERIPH>_<REG>`. Commit to the public repo with a Tesla-name-free message.
