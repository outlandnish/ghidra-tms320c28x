// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nishanth Samala
// Post-import setup for a raw TMS320F2812 (F281x) firmware image:
//   1. Map the F2812 device memory map — on-chip SARAM (M0/M1, L0/L1, H0), Flash, OTP,
//      Boot ROM, the PIE vector RAM, and (optionally) the XINTF external-memory zones.
//      Mapping RAM/ROM as uninitialized blocks lets references into them resolve (e.g. an
//      LCR into H0 SARAM where copied-from-flash `.ramfunc` code runs, absent from a static
//      flash dump) instead of "could not follow flow into non-existing memory".
//   2. Map + label ALL F281x peripheral frames (eCAN, EV-A/EV-B, ADC, SCI-A/B, SPI-A,
//      McBSP-A, GPIO mux/data, SysCtrl/PLL/WD, PIE control, CPU timers, external-interrupt,
//      XINTF config, CSM, Flash/OTP config, DevEmu) so every MMIO access is self-documenting
//      and XREFs resolve.
//   3. Label the common peripherals field-by-field via shared *_REGS tables.
//
// This is the F281x analog of SetupF28377D.java. The F2812 is the ORIGINAL fixed-point C28x
// (no FPU/TMU/VCU/CLA, and a completely different peripheral set from the F2837xD: Event
// Managers instead of ePWM/eCAP/eQEP, eCAN instead of D_CAN, an older ADC, McBSP). The C28x
// instruction set is a strict subset of what the SLEIGH core decodes, so nothing changes at
// the ISA level — only this device map. Pair with the `TMS320C28x:LE:32:f2812` language
// variant (tms320c28x_f2812.pspec) for correct volatile MMIO ranges + interrupt vectors.
//
// Word addresses (the C28x is word-addressable — 1 address = 16 bits). Peripheral bases
// verified against the TI DSP281x header package (DSP281x_Headers_nonBIOS.cmd + the
// DSP281x_*.h register structs); the RAM/Flash/ROM/XINTF memory map verified against the
// device datasheet SPRS174V (F2812 Memory Map, Figure 9-13). See docs/c28x/f2812_memmap.md.
// Run as a post-script after importing the .bin + setting the image base.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SetupF2812 extends GhidraScript {

    // ── EV-A (Event Manager A) register file — DSP281x_Ev.h struct EVA_REGS @ 0x7400 ──
    // GP timers 1/2, compare/PWM (COMCONA/ACTRA/CMPRx), and capture units (CAPCONA/CAPnFIFO).
    private static final Object[][] EVA_REGS = {
        {0x00L,"GPTCONA"},{0x01L,"T1CNT"},{0x02L,"T1CMPR"},{0x03L,"T1PR"},{0x04L,"T1CON"},
        {0x05L,"T2CNT"},{0x06L,"T2CMPR"},{0x07L,"T2PR"},{0x08L,"T2CON"},{0x09L,"EXTCONA"},
        {0x11L,"COMCONA"},{0x13L,"ACTRA"},{0x15L,"DBTCONA"},
        {0x17L,"CMPR1"},{0x18L,"CMPR2"},{0x19L,"CMPR3"},
        {0x20L,"CAPCONA"},{0x22L,"CAPFIFOA"},
        {0x23L,"CAP1FIFO"},{0x24L,"CAP2FIFO"},{0x25L,"CAP3FIFO"},
        {0x27L,"CAP1FBOT"},{0x28L,"CAP2FBOT"},{0x29L,"CAP3FBOT"},
        {0x2CL,"EVAIMRA"},{0x2DL,"EVAIMRB"},{0x2EL,"EVAIMRC"},
        {0x2FL,"EVAIFRA"},{0x30L,"EVAIFRB"},{0x31L,"EVAIFRC"},
    };

    // ── EV-B (Event Manager B) register file — DSP281x_Ev.h struct EVB_REGS @ 0x7500 ──
    private static final Object[][] EVB_REGS = {
        {0x00L,"GPTCONB"},{0x01L,"T3CNT"},{0x02L,"T3CMPR"},{0x03L,"T3PR"},{0x04L,"T3CON"},
        {0x05L,"T4CNT"},{0x06L,"T4CMPR"},{0x07L,"T4PR"},{0x08L,"T4CON"},{0x09L,"EXTCONB"},
        {0x11L,"COMCONB"},{0x13L,"ACTRB"},{0x15L,"DBTCONB"},
        {0x17L,"CMPR4"},{0x18L,"CMPR5"},{0x19L,"CMPR6"},
        {0x20L,"CAPCONB"},{0x22L,"CAPFIFOB"},
        {0x23L,"CAP4FIFO"},{0x24L,"CAP5FIFO"},{0x25L,"CAP6FIFO"},
        {0x27L,"CAP4FBOT"},{0x28L,"CAP5FBOT"},{0x29L,"CAP6FBOT"},
        {0x2CL,"EVBIMRA"},{0x2DL,"EVBIMRB"},{0x2EL,"EVBIMRC"},
        {0x2FL,"EVBIFRA"},{0x30L,"EVBIFRB"},{0x31L,"EVBIFRC"},
    };

    // ── ADC — DSP281x_Adc.h struct ADC_REGS @ 0x7100 ──────────────────────────
    private static final Object[][] ADC_REGS = {
        {0x00L,"ADCTRL1"},{0x01L,"ADCTRL2"},{0x02L,"ADCMAXCONV"},
        {0x03L,"ADCCHSELSEQ1"},{0x04L,"ADCCHSELSEQ2"},{0x05L,"ADCCHSELSEQ3"},{0x06L,"ADCCHSELSEQ4"},
        {0x07L,"ADCASEQSR"},
        {0x08L,"ADCRESULT0"},{0x09L,"ADCRESULT1"},{0x0AL,"ADCRESULT2"},{0x0BL,"ADCRESULT3"},
        {0x0CL,"ADCRESULT4"},{0x0DL,"ADCRESULT5"},{0x0EL,"ADCRESULT6"},{0x0FL,"ADCRESULT7"},
        {0x10L,"ADCRESULT8"},{0x11L,"ADCRESULT9"},{0x12L,"ADCRESULT10"},{0x13L,"ADCRESULT11"},
        {0x14L,"ADCRESULT12"},{0x15L,"ADCRESULT13"},{0x16L,"ADCRESULT14"},{0x17L,"ADCRESULT15"},
        {0x18L,"ADCTRL3"},{0x19L,"ADCST"},
    };

    // ── SCI (shared by SCI-A @ 0x7050 and SCI-B @ 0x7750) — DSP281x_Sci.h ──────
    private static final Object[][] SCI_REGS = {
        {0x00L,"SCICCR"},{0x01L,"SCICTL1"},{0x02L,"SCIHBAUD"},{0x03L,"SCILBAUD"},
        {0x04L,"SCICTL2"},{0x05L,"SCIRXST"},{0x06L,"SCIRXEMU"},{0x07L,"SCIRXBUF"},
        {0x09L,"SCITXBUF"},{0x0AL,"SCIFFTX"},{0x0BL,"SCIFFRX"},{0x0CL,"SCIFFCT"},
        {0x0FL,"SCIPRI"},
    };

    // ── SPI-A @ 0x7040 — DSP281x_Spi.h struct SPI_REGS ────────────────────────
    private static final Object[][] SPI_REGS = {
        {0x00L,"SPICCR"},{0x01L,"SPICTL"},{0x02L,"SPISTS"},{0x04L,"SPIBRR"},
        {0x06L,"SPIRXEMU"},{0x07L,"SPIRXBUF"},{0x08L,"SPITXBUF"},{0x09L,"SPIDAT"},
        {0x0AL,"SPIFFTX"},{0x0BL,"SPIFFRX"},{0x0CL,"SPIFFCT"},{0x0FL,"SPIPRI"},
    };

    // ── System Control / PLL / Watchdog @ 0x7010 — DSP281x_SysCtrl.h ───────────
    // HISPCP/LOSPCP clock prescalers, PCLKCR peripheral clock enables, PLLCR, watchdog.
    private static final Object[][] SYS_CTRL_REGS = {
        {0x0AL,"HISPCP"},{0x0BL,"LOSPCP"},{0x0CL,"PCLKCR"},
        {0x0EL,"LPMCR0"},{0x0FL,"LPMCR1"},
        {0x11L,"PLLCR"},{0x12L,"SCSR"},{0x13L,"WDCNTR"},{0x15L,"WDKEY"},{0x19L,"WDCR"},
    };

    // ── GPIO MUX / direction / qualifier @ 0x70C0 — DSP281x_Gpio.h ─────────────
    private static final Object[][] GPIO_MUX_REGS = {
        {0x00L,"GPAMUX"},{0x01L,"GPADIR"},{0x02L,"GPAQUAL"},
        {0x04L,"GPBMUX"},{0x05L,"GPBDIR"},{0x06L,"GPBQUAL"},
        {0x0CL,"GPDMUX"},{0x0DL,"GPDDIR"},{0x0EL,"GPDQUAL"},
        {0x10L,"GPEMUX"},{0x11L,"GPEDIR"},{0x12L,"GPEQUAL"},
        {0x14L,"GPFMUX"},{0x15L,"GPFDIR"},
        {0x18L,"GPGMUX"},{0x19L,"GPGDIR"},
    };

    // ── GPIO data (DAT/SET/CLEAR/TOGGLE) @ 0x70E0 — DSP281x_Gpio.h ─────────────
    private static final Object[][] GPIO_DATA_REGS = {
        {0x00L,"GPADAT"},{0x01L,"GPASET"},{0x02L,"GPACLEAR"},{0x03L,"GPATOGGLE"},
        {0x04L,"GPBDAT"},{0x05L,"GPBSET"},{0x06L,"GPBCLEAR"},{0x07L,"GPBTOGGLE"},
        {0x0CL,"GPDDAT"},{0x0DL,"GPDSET"},{0x0EL,"GPDCLEAR"},{0x0FL,"GPDTOGGLE"},
        {0x10L,"GPEDAT"},{0x11L,"GPESET"},{0x12L,"GPECLEAR"},{0x13L,"GPETOGGLE"},
        {0x14L,"GPFDAT"},{0x15L,"GPFSET"},{0x16L,"GPFCLEAR"},{0x17L,"GPFTOGGLE"},
        {0x18L,"GPGDAT"},{0x19L,"GPGSET"},{0x1AL,"GPGCLEAR"},{0x1BL,"GPGTOGGLE"},
    };

    // ── CPU Timer (shared by TIMER0/1/2) — DSP281x_CpuTimers.h. TIM/PRD are 32-bit. ──
    private static final Object[][] CPUTIMER_REGS = {
        {0x00L,"TIM"},{0x02L,"PRD"},{0x04L,"TCR"},{0x06L,"TPR"},{0x07L,"TPRH"},
    };

    // ── PIE control @ 0x0CE0 — DSP281x_PieCtrl.h ──────────────────────────────
    private static final Object[][] PIE_CTRL_REGS = {
        {0x00L,"PIECTRL"},{0x01L,"PIEACK"},
        {0x02L,"PIEIER1"},{0x03L,"PIEIFR1"},{0x04L,"PIEIER2"},{0x05L,"PIEIFR2"},
        {0x06L,"PIEIER3"},{0x07L,"PIEIFR3"},{0x08L,"PIEIER4"},{0x09L,"PIEIFR4"},
        {0x0AL,"PIEIER5"},{0x0BL,"PIEIFR5"},{0x0CL,"PIEIER6"},{0x0DL,"PIEIFR6"},
        {0x0EL,"PIEIER7"},{0x0FL,"PIEIFR7"},{0x10L,"PIEIER8"},{0x11L,"PIEIFR8"},
        {0x12L,"PIEIER9"},{0x13L,"PIEIFR9"},{0x14L,"PIEIER10"},{0x15L,"PIEIFR10"},
        {0x16L,"PIEIER11"},{0x17L,"PIEIFR11"},{0x18L,"PIEIER12"},{0x19L,"PIEIFR12"},
    };

    // ── External-interrupt control @ 0x7070 — DSP281x_XIntrupt.h ──────────────
    private static final Object[][] XINT_REGS = {
        {0x00L,"XINT1CR"},{0x01L,"XINT2CR"},{0x07L,"XNMICR"},
        {0x08L,"XINT1CTR"},{0x09L,"XINT2CTR"},{0x0FL,"XNMICTR"},
    };

    // ── XINTF config @ 0x0B20 — datasheet SPRS174V Table 9-22 (absolute addresses).
    //    XTIMINGn/XINTCNF2 are 32-bit (2 words each), with reserved gaps between them. ──
    private static final Object[][] XINTF_REGS = {
        {0x00L,"XTIMING0"},{0x02L,"XTIMING1"},{0x04L,"XTIMING2"}, // 0x0B20/22/24
        {0x0CL,"XTIMING6"},{0x0EL,"XTIMING7"},                    // 0x0B2C/2E
        {0x14L,"XINTCNF2"},{0x18L,"XBANK"},{0x1AL,"XREVISION"},   // 0x0B34/38/3A
    };

    // ── Code Security Module @ 0x0AE0 — KEY0-7 (password match) + CSMSCR ───────
    private static final Object[][] CSM_REGS = {
        {0x00L,"KEY0"},{0x01L,"KEY1"},{0x02L,"KEY2"},{0x03L,"KEY3"},
        {0x04L,"KEY4"},{0x05L,"KEY5"},{0x06L,"KEY6"},{0x07L,"KEY7"},
        {0x0FL,"CSMSCR"},
    };

    // ── eCAN-A control/status registers @ 0x6000 — DSP281x_ECan.h struct ECAN_REGS.
    //    Every register is 32-bit (2 words); the firmware often touches the 16-bit halves. ──
    private static final Object[][] ECAN_REGS = {
        {0x00L,"CANME"},{0x02L,"CANMD"},{0x04L,"CANTRS"},{0x06L,"CANTRR"},
        {0x08L,"CANTA"},{0x0AL,"CANAA"},{0x0CL,"CANRMP"},{0x0EL,"CANRML"},
        {0x10L,"CANRFP"},{0x12L,"CANGAM"},{0x14L,"CANMC"},{0x16L,"CANBTC"},
        {0x18L,"CANES"},{0x1AL,"CANTEC"},{0x1CL,"CANREC"},{0x1EL,"CANGIF0"},
        {0x20L,"CANGIM"},{0x22L,"CANGIF1"},{0x24L,"CANMIM"},{0x26L,"CANMIL"},
        {0x28L,"CANOPC"},{0x2AL,"CANTIOC"},{0x2CL,"CANRIOC"},{0x2EL,"CANTSC"},
        {0x30L,"CANTOC"},{0x32L,"CANTOS"},
    };

    // ── McBSP-A @ 0x7800 — datasheet SPRS174V Table 9-9 (data/control/multichannel +
    //    the multichannel-FIFO block at 0x20-0x24). ─────────────────────────────
    private static final Object[][] MCBSP_REGS = {
        {0x00L,"DRR2"},{0x01L,"DRR1"},{0x02L,"DXR2"},{0x03L,"DXR1"},
        {0x04L,"SPCR2"},{0x05L,"SPCR1"},{0x06L,"RCR2"},{0x07L,"RCR1"},
        {0x08L,"XCR2"},{0x09L,"XCR1"},{0x0AL,"SRGR2"},{0x0BL,"SRGR1"},
        {0x0CL,"MCR2"},{0x0DL,"MCR1"},{0x0EL,"RCERA"},{0x0FL,"RCERB"},
        {0x10L,"XCERA"},{0x11L,"XCERB"},{0x12L,"PCR"},
        {0x13L,"RCERC"},{0x14L,"RCERD"},{0x15L,"XCERC"},{0x16L,"XCERD"},
        {0x17L,"RCERE"},{0x18L,"RCERF"},{0x19L,"XCERE"},{0x1AL,"XCERF"},
        {0x1BL,"RCERG"},{0x1CL,"RCERH"},{0x1DL,"XCERG"},{0x1EL,"XCERH"},
        {0x20L,"MFFTX"},{0x21L,"MFFRX"},{0x22L,"MFFCT"},{0x23L,"MFFINT"},{0x24L,"MFFST"},
    };

    // ─────────────────────────────────────────────────────────────────────────
    // The C28x "ram" space is WORD-addressed (addressableUnitSize = 2), so toAddr(x)
    // treats x as a BYTE offset and lands at WORD x/2. The register tables above hold the
    // TI memory-map WORD addresses/offsets the firmware loads directly, so to land a
    // block/label at displayed WORD W we pass W*2 to toAddr. Block lengths are BYTES
    // (= word_count * 2). This is the #1 footgun in this word-addressed space — keep it
    // identical to SetupF28377D.java.
    private Address wAddr(long word) {
        return toAddr(word * 2);
    }

    // Field-level labeler. Prepends the module name only when the register name does not
    // already carry it, so datasheet-exact names (CANME, ADCTRL1, EVAIMRA) stay verbatim
    // while generic names get namespaced by instance (SCIA_SCICCR, CPU_TIMER0_TIM).
    private void labelRegs(String mod, long base, Object[][] regs) throws Exception {
        int n = 0;
        for (Object[] r : regs) {
            long off = (Long) r[0];
            String reg = (String) r[1];
            String nm = reg.startsWith(mod) ? reg : mod + "_" + reg;
            createLabel(wAddr(base + off), nm, true, SourceType.USER_DEFINED);
            n++;
        }
        println("labeled " + mod + " (" + n + " regs) @ 0x" + Long.toHexString(base));
    }

    // Create an uninitialized (MMIO) memory block if it isn't already mapped.
    private void ensureBlock(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = wAddr(start);
        if (mem.getBlock(a) == null) {
            MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(true);
            println("created MMIO block " + name + " @ 0x" + Long.toHexString(start));
        }
    }

    // Create an uninitialized RAM/ROM block (non-volatile) if not already mapped.
    private void ensureRam(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = wAddr(start);
        if (mem.getBlock(a) == null) {
            MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(false);
            println("created RAM block " + name + " @ 0x" + Long.toHexString(start));
        }
    }

    // ── Peripheral frames: {word base, byte length (= word_count*2), name}. Verified
    //    against DSP281x_Headers_nonBIOS.cmd. Length in BYTES; the C28x space is
    //    word-addressed (1 word = 2 bytes), so a frame of N words has length N*2. ──
    private static final Object[][] PERIPHS = {
        // Peripheral Frame 0 (0x000800-0x000CFF): config/system peripherals.
        {0x000880L, 0x300L, "DEV_EMU"},     // 0x180 words
        {0x000A80L, 0x0C0L, "FLASH_CFG"},   // 0x60 words  (Flash/OTP wait-state control)
        {0x000AE0L, 0x020L, "CSM"},         // 0x10 words  (code security module)
        {0x000B20L, 0x040L, "XINTF_CFG"},   // 0x20 words  (external interface timing)
        {0x000C00L, 0x010L, "CPU_TIMER0"},  // 0x08 words
        {0x000C08L, 0x010L, "CPU_TIMER1"},
        {0x000C10L, 0x010L, "CPU_TIMER2"},
        {0x000CE0L, 0x040L, "PIE_CTRL"},    // 0x20 words
        // Peripheral Frame 1 (0x006000-0x006FFF, protected): eCAN-A (ctrl + LAM/MOTS/MOTO
        // + 32 mailboxes span 0x6000-0x61FF).
        {0x006000L, 0x400L, "ECANA"},       // 0x200 words
        // Peripheral Frame 2 (0x007000-0x007FFF, protected): the rest.
        {0x007010L, 0x040L, "SYS_CTRL"},    // 0x20 words
        {0x007040L, 0x020L, "SPIA"},        // 0x10 words
        {0x007050L, 0x020L, "SCIA"},
        {0x007070L, 0x020L, "XINT"},        // external-interrupt control
        {0x0070C0L, 0x040L, "GPIO_MUX"},    // 0x20 words
        {0x0070E0L, 0x040L, "GPIO_DATA"},
        {0x007100L, 0x040L, "ADC"},
        {0x007400L, 0x080L, "EVA"},         // 0x40 words
        {0x007500L, 0x080L, "EVB"},
        {0x007750L, 0x020L, "SCIB"},
        {0x007800L, 0x080L, "MCBSPA"},      // 0x40 words
    };

    // ── On-chip RAM/ROM regions: {word base, byte length (= word_count*2), name}.
    //    Verified against SPRS174V F2812 Memory Map (Figure 9-13). These are RAM/ROM at
    //    runtime but ABSENT from a static flash-only dump — mapping them as uninitialized
    //    blocks lets Ghidra resolve references into them (e.g. an LCR into H0 SARAM, where
    //    copied-from-flash `.ramfunc` code runs) instead of flagging "non-existing memory". ──
    private static final Object[][] RAM_REGIONS = {
        {0x000000L, 0x001000L, "M0M1_SARAM"}, // M0+M1 = 0x800 words (0x0000-0x07FF)
        {0x000D00L, 0x000200L, "PIE_VECT"},   // PIE vector RAM = 0x100 words (0x0D00-0x0DFF)
        {0x008000L, 0x002000L, "L0_SARAM"},   // 4K words (0x8000-0x8FFF)
        {0x009000L, 0x002000L, "L1_SARAM"},   // 4K words (0x9000-0x9FFF)
        {0x3F8000L, 0x004000L, "H0_SARAM"},   // 8K words (0x3F8000-0x3F9FFF) — .ramfunc target
    };

    // ── On-chip Flash / OTP / CSM password / Boot ROM (word base, byte length, name). ──
    private static final Object[][] FLASH_REGIONS = {
        {0x3D7800L, 0x000800L, "OTP"},        // 1K words (0x3D7800-0x3D7BFF)
        {0x3D8000L, 0x040000L, "FLASH"},      // 128K words (0x3D8000-0x3F7FFF)
        {0x3F7FF8L, 0x000010L, "CSM_PWL"},    // 8 words: 128-bit flash password (overlaps end of FLASH)
    };

    // ── XINTF external-memory zones (word base, byte length, name), SPRS174V. Only mapped
    //    on request — most F2812 firmware is internal-flash-only, and these are large. ──
    private static final Object[][] XINTF_ZONES = {
        {0x002000L, 0x004000L, "XINTF_ZONE0"}, // 8K words  (0x002000-0x003FFF, XZCS0AND1)
        {0x004000L, 0x004000L, "XINTF_ZONE1"}, // 8K words  (0x004000-0x005FFF, XZCS0AND1)
        {0x080000L, 0x100000L, "XINTF_ZONE2"}, // 0.5M words (0x080000-0x0FFFFF, XZCS2)
        {0x100000L, 0x100000L, "XINTF_ZONE6"}, // 0.5M words (0x100000-0x17FFFF, XZCS6AND7)
    };

    @Override
    public void run() throws Exception {
        // Boot mode determines the top of the map: Boot ROM (MP/MC=0, on-chip; typical for
        // flash firmware) vs XINTF Zone 7 (MP/MC=1, external) — they are mutually exclusive.
        String bootMode = askChoice("Boot mode (MP/MC pin)",
            "Which memory occupies 0x3FC000-0x3FFFFF?",
            java.util.Arrays.asList("Microcomputer (on-chip Boot ROM)",
                                    "Microprocessor (XINTF Zone 7 external)"),
            "Microcomputer (on-chip Boot ROM)");
        boolean microcomputer = bootMode.startsWith("Microcomputer");

        boolean mapXintf = askYesNo("XINTF external zones",
            "Map the XINTF external-memory zones (Zone0/1/2/6)?\n" +
            "Choose No for internal-flash-only firmware (the common case).");

        // 0. Map + label peripheral frames.
        int n = 0;
        for (Object[] p : PERIPHS) {
            long base = (Long) p[0], size = (Long) p[1];
            String name = (String) p[2];
            try {
                ensureBlock(name + "_REGS", base, size);
                createLabel(wAddr(base), name, true, SourceType.USER_DEFINED);
                n++;
            } catch (Exception e) { println("skip " + name + ": " + e.getMessage()); }
        }
        println("labeled " + n + " peripheral frames");

        // 0b. Map on-chip RAM regions, then Flash/OTP/ROM.
        int rn = 0;
        for (Object[] r : RAM_REGIONS) {
            try { ensureRam((String) r[2], (Long) r[0], (Long) r[1]);
                  createLabel(wAddr((Long) r[0]), (String) r[2], true, SourceType.USER_DEFINED); rn++; }
            catch (Exception e) { println("skip RAM " + r[2] + ": " + e.getMessage()); }
        }
        for (Object[] r : FLASH_REGIONS) {
            try { ensureRam((String) r[2], (Long) r[0], (Long) r[1]);
                  createLabel(wAddr((Long) r[0]), (String) r[2], true, SourceType.USER_DEFINED); rn++; }
            catch (Exception e) { println("skip " + r[2] + ": " + e.getMessage()); }
        }
        // Boot ROM (microcomputer) OR XINTF Zone 7 (microprocessor).
        try {
            if (microcomputer) {
                ensureRam("BOOT_ROM", 0x3FF000L, 0x002000L);   // 4K words (0x3FF000-0x3FFFFF)
                createLabel(wAddr(0x3FF000L), "BOOT_ROM", true, SourceType.USER_DEFINED);
            } else {
                ensureRam("XINTF_ZONE7", 0x3FC000L, 0x008000L); // 16K words (0x3FC000-0x3FFFFF)
                createLabel(wAddr(0x3FC000L), "XINTF_ZONE7", true, SourceType.USER_DEFINED);
            }
            rn++;
        } catch (Exception e) { println("skip top region: " + e.getMessage()); }
        // Optional XINTF external zones.
        if (mapXintf) {
            for (Object[] z : XINTF_ZONES) {
                try { ensureBlock((String) z[2], (Long) z[0], (Long) z[1]);
                      createLabel(wAddr((Long) z[0]), (String) z[2], true, SourceType.USER_DEFINED); rn++; }
                catch (Exception e) { println("skip " + z[2] + ": " + e.getMessage()); }
            }
        }
        println("mapped " + rn + " RAM/ROM/XINTF regions");

        // 1. Event Managers (EV-A, EV-B).
        labelRegs("EVA", 0x007400L, EVA_REGS);
        labelRegs("EVB", 0x007500L, EVB_REGS);

        // 2. ADC.
        labelRegs("ADC", 0x007100L, ADC_REGS);

        // 3. SCI-A / SCI-B.
        labelRegs("SCIA", 0x007050L, SCI_REGS);
        labelRegs("SCIB", 0x007750L, SCI_REGS);

        // 4. SPI-A.
        labelRegs("SPIA", 0x007040L, SPI_REGS);

        // 4b. McBSP-A.
        labelRegs("MCBSPA", 0x007800L, MCBSP_REGS);

        // 5. System control / PLL / watchdog.
        labelRegs("SYS", 0x007010L, SYS_CTRL_REGS);

        // 6. GPIO mux + data.
        labelRegs("GPIO", 0x0070C0L, GPIO_MUX_REGS);
        labelRegs("GPIO", 0x0070E0L, GPIO_DATA_REGS);

        // 7. CPU timers 0/1/2.
        long[] timerBases = {0x000C00L, 0x000C08L, 0x000C10L};
        for (int i = 0; i < timerBases.length; i++) {
            labelRegs("CPU_TIMER" + i, timerBases[i], CPUTIMER_REGS);
        }

        // 8. PIE control.
        labelRegs("PIE", 0x000CE0L, PIE_CTRL_REGS);

        // 9. External-interrupt control.
        labelRegs("XINT", 0x007070L, XINT_REGS);

        // 10. XINTF config.
        labelRegs("XINTF", 0x000B20L, XINTF_REGS);

        // 11. Code security module (password-match KEYs).
        labelRegs("CSM", 0x000AE0L, CSM_REGS);

        // 12. eCAN-A control registers + sub-region + mailbox labels.
        labelRegs("ECANA", 0x006000L, ECAN_REGS);
        createLabel(wAddr(0x006040L), "ECANA_LAM",  true, SourceType.USER_DEFINED); // local accept masks
        createLabel(wAddr(0x006080L), "ECANA_MOTS", true, SourceType.USER_DEFINED); // msg-object time stamps
        createLabel(wAddr(0x0060C0L), "ECANA_MOTO", true, SourceType.USER_DEFINED); // msg-object time-out
        // 32 mailboxes, 8 words each (MSGID/MSGCTRL/CANMDL/CANMDH, all 32-bit), from 0x6100.
        for (int mb = 0; mb < 32; mb++) {
            long base = 0x006100L + (long) mb * 0x8L;
            createLabel(wAddr(base + 0x0L), "MBOX" + mb + "_MSGID",   true, SourceType.USER_DEFINED);
            createLabel(wAddr(base + 0x2L), "MBOX" + mb + "_MSGCTRL", true, SourceType.USER_DEFINED);
            createLabel(wAddr(base + 0x4L), "MBOX" + mb + "_CANMDL",  true, SourceType.USER_DEFINED);
            createLabel(wAddr(base + 0x6L), "MBOX" + mb + "_CANMDH",  true, SourceType.USER_DEFINED);
        }
        println("labeled ECANA (control + LAM/MOTS/MOTO + 32 mailboxes)");

        // 13. Reset vector (boot-ROM vector map at 0x3FFFC0), only if that region is mapped.
        try {
            Address resetVec = wAddr(0x3FFFC0L);
            if (currentProgram.getMemory().contains(resetVec)) {
                createLabel(resetVec, "RESET", true, SourceType.USER_DEFINED);
            }
        } catch (Exception e) { /* region not in this image */ }

        println("F2812 setup complete: memory mapped and peripheral registers labeled.");
    }
}
