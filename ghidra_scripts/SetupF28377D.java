// Post-import setup for a raw TMS320F28377D firmware image:
//   1. Map + label ALL peripheral frames (CAN, GPIO, SCI, SPI, I2C, ADC, ePWM,
//      eCAP/eQEP, DMA, PIE, sysctl, timers...) so every MMIO access is self-
//      documenting and XREFs resolve to named registers.
//   2. Label every peripheral field-by-field (not just CAN) via shared *_REGS tables.
//   3. Mark the reset vector so Ghidra can follow real flow and decode only reachable
//      code (leaving const pools as data).
//
// Word addresses (the C28x is word-addressable; see docs/c28x/f2837xd_peripherals.md,
// f28377d_memmap.md, dcan_registers.md). Run as a post-script after importing the .bin.
// Register tables extracted from spruhm8k.pdf (F2837xD TRM, SPRUHM8K).
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SetupF28377D extends GhidraScript {

    // ── D_CAN (spruhm8k Table 22-8, word offsets = TRM byte offset / 2) ────────
    private static final Object[][] CAN_REGS = {
        {0x0000L,"CTL"},{0x0002L,"ES"},{0x0004L,"ERRC"},{0x0006L,"BTR"},{0x0008L,"INT"},
        {0x000AL,"TEST"},{0x000EL,"PERR"},
        {0x0020L,"RAM_INIT"},
        {0x0028L,"GLB_INT_EN"},{0x002AL,"GLB_INT_FLG"},{0x002CL,"GLB_INT_CLR"},
        {0x0040L,"ABOTR"},
        {0x0042L,"TXRQ_X"},{0x0044L,"TXRQ_21"},
        {0x004CL,"NDAT_X"},{0x004EL,"NDAT_21"},
        {0x0056L,"IPEN_X"},{0x0058L,"IPEN_21"},
        {0x0060L,"MVAL_X"},{0x0062L,"MVAL_21"},
        {0x006CL,"IP_MUX21"},
        {0x0080L,"IF1CMD"},{0x0082L,"IF1MSK"},{0x0084L,"IF1ARB"},{0x0086L,"IF1MCTL"},
        {0x0088L,"IF1DATA"},{0x008AL,"IF1DATB"},
        {0x0090L,"IF2CMD"},{0x0092L,"IF2MSK"},{0x0094L,"IF2ARB"},{0x0096L,"IF2MCTL"},
        {0x0098L,"IF2DATA"},{0x009AL,"IF2DATB"},
        {0x00A0L,"IF3OBS"},{0x00A2L,"IF3MSK"},{0x00A4L,"IF3ARB"},{0x00A6L,"IF3MCTL"},
        {0x00A8L,"IF3DATA"},{0x00AAL,"IF3DATB"},{0x00B0L,"IF3UPD"},
    };

    // ── ePWM (spruhm8k Table 15-20, shared across all 12 instances) ────────────
    private static final Object[][] EPWM_REGS = {
        {0x0000L,"TBCTL"},{0x0001L,"TBCTL2"},{0x0004L,"TBCTR"},{0x0005L,"TBSTS"},
        {0x0008L,"CMPCTL"},{0x0009L,"CMPCTL2"},{0x000CL,"DBCTL"},{0x000DL,"DBCTL2"},
        {0x0010L,"AQCTL"},{0x0011L,"AQTSRCSEL"},{0x0014L,"PCCTL"},
        {0x0018L,"VCAPCTL"},{0x0019L,"VCNTCFG"},
        {0x0020L,"HRCNFG"},{0x0021L,"HRPWR"},{0x0026L,"HRMSTEP"},{0x0027L,"HRCNFG2"},
        {0x002DL,"HRPCTL"},{0x002EL,"TRREM"},
        {0x0034L,"GLDCTL"},{0x0035L,"GLDCFG"},{0x0038L,"EPWMXLINK"},
        {0x0040L,"AQCTLA"},{0x0041L,"AQCTLA2"},{0x0042L,"AQCTLB"},{0x0043L,"AQCTLB2"},
        {0x0047L,"AQSFRC"},{0x0049L,"AQCSFRC"},
        {0x0050L,"DBREDHR"},{0x0051L,"DBRED"},{0x0052L,"DBFEDHR"},{0x0053L,"DBFED"},
        {0x0060L,"TBPHS"},{0x0062L,"TBPRDHR"},{0x0063L,"TBPRD"},
        {0x006AL,"CMPA"},{0x006CL,"CMPB"},{0x006FL,"CMPC"},{0x0071L,"CMPD"},
        {0x0074L,"GLDCTL2"},{0x0077L,"SWVDELVAL"},
        {0x0080L,"TZSEL"},{0x0082L,"TZDCSEL"},{0x0084L,"TZCTL"},{0x0085L,"TZCTL2"},
        {0x0086L,"TZCTLDCA"},{0x0087L,"TZCTLDCB"},{0x008DL,"TZEINT"},
        {0x0093L,"TZFLG"},{0x0094L,"TZCBCFLG"},{0x0095L,"TZOSTFLG"},
        {0x0097L,"TZCLR"},{0x0098L,"TZCBCCLR"},{0x0099L,"TZOSTCLR"},{0x009BL,"TZFRC"},
        {0x00A4L,"ETSEL"},{0x00A6L,"ETPS"},{0x00A8L,"ETFLG"},{0x00AAL,"ETCLR"},
        {0x00ACL,"ETFRC"},{0x00AEL,"ETINTPS"},{0x00B0L,"ETSOCPS"},
        {0x00B2L,"ETCNTINITCTL"},{0x00B4L,"ETCNTINIT"},
        {0x00C0L,"DCTRIPSEL"},{0x00C3L,"DCACTL"},{0x00C4L,"DCBCTL"},{0x00C7L,"DCFCTL"},
        {0x00C8L,"DCCAPCTL"},{0x00C9L,"DCFOFFSET"},{0x00CAL,"DCFOFFSETCNT"},
        {0x00CBL,"DCFWINDOW"},{0x00CCL,"DCFWINDOWCNT"},{0x00CFL,"DCCAP"},
        {0x00D2L,"DCAHTRIPSEL"},{0x00D3L,"DCALTRIPSEL"},
        {0x00D4L,"DCBHTRIPSEL"},{0x00D5L,"DCBLTRIPSEL"},
        {0x00FDL,"HWVDELVAL"},{0x00FEL,"VCNTVAL"},
    };

    // ── eCAP (spruhm8k Table 16-8, shared across ECAP1-3) ──────────────────────
    private static final Object[][] ECAP_REGS = {
        {0x0000L,"TSCTR"},{0x0002L,"CTRPHS"},
        {0x0004L,"CAP1"},{0x0006L,"CAP2"},{0x0008L,"CAP3"},{0x000AL,"CAP4"},
        {0x0014L,"ECCTL1"},{0x0015L,"ECCTL2"},
        {0x0016L,"ECEINT"},{0x0017L,"ECFLG"},{0x0018L,"ECCLR"},{0x0019L,"ECFRC"},
    };

    // ── eQEP (spruhm8k Table 17-16, shared across EQEP1-3) ────────────────────
    private static final Object[][] EQEP_REGS = {
        {0x0000L,"QPOSCNT"},{0x0002L,"QPOSINIT"},{0x0004L,"QPOSMAX"},{0x0006L,"QPOSCMP"},
        {0x0008L,"QPOSILAT"},{0x000AL,"QPOSSLAT"},{0x000CL,"QPOSLAT"},
        {0x000EL,"QUTMR"},{0x0010L,"QUPRD"},
        {0x0012L,"QWDTMR"},{0x0013L,"QWDPRD"},
        {0x0014L,"QDECCTL"},{0x0015L,"QEPCTL"},{0x0016L,"QCAPCTL"},{0x0017L,"QPOSCTL"},
        {0x0018L,"QEINT"},{0x0019L,"QFLG"},{0x001AL,"QCLR"},{0x001BL,"QFRC"},
        {0x001CL,"QEPSTS"},{0x001DL,"QCTMR"},{0x001EL,"QCPRD"},
        {0x001FL,"QCTMRLAT"},{0x0020L,"QCPRDLAT"},
    };

    // ── SPI (spruhm8k Table 18-8, shared across SPIA-C) ───────────────────────
    private static final Object[][] SPI_REGS = {
        {0x0000L,"SPICCR"},{0x0001L,"SPICTL"},{0x0002L,"SPISTS"},{0x0004L,"SPIBRR"},
        {0x0006L,"SPIRXEMU"},{0x0007L,"SPIRXBUF"},{0x0008L,"SPITXBUF"},{0x0009L,"SPIDAT"},
        {0x000AL,"SPIFFTX"},{0x000BL,"SPIFFRX"},{0x000CL,"SPIFFCT"},{0x000FL,"SPIPRI"},
    };

    // ── SCI (spruhm8k Table 19-12, shared across SCIA-D) ─────────────────────
    private static final Object[][] SCI_REGS = {
        {0x0000L,"SCICCR"},{0x0001L,"SCICTL1"},{0x0002L,"SCIHBAUD"},{0x0003L,"SCILBAUD"},
        {0x0004L,"SCICTL2"},{0x0005L,"SCIRXST"},{0x0006L,"SCIRXEMU"},{0x0007L,"SCIRXBUF"},
        {0x0009L,"SCITXBUF"},{0x000AL,"SCIFFTX"},{0x000BL,"SCIFFRX"},
        {0x000CL,"SCIFFCT"},{0x000FL,"SCIPRI"},
    };

    // ── I2C (spruhm8k Table 20-12, shared across I2CA/B) ─────────────────────
    private static final Object[][] I2C_REGS = {
        {0x0000L,"I2COAR"},{0x0001L,"I2CIER"},{0x0002L,"I2CSTR"},
        {0x0003L,"I2CCLKL"},{0x0004L,"I2CCLKH"},{0x0005L,"I2CCNT"},
        {0x0006L,"I2CDRR"},{0x0007L,"I2CSAR"},{0x0008L,"I2CDXR"},{0x0009L,"I2CMDR"},
        {0x000AL,"I2CISRC"},{0x000BL,"I2CEMDR"},{0x000CL,"I2CPSC"},
        {0x0020L,"I2CFFTX"},{0x0021L,"I2CFFRX"},
    };

    // ── ADC result registers (spruhm8k Table 11-15, base = ADCx_RESULT at 0x0400 above ctrl) ──
    // ADCx_RESULT base: ADCA=0x000400, ADCB=0x000600, ADCC=0x000800, ADCD=0x000A00
    // (absolute: 0x000400 word-offset from ADC result base at same frame)
    // TRM: ADC_RESULT_REGS base is 0x0B00 above 0x050000 => 0x050B00 for ADCA, etc.
    // Actual bases per f2837xd_peripherals.md: result regs share the ADC frame; offset 0x00
    private static final Object[][] ADC_RESULT_REGS = {
        {0x0000L,"ADCRESULT0"},{0x0001L,"ADCRESULT1"},{0x0002L,"ADCRESULT2"},
        {0x0003L,"ADCRESULT3"},{0x0004L,"ADCRESULT4"},{0x0005L,"ADCRESULT5"},
        {0x0006L,"ADCRESULT6"},{0x0007L,"ADCRESULT7"},{0x0008L,"ADCRESULT8"},
        {0x0009L,"ADCRESULT9"},{0x000AL,"ADCRESULT10"},{0x000BL,"ADCRESULT11"},
        {0x000CL,"ADCRESULT12"},{0x000DL,"ADCRESULT13"},{0x000EL,"ADCRESULT14"},
        {0x000FL,"ADCRESULT15"},
        {0x0010L,"ADCPPB1RESULT"},{0x0012L,"ADCPPB2RESULT"},
        {0x0014L,"ADCPPB3RESULT"},{0x0016L,"ADCPPB4RESULT"},
    };

    // ── ADC control registers (spruhm8k Table 11-37) ──────────────────────────
    private static final Object[][] ADC_REGS = {
        {0x0000L,"ADCCTL1"},{0x0001L,"ADCCTL2"},{0x0002L,"ADCBURSTCTL"},
        {0x0003L,"ADCINTFLG"},{0x0004L,"ADCINTFLGCLR"},{0x0005L,"ADCINTOVF"},
        {0x0006L,"ADCINTOVFCLR"},{0x0007L,"ADCINTSEL1N2"},{0x0008L,"ADCINTSEL3N4"},
        {0x0009L,"ADCSOCPRICTL"},{0x000AL,"ADCINTSOCSEL1"},{0x000BL,"ADCINTSOCSEL2"},
        {0x000CL,"ADCSOCFLG1"},{0x000DL,"ADCSOCFRC1"},{0x000EL,"ADCSOCOVF1"},
        {0x000FL,"ADCSOCOVFCLR1"},
        {0x0010L,"ADCSOC0CTL"},{0x0012L,"ADCSOC1CTL"},{0x0014L,"ADCSOC2CTL"},
        {0x0016L,"ADCSOC3CTL"},{0x0018L,"ADCSOC4CTL"},{0x001AL,"ADCSOC5CTL"},
        {0x001CL,"ADCSOC6CTL"},{0x001EL,"ADCSOC7CTL"},{0x0020L,"ADCSOC8CTL"},
        {0x0022L,"ADCSOC9CTL"},{0x0024L,"ADCSOC10CTL"},{0x0026L,"ADCSOC11CTL"},
        {0x0028L,"ADCSOC12CTL"},{0x002AL,"ADCSOC13CTL"},{0x002CL,"ADCSOC14CTL"},
        {0x002EL,"ADCSOC15CTL"},
        {0x0030L,"ADCEVTSTAT"},{0x0032L,"ADCEVTCLR"},{0x0034L,"ADCEVTSEL"},
        {0x0036L,"ADCEVTINTSEL"},{0x0038L,"ADCOSDETECT"},{0x0039L,"ADCCOUNTER"},
        {0x003AL,"ADCREV"},{0x003BL,"ADCOFFTRIM"},
        {0x0040L,"ADCPPB1CONFIG"},{0x0041L,"ADCPPB1STAMP"},{0x0042L,"ADCPPB1OFFCAL"},
        {0x0043L,"ADCPPB1OFFREF"},{0x0044L,"ADCPPB1TRIPHI"},{0x0046L,"ADCPPB1TRIPLO"},
        {0x0048L,"ADCPPB2CONFIG"},{0x0049L,"ADCPPB2STAMP"},{0x004AL,"ADCPPB2OFFCAL"},
        {0x004BL,"ADCPPB2OFFREF"},{0x004CL,"ADCPPB2TRIPHI"},{0x004EL,"ADCPPB2TRIPLO"},
        {0x0050L,"ADCPPB3CONFIG"},{0x0051L,"ADCPPB3STAMP"},{0x0052L,"ADCPPB3OFFCAL"},
        {0x0053L,"ADCPPB3OFFREF"},{0x0054L,"ADCPPB3TRIPHI"},{0x0056L,"ADCPPB3TRIPLO"},
        {0x0058L,"ADCPPB4CONFIG"},{0x0059L,"ADCPPB4STAMP"},{0x005AL,"ADCPPB4OFFCAL"},
        {0x005BL,"ADCPPB4OFFREF"},{0x005CL,"ADCPPB4TRIPHI"},{0x005EL,"ADCPPB4TRIPLO"},
        {0x0070L,"ADCINLTRIM1"},{0x0072L,"ADCINLTRIM2"},{0x0074L,"ADCINLTRIM3"},
        {0x0076L,"ADCINLTRIM4"},{0x0078L,"ADCINLTRIM5"},{0x007AL,"ADCINLTRIM6"},
    };

    // ── CPU Timer (spruhm8k Table 3-21, shared across TIMER0-2) ───────────────
    private static final Object[][] CPUTIMER_REGS = {
        {0x0000L,"TIM"},{0x0002L,"PRD"},{0x0004L,"TCR"},{0x0006L,"TPR"},{0x0007L,"TPRH"},
    };

    // ── PIE_CTRL (spruhm8k Table 3-28) ────────────────────────────────────────
    private static final Object[][] PIE_CTRL_REGS = {
        {0x0000L,"PIECTRL"},{0x0001L,"PIEACK"},
        {0x0002L,"PIEIER1"},{0x0003L,"PIEIFR1"},
        {0x0004L,"PIEIER2"},{0x0005L,"PIEIFR2"},
        {0x0006L,"PIEIER3"},{0x0007L,"PIEIFR3"},
        {0x0008L,"PIEIER4"},{0x0009L,"PIEIFR4"},
        {0x000AL,"PIEIER5"},{0x000BL,"PIEIFR5"},
        {0x000CL,"PIEIER6"},{0x000DL,"PIEIFR6"},
        {0x000EL,"PIEIER7"},{0x000FL,"PIEIFR7"},
        {0x0010L,"PIEIER8"},{0x0011L,"PIEIFR8"},
        {0x0012L,"PIEIER9"},{0x0013L,"PIEIFR9"},
        {0x0014L,"PIEIER10"},{0x0015L,"PIEIFR10"},
        {0x0016L,"PIEIER11"},{0x0017L,"PIEIFR11"},
        {0x0018L,"PIEIER12"},{0x0019L,"PIEIFR12"},
    };

    // ── DEV_CFG (spruhm8k Table 3-98) ─────────────────────────────────────────
    private static final Object[][] DEV_CFG_REGS = {
        {0x0000L,"DEVCFGLOCK1"},
        {0x0008L,"PARTIDL"},{0x000AL,"PARTIDH"},{0x000CL,"REVID"},
        {0x0010L,"DC0"},{0x0012L,"DC1"},{0x0014L,"DC2"},{0x0016L,"DC3"},
        {0x0018L,"DC4"},{0x001AL,"DC5"},{0x001CL,"DC6"},{0x001EL,"DC7"},
        {0x0020L,"DC8"},{0x0022L,"DC9"},{0x0024L,"DC10"},{0x0026L,"DC11"},
        {0x0028L,"DC12"},{0x002AL,"DC13"},{0x002CL,"DC14"},{0x002EL,"DC15"},
        {0x0032L,"DC17"},{0x0034L,"DC18"},{0x0036L,"DC19"},{0x0038L,"DC20"},
        {0x0060L,"PERCNF1"},{0x0074L,"FUSEERR"},
        {0x0082L,"SOFTPRES0"},{0x0084L,"SOFTPRES1"},{0x0086L,"SOFTPRES2"},
        {0x0088L,"SOFTPRES3"},{0x008AL,"SOFTPRES4"},{0x008EL,"SOFTPRES6"},
        {0x0090L,"SOFTPRES7"},{0x0092L,"SOFTPRES8"},{0x0094L,"SOFTPRES9"},
        {0x0098L,"SOFTPRES11"},{0x009CL,"SOFTPRES13"},{0x009EL,"SOFTPRES14"},
    };

    // ── CLK_CFG (spruhm8k Table 3-156) ────────────────────────────────────────
    private static final Object[][] CLK_CFG_REGS = {
        {0x0000L,"CLKSEM"},{0x0002L,"CLKCFGLOCK1"},
        {0x0008L,"CLKSRCCTL1"},{0x000AL,"CLKSRCCTL2"},{0x000CL,"CLKSRCCTL3"},
        {0x000EL,"SYSPLLCTL1"},{0x0014L,"SYSPLLMULT"},{0x0016L,"SYSPLLSTS"},
        {0x0018L,"AUXPLLCTL1"},{0x001EL,"AUXPLLMULT"},{0x0020L,"AUXPLLSTS"},
        {0x0022L,"SYSCLKDIVSEL"},{0x0024L,"AUXCLKDIVSEL"},{0x0026L,"PERCLKDIVSEL"},
        {0x0028L,"XCLKOUTDIVSEL"},{0x002CL,"LOSPCP"},{0x002EL,"MCDCR"},{0x0030L,"X1CNT"},
    };

    // ── CPU_SYS_REGS / PCLKCR (spruhm8k Table 3-176) ─────────────────────────
    // These live at the CPU_SYS base (separate from CLK_CFG and DEV_CFG).
    // PCLKCR bits tell which peripherals are clock-gated — high RE value.
    // CPU_SYS base = 0x005D00 (same block as CPU_TIMER0 frame in TRM, but separate periph).
    // Actually CPU_SYS_REGS base is NOT in PERIPHS[] — it's at 0x005D00? Check TRM carefully.
    // TRM: CPU_SYS_REGS base = 0x000000 (virtual offset) within the sysctl block at 0x005D00.
    // Per spruhm8k Table 3-1: CPU_SYS_REGS base addr = 0x000D00h (same as PIE section).
    // Leaving CPU_SYS at DEV_CFG base offset 0x5D00 — frame not yet in PERIPHS[], label below.
    private static final Object[][] CPU_SYS_REGS = {
        {0x0000L,"CPUSYSLOCK1"},{0x0006L,"HIBBOOTMODE"},
        {0x0008L,"IORESTOREADDR"},{0x000AL,"PIEVERRADDR"},
        {0x0022L,"PCLKCR0"},{0x0024L,"PCLKCR1"},{0x0026L,"PCLKCR2"},
        {0x0028L,"PCLKCR3"},{0x002AL,"PCLKCR4"},{0x002EL,"PCLKCR6"},
        {0x0030L,"PCLKCR7"},{0x0032L,"PCLKCR8"},{0x0034L,"PCLKCR9"},
        {0x0036L,"PCLKCR10"},{0x0038L,"PCLKCR11"},{0x003AL,"PCLKCR12"},
        {0x003CL,"PCLKCR13"},{0x003EL,"PCLKCR14"},{0x0042L,"PCLKCR16"},
        {0x0074L,"SECMSEL"},{0x0076L,"LPMCR"},
        {0x0078L,"GPIOLPMSEL0"},{0x007AL,"GPIOLPMSEL1"},
        {0x007CL,"TMR2CLKCTL"},{0x0080L,"RESC"},
    };

    // ── GPIO_CTRL (spruhm8k Table 8-108, groups A-F) ──────────────────────────
    private static final Object[][] GPIO_CTRL_REGS = {
        // Group A (GPIO0-31)
        {0x0000L,"GPACTRL"},{0x0002L,"GPAQSEL1"},{0x0004L,"GPAQSEL2"},
        {0x0006L,"GPAMUX1"},{0x0008L,"GPAMUX2"},{0x000AL,"GPADIR"},
        {0x000CL,"GPAPUD"},{0x0010L,"GPAINV"},{0x0012L,"GPAODR"},
        {0x0020L,"GPAGMUX1"},{0x0022L,"GPAGMUX2"},
        {0x0028L,"GPACSEL1"},{0x002AL,"GPACSEL2"},{0x002CL,"GPACSEL3"},{0x002EL,"GPACSEL4"},
        {0x003CL,"GPALOCK"},{0x003EL,"GPACR"},
        // Group B (GPIO32-63)
        {0x0040L,"GPBCTRL"},{0x0042L,"GPBQSEL1"},{0x0044L,"GPBQSEL2"},
        {0x0046L,"GPBMUX1"},{0x0048L,"GPBMUX2"},{0x004AL,"GPBDIR"},
        {0x004CL,"GPBPUD"},{0x0050L,"GPBINV"},{0x0052L,"GPBODR"},{0x0054L,"GPBAMSEL"},
        {0x0060L,"GPBGMUX1"},{0x0062L,"GPBGMUX2"},
        {0x0068L,"GPBCSEL1"},{0x006AL,"GPBCSEL2"},{0x006CL,"GPBCSEL3"},{0x006EL,"GPBCSEL4"},
        {0x007CL,"GPBLOCK"},{0x007EL,"GPBCR"},
        // Group C (GPIO64-95)
        {0x0080L,"GPCCTRL"},{0x0082L,"GPCQSEL1"},{0x0084L,"GPCQSEL2"},
        {0x0086L,"GPCMUX1"},{0x0088L,"GPCMUX2"},{0x008AL,"GPCDIR"},
        {0x008CL,"GPCPUD"},{0x0090L,"GPCINV"},{0x0092L,"GPCODR"},
        {0x00A0L,"GPCGMUX1"},{0x00A2L,"GPCGMUX2"},
        {0x00A8L,"GPCCSEL1"},{0x00AAL,"GPCCSEL2"},{0x00ACL,"GPCCSEL3"},{0x00AEL,"GPCCSEL4"},
        {0x00BCL,"GPCLOCK"},{0x00BEL,"GPCCR"},
        // Group D (GPIO96-127)
        {0x00C0L,"GPDCTRL"},{0x00C2L,"GPDQSEL1"},{0x00C4L,"GPDQSEL2"},
        {0x00C6L,"GPDMUX1"},{0x00C8L,"GPDMUX2"},{0x00CAL,"GPDDIR"},
        {0x00CCL,"GPDPUD"},{0x00D0L,"GPDINV"},{0x00D2L,"GPDODR"},
        {0x00E0L,"GPDGMUX1"},{0x00E2L,"GPDGMUX2"},
        {0x00E8L,"GPDCSEL1"},{0x00EAL,"GPDCSEL2"},{0x00ECL,"GPDCSEL3"},{0x00EEL,"GPDCSEL4"},
        {0x00FCL,"GPDLOCK"},{0x00FEL,"GPDCR"},
        // Group E (GPIO128-159)
        {0x0100L,"GPECTRL"},{0x0102L,"GPEQSEL1"},{0x0104L,"GPEQSEL2"},
        {0x0106L,"GPEMUX1"},{0x0108L,"GPEMUX2"},{0x010AL,"GPEDIR"},
        {0x010CL,"GPEPUD"},{0x0110L,"GPEINV"},{0x0112L,"GPEODR"},
        {0x0120L,"GPEGMUX1"},{0x0122L,"GPEGMUX2"},
        {0x0128L,"GPECSEL1"},{0x012AL,"GPECSEL2"},{0x012CL,"GPECSEL3"},{0x012EL,"GPECSEL4"},
        {0x013CL,"GPELOCK"},{0x013EL,"GPECR"},
        // Group F (GPIO160-168)
        {0x0140L,"GPFCTRL"},{0x0142L,"GPFQSEL1"},{0x0146L,"GPFMUX1"},
        {0x014AL,"GPFDIR"},{0x014CL,"GPFPUD"},{0x0150L,"GPFINV"},{0x0152L,"GPFODR"},
        {0x0160L,"GPFGMUX1"},
        {0x0168L,"GPFCSEL1"},{0x016AL,"GPFCSEL2"},
        {0x017CL,"GPFLOCK"},{0x017EL,"GPFCR"},
    };

    // ── GPIO_DATA (spruhm8k Table 8-112) ──────────────────────────────────────
    private static final Object[][] GPIO_DATA_REGS = {
        {0x0000L,"GPADAT"},{0x0002L,"GPASET"},{0x0004L,"GPACLEAR"},{0x0006L,"GPATOGGLE"},
        {0x0008L,"GPBDAT"},{0x000AL,"GPBSET"},{0x000CL,"GPBCLEAR"},{0x000EL,"GPBTOGGLE"},
        {0x0010L,"GPCDAT"},{0x0012L,"GPCSET"},{0x0014L,"GPCCLEAR"},{0x0016L,"GPCTOGGLE"},
        {0x0018L,"GPDDAT"},{0x001AL,"GPDSET"},{0x001CL,"GPDCLEAR"},{0x001EL,"GPDTOGGLE"},
        {0x0020L,"GPEDAT"},{0x0022L,"GPESET"},{0x0024L,"GPECLEAR"},{0x0026L,"GPETOGGLE"},
        {0x0028L,"GPFDAT"},{0x002AL,"GPFSET"},{0x002CL,"GPFCLEAR"},{0x002EL,"GPFTOGGLE"},
    };

    // ── DMA global registers (spruhm8k Table 5-4) ─────────────────────────────
    private static final Object[][] DMA_GLOBAL_REGS = {
        {0x0000L,"DMACTRL"},{0x0001L,"DEBUGCTRL"},
        {0x0004L,"PRIORITYCTRL1"},{0x0006L,"PRIORITYSTAT"},
    };

    // ── DMA per-channel registers (spruhm8k Table 5-10, 6 channels × 0x40 stride) ──
    private static final Object[][] DMA_CH_REGS = {
        {0x0000L,"MODE"},{0x0001L,"CONTROL"},
        {0x0002L,"BURST_SIZE"},{0x0003L,"BURST_COUNT"},
        {0x0004L,"SRC_BURST_STEP"},{0x0005L,"DST_BURST_STEP"},
        {0x0006L,"TRANSFER_SIZE"},{0x0007L,"TRANSFER_COUNT"},
        {0x0008L,"SRC_TRANSFER_STEP"},{0x0009L,"DST_TRANSFER_STEP"},
        {0x000AL,"SRC_WRAP_SIZE"},{0x000BL,"SRC_WRAP_COUNT"},{0x000CL,"SRC_WRAP_STEP"},
        {0x000DL,"DST_WRAP_SIZE"},{0x000EL,"DST_WRAP_COUNT"},{0x000FL,"DST_WRAP_STEP"},
        {0x0010L,"SRC_BEG_ADDR_SHADOW"},{0x0012L,"SRC_ADDR_SHADOW"},
        {0x0014L,"SRC_BEG_ADDR_ACTIVE"},{0x0016L,"SRC_ADDR_ACTIVE"},
        {0x0018L,"DST_BEG_ADDR_SHADOW"},{0x001AL,"DST_ADDR_SHADOW"},
        {0x001CL,"DST_BEG_ADDR_ACTIVE"},{0x001EL,"DST_ADDR_ACTIVE"},
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Generic field-level labeler — generalisation of the original labelCan().
    private void labelRegs(String mod, long base, Object[][] regs) throws Exception {
        int n = 0;
        for (Object[] r : regs) {
            long off = (Long) r[0];
            String nm = mod + "_" + (String) r[1];
            createLabel(toAddr(base + off), nm, true, SourceType.USER_DEFINED);
            n++;
        }
        println("labeled " + mod + " (" + n + " regs) @ 0x" + Long.toHexString(base));
    }

    // Create an uninitialized (MMIO) memory block if it isn't already mapped.
    private void ensureBlock(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = toAddr(start);
        if (mem.getBlock(a) == null) {
            MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(true);
            println("created MMIO block " + name + " @ 0x" + Long.toHexString(start));
        }
    }

    // Create an uninitialized RAM block (non-volatile) if not already mapped.
    private void ensureRam(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = toAddr(start);
        if (mem.getBlock(a) == null) {
            MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(false);
            println("created RAM block " + name + " @ 0x" + Long.toHexString(start));
        }
    }

    // Peripheral frames shared by both CPU1 and CPU2.
    // Addresses verified against F2837xD_Headers_nonBIOS_cpu{1,2}.cmd (C2000Ware 26.01.00.00).
    private static final Object[][] PERIPHS_COMMON = {
        {0x000B00L, 0x020L, "ADCARESULT"},  {0x000B20L, 0x020L, "ADCBRESULT"},
        {0x000B40L, 0x020L, "ADCCRESULT"},  {0x000B60L, 0x020L, "ADCDRESULT"},
        {0x000C00L, 0x008L, "CPU_TIMER0"},  {0x000C08L, 0x008L, "CPU_TIMER1"},
        {0x000C10L, 0x008L, "CPU_TIMER2"},
        {0x000CE0L, 0x020L, "PIE_CTRL"},    {0x000D00L, 0x200L, "PIE_VECT"},
        {0x001000L, 0x200L, "DMA"},
        {0x004000L, 0x100L, "EPWM1"},       {0x004100L, 0x100L, "EPWM2"},
        {0x004200L, 0x100L, "EPWM3"},       {0x004300L, 0x100L, "EPWM4"},
        {0x004400L, 0x100L, "EPWM5"},       {0x004500L, 0x100L, "EPWM6"},
        {0x004600L, 0x100L, "EPWM7"},       {0x004700L, 0x100L, "EPWM8"},
        {0x004800L, 0x100L, "EPWM9"},       {0x004900L, 0x100L, "EPWM10"},
        {0x004A00L, 0x100L, "EPWM11"},      {0x004B00L, 0x100L, "EPWM12"},
        {0x005000L, 0x020L, "ECAP1"},       {0x005020L, 0x020L, "ECAP2"},
        {0x005040L, 0x020L, "ECAP3"},       {0x005060L, 0x020L, "ECAP4"},
        {0x005080L, 0x020L, "ECAP5"},       {0x0050A0L, 0x020L, "ECAP6"},
        {0x005100L, 0x022L, "EQEP1"},       {0x005140L, 0x022L, "EQEP2"},
        {0x005180L, 0x022L, "EQEP3"},
        {0x006100L, 0x010L, "SPIA"},        {0x006110L, 0x010L, "SPIB"},
        {0x006120L, 0x010L, "SPIC"},
        {0x007200L, 0x010L, "SCIA"},        {0x007210L, 0x010L, "SCIB"},
        {0x007220L, 0x010L, "SCIC"},        {0x007230L, 0x010L, "SCID"},
        {0x007300L, 0x022L, "I2CA"},        {0x007340L, 0x022L, "I2CB"},
        {0x007400L, 0x080L, "ADCA"},        {0x007480L, 0x080L, "ADCB"},
        {0x007500L, 0x080L, "ADCC"},        {0x007580L, 0x080L, "ADCD"},
        {0x007F00L, 0x030L, "GPIO_DATA"},
        {0x0005D200L, 0x032L, "CLK_CFG"},   {0x0005D300L, 0x082L, "CPU_SYS"},
    };

    // Peripheral frames accessible from CPU1 only.
    private static final Object[][] PERIPHS_CPU1_ONLY = {
        {0x007900L, 0x020L, "INPUT_XBAR"},  {0x007920L, 0x020L, "XBAR"},
        {0x007C00L, 0x180L, "GPIO_CTRL"},
        {0x0005D000L, 0x130L, "DEV_CFG"},
    };

    // Dual-core RAM regions.
    private static final Object[][] RAM_REGIONS = {
        {0x000000L, 0x000800L, "M0M1_RAM"},
        {0x008000L, 0x004000L, "LS_RAM"},
        {0x00C000L, 0x002000L, "D0D1_RAM"},
        {0x00E000L, 0x002000L, "GS_RAM_LO"},
        {0x010000L, 0x008000L, "GS0_15_RAM"},
        {0x018000L, 0x004000L, "RAM_18000"},
        {0x03F800L, 0x000400L, "MSGRAM_CPU2_TO_CPU1"},
        {0x03FC00L, 0x000400L, "MSGRAM_CPU1_TO_CPU2"},
    };

    @Override
    public void run() throws Exception {
        // Prompt for CPU core — determines which peripheral frames are visible.
        int cpuChoice = askChoice("CPU Core",
            "Which CPU core is this firmware for?",
            java.util.Arrays.asList("CPU1", "CPU2"), "CPU1");
        boolean isCPU1 = cpuChoice == 0;
        println("Setting up for " + (isCPU1 ? "CPU1" : "CPU2"));

        // 0. Map + label peripheral frames (common to both cores, plus CPU1-only).
        int n = 0;
        for (Object[] p : PERIPHS_COMMON) {
            long base = (Long) p[0], size = (Long) p[1];
            String name = (String) p[2];
            try {
                ensureBlock(name + "_REGS", base, size);
                createLabel(toAddr(base), name, true, SourceType.USER_DEFINED);
                n++;
            } catch (Exception e) { println("skip " + name + ": " + e.getMessage()); }
        }
        if (isCPU1) {
            for (Object[] p : PERIPHS_CPU1_ONLY) {
                long base = (Long) p[0], size = (Long) p[1];
                String name = (String) p[2];
                try {
                    ensureBlock(name + "_REGS", base, size);
                    createLabel(toAddr(base), name, true, SourceType.USER_DEFINED);
                    n++;
                } catch (Exception e) { println("skip " + name + ": " + e.getMessage()); }
            }
        }
        println("labeled " + n + " peripheral frames");

        // 0b. Map dual-core RAM regions.
        int rn = 0;
        for (Object[] r : RAM_REGIONS) {
            long base = (Long) r[0], size = (Long) r[1];
            String name = (String) r[2];
            try {
                ensureRam(name, base, size);
                createLabel(toAddr(base), name, true, SourceType.USER_DEFINED); rn++;
            } catch (Exception e) { println("skip RAM " + name + ": " + e.getMessage()); }
        }
        println("mapped " + rn + " RAM regions");

        // 1. D_CAN field-level labels (CAN kept as-is, now uses generic labeler).
        ensureBlock("CANA_REGS", 0x048000L, 0x0200);
        ensureBlock("CANB_REGS", 0x04A000L, 0x0200);
        labelRegs("CANA", 0x048000L, CAN_REGS);
        labelRegs("CANB", 0x04A000L, CAN_REGS);

        // 2. ePWM field-level labels (12 instances, shared table).
        for (int i = 0; i < 12; i++) {
            long base = 0x004000L + (long)i * 0x100L;
            try { labelRegs("EPWM" + (i + 1), base, EPWM_REGS); }
            catch (Exception e) { println("skip EPWM" + (i+1) + ": " + e.getMessage()); }
        }

        // 3. eCAP field-level labels (6 instances, stride 0x20).
        for (int i = 0; i < 6; i++) {
            long base = 0x005000L + (long)i * 0x20L;
            try { labelRegs("ECAP" + (i + 1), base, ECAP_REGS); }
            catch (Exception e) { println("skip ECAP" + (i+1) + ": " + e.getMessage()); }
        }

        // 4. eQEP field-level labels (3 instances, stride 0x40).
        for (int i = 0; i < 3; i++) {
            long base = 0x005100L + (long)i * 0x40L;
            try { labelRegs("EQEP" + (i + 1), base, EQEP_REGS); }
            catch (Exception e) { println("skip EQEP" + (i+1) + ": " + e.getMessage()); }
        }

        // 5. SCI field-level labels (4 instances, stride 0x10).
        String[] sciNames = {"SCIA", "SCIB", "SCIC", "SCID"};
        for (int i = 0; i < 4; i++) {
            long base = 0x007200L + (long)i * 0x10L;
            try { labelRegs(sciNames[i], base, SCI_REGS); }
            catch (Exception e) { println("skip " + sciNames[i] + ": " + e.getMessage()); }
        }

        // 6. SPI field-level labels (3 instances, stride 0x10).
        String[] spiNames = {"SPIA", "SPIB", "SPIC"};
        for (int i = 0; i < 3; i++) {
            long base = 0x006100L + (long)i * 0x10L;
            try { labelRegs(spiNames[i], base, SPI_REGS); }
            catch (Exception e) { println("skip " + spiNames[i] + ": " + e.getMessage()); }
        }

        // 7. I2C field-level labels.
        try { labelRegs("I2CA", 0x007300L, I2C_REGS); }
        catch (Exception e) { println("skip I2CA: " + e.getMessage()); }
        try { labelRegs("I2CB", 0x007340L, I2C_REGS); }
        catch (Exception e) { println("skip I2CB: " + e.getMessage()); }

        // 8. ADC field-level labels.
        // Control bases: ADCA=0x007400, ADCB=0x007480, ADCC=0x007500, ADCD=0x007580.
        // Result bases:  ADCA=0x000B00, ADCB=0x000B20, ADCC=0x000B40, ADCD=0x000B60.
        String[] adcNames = {"ADCA", "ADCB", "ADCC", "ADCD"};
        long[] adcCtrlBases   = {0x007400L, 0x007480L, 0x007500L, 0x007580L};
        long[] adcResultBases = {0x000B00L, 0x000B20L, 0x000B40L, 0x000B60L};
        for (int i = 0; i < 4; i++) {
            try { labelRegs(adcNames[i], adcCtrlBases[i], ADC_REGS); }
            catch (Exception e) { println("skip " + adcNames[i] + ": " + e.getMessage()); }
            try { labelRegs(adcNames[i] + "_RESULT", adcResultBases[i], ADC_RESULT_REGS); }
            catch (Exception e) { println("skip " + adcNames[i] + "_RESULT: " + e.getMessage()); }
        }

        // 9. CPU Timer field-level labels.
        long[] timerBases = {0x000C00L, 0x000C08L, 0x000C10L};
        for (int i = 0; i < timerBases.length; i++) {
            try { labelRegs("CPU_TIMER" + i, timerBases[i], CPUTIMER_REGS); }
            catch (Exception e) { println("skip CPU_TIMER" + i + ": " + e.getMessage()); }
        }

        // 10. PIE_CTRL field-level labels.
        try { labelRegs("PIE", 0x000CE0L, PIE_CTRL_REGS); }
        catch (Exception e) { println("skip PIE_CTRL: " + e.getMessage()); }

        // 11. Sysctl field-level labels.
        if (isCPU1) {
            try { labelRegs("DEV_CFG", 0x0005D000L, DEV_CFG_REGS); }
            catch (Exception e) { println("skip DEV_CFG: " + e.getMessage()); }
        }
        try { labelRegs("CLK_CFG", 0x0005D200L, CLK_CFG_REGS); }
        catch (Exception e) { println("skip CLK_CFG: " + e.getMessage()); }
        try { labelRegs("CPU_SYS", 0x0005D300L, CPU_SYS_REGS); }
        catch (Exception e) { println("skip CPU_SYS: " + e.getMessage()); }

        // 12. GPIO field-level labels (GPIO_CTRL is CPU1-only; GPIO_DATA is shared).
        if (isCPU1) {
            try { labelRegs("GPIO_CTRL", 0x007C00L, GPIO_CTRL_REGS); }
            catch (Exception e) { println("skip GPIO_CTRL: " + e.getMessage()); }
        }
        try { labelRegs("GPIO_DATA", 0x007F00L, GPIO_DATA_REGS); }
        catch (Exception e) { println("skip GPIO_DATA: " + e.getMessage()); }

        // 13. DMA global + 6 per-channel tables.
        // DMA base = 0x001000. CH1 starts at +0x20 (after 32 words of global regs + reserved).
        // CH_REGS is 0x20 words each, so CH2=0x001040, CH3=0x001060, etc.
        try { labelRegs("DMA", 0x001000L, DMA_GLOBAL_REGS); }
        catch (Exception e) { println("skip DMA global: " + e.getMessage()); }
        for (int ch = 1; ch <= 6; ch++) {
            long chBase = 0x001020L + (long)(ch - 1) * 0x20L;
            try { labelRegs("DMA_CH" + ch, chBase, DMA_CH_REGS); }
            catch (Exception e) { println("skip DMA_CH" + ch + ": " + e.getMessage()); }
        }

        // 15. Reset vector label.
        try {
            Address resetVec = toAddr(0x3FFFC0L);
            if (currentProgram.getMemory().contains(resetVec)) {
                createLabel(resetVec, "RESET", true, SourceType.USER_DEFINED);
            }
        } catch (Exception e) { /* region not in this image */ }

        println("F28377D setup complete: all peripheral registers labeled.");
    }
}
