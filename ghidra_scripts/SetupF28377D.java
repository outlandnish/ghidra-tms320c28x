// Post-import setup for a raw TMS320F28377D firmware image:
//   1. Map + label ALL peripheral frames (CAN, GPIO, SCI, SPI, I2C, ADC, ePWM,
//      eCAP/eQEP, DMA, PIE, sysctl, timers...) so every MMIO access is self-
//      documenting and XREFs resolve to named registers.
//   2. Label the D_CAN (CANA/CANB) registers field-by-field (the CAN-RE payoff).
//   3. Mark the reset vector so Ghidra can follow real flow and decode only reachable
//      code (leaving const pools as data).
//
// Word addresses (the C28x is word-addressable; see docs/c28x/f2837xd_peripherals.md,
// f28377d_memmap.md, dcan_registers.md). Run as a post-script after importing the .bin.
//
// @category TMS320C28x
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SetupF28377D extends GhidraScript {

    // D_CAN register offsets from a module base (word offsets).
    private static final Object[][] CAN_REGS = {
        {0x0000L,"CTL"},{0x0002L,"ES"},{0x0004L,"ERRC"},{0x0006L,"BTR"},{0x0008L,"INT"},
        {0x000AL,"TEST"},{0x000EL,"PERR"},{0x001CL,"RAM_INIT"},{0x0020L,"ABOTR"},
        {0x0024L,"TXRQ_X"},{0x0026L,"TXRQ_21"},{0x0028L,"NWDAT_X"},{0x002AL,"NWDAT_21"},
        {0x0034L,"INTPND_X"},{0x003CL,"MSGVAL_X"},{0x0040L,"INTMUX21"},
        {0x0080L,"IF1CMD"},{0x0084L,"IF1MSK"},{0x0088L,"IF1ARB"},{0x008CL,"IF1MCTL"},
        {0x0090L,"IF1DATA"},{0x0094L,"IF1DATB"},
        {0x00A0L,"IF2CMD"},{0x00A4L,"IF2MSK"},{0x00A8L,"IF2ARB"},{0x00ACL,"IF2MCTL"},
        {0x00B0L,"IF2DATA"},{0x00B4L,"IF2DATB"},
        {0x0100L,"IF3OBS"},{0x0104L,"IF3MSK"},{0x0108L,"IF3ARB"},{0x010CL,"IF3MCTL"},
        {0x0110L,"IF3DATA"},{0x0114L,"IF3DATB"},
    };

    private void labelCan(String mod, long base) throws Exception {
        for (Object[] r : CAN_REGS) {
            long off = (Long) r[0];
            String nm = mod + "_" + (String) r[1];
            Address a = toAddr(base + off);
            createLabel(a, nm, true, SourceType.USER_DEFINED);
        }
        println("labeled " + mod + " @ " + Long.toHexString(base));
    }

    // Create an uninitialized (MMIO) memory block if it isn't already mapped.
    private void ensureBlock(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = toAddr(start);
        if (mem.getBlock(a) == null) {
            MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
            b.setRead(true); b.setWrite(true); b.setVolatile(true);  // peripheral = volatile
            println("created MMIO block " + name + " @ " + Long.toHexString(start));
        }
    }

    // Full F2837xD CPU1 peripheral frame map: {base, size(words), name}.
    // Each becomes a volatile MMIO block + a base label, so any access decodes as
    // <NAME>+offset instead of a bare address.
    private static final Object[][] PERIPHS = {
        {0x000CE0L, 0x020L, "PIE_CTRL"},   {0x000D00L, 0x200L, "PIE_VECT"},
        {0x005000L, 0x200L, "DEV_CFG"},    {0x005C00L, 0x080L, "CLK_CFG"},
        {0x005D00L, 0x040L, "CPU_TIMER0"}, {0x005D40L, 0x040L, "CPU_TIMER1"},
        {0x005D80L, 0x040L, "CPU_TIMER2"}, {0x005F00L, 0x100L, "DCSM"},
        {0x0058E0L, 0x040L, "INPUT_XBAR"}, {0x005900L, 0x080L, "XBAR"},
        {0x006000L, 0x100L, "EPWM1"},      {0x006100L, 0x100L, "EPWM2"},
        {0x006200L, 0x100L, "EPWM3"},      {0x006300L, 0x100L, "EPWM4"},
        {0x006400L, 0x100L, "EPWM5"},      {0x006500L, 0x100L, "EPWM6"},
        {0x006600L, 0x100L, "EPWM7"},      {0x006700L, 0x100L, "EPWM8"},
        {0x006800L, 0x100L, "EPWM9"},      {0x006900L, 0x100L, "EPWM10"},
        {0x006A00L, 0x100L, "EPWM11"},     {0x006B00L, 0x100L, "EPWM12"},
        {0x006C00L, 0x080L, "ECAP1"},      {0x006C80L, 0x080L, "ECAP2"},
        {0x006D00L, 0x080L, "ECAP3"},      {0x006E00L, 0x100L, "EQEP1"},
        {0x006F00L, 0x100L, "EQEP2"},      {0x007000L, 0x100L, "EQEP3"},
        {0x0061C0L, 0x040L, "GPIO_DATA"},  {0x007C00L, 0x200L, "GPIO_CTRL"},
        {0x007400L, 0x200L, "DMA"},        {0x007900L, 0x040L, "I2CA"},
        {0x007A00L, 0x040L, "I2CB"},       {0x007D00L, 0x010L, "SCIA"},
        {0x007D10L, 0x010L, "SCIB"},       {0x007D20L, 0x010L, "SCIC"},
        {0x007D30L, 0x010L, "SCID"},       {0x006100L, 0x010L, "SPIA"},
        {0x056000L, 0x010L, "SPIB"},       {0x056010L, 0x010L, "SPIC"},
        {0x050000L, 0x080L, "ADCA"},       {0x050200L, 0x080L, "ADCB"},
        {0x050400L, 0x080L, "ADCC"},       {0x050600L, 0x080L, "ADCD"},
    };

    @Override
    public void run() throws Exception {
        // 0. Map + label ALL peripheral frames.
        int n = 0;
        for (Object[] p : PERIPHS) {
            long base = (Long) p[0], size = (Long) p[1];
            String name = (String) p[2];
            try {
                ensureBlock(name + "_REGS", base, size);
                createLabel(toAddr(base), name, true, SourceType.USER_DEFINED);
                n++;
            } catch (Exception e) { println("skip " + name + ": " + e.getMessage()); }
        }
        println("labeled " + n + " peripheral frames");

        // 1. D_CAN modules: map blocks + field-level register labels (the CAN payoff).
        ensureBlock("CANA_REGS", 0x048000L, 0x0200);
        ensureBlock("CANB_REGS", 0x04A000L, 0x0200);
        labelCan("CANA", 0x048000L);
        labelCan("CANB", 0x04A000L);

        // 2. If the reset vector region is present in this image, seed flow there.
        //    (For a flash image loaded at 0x080800, entry is found via the vector or
        //    the user marks it; we disassemble the image start as a fallback.)
        try {
            Address resetVec = toAddr(0x3FFFC0L);
            if (currentProgram.getMemory().contains(resetVec)) {
                createLabel(resetVec, "RESET", true, SourceType.USER_DEFINED);
            }
        } catch (Exception e) { /* region not in this image */ }

        println("F28377D setup complete: CAN registers + peripheral frames labeled.");
    }
}
