# TMS320F2837xD peripheral base addresses (CPU1, word addresses)

| Base      | Peripheral            | Base      | Peripheral            |
|-----------|-----------------------|-----------|-----------------------|
| 0x000000  | M0 RAM                 | 0x005F00 | DCSM_Z1 (sec)         |
| 0x000800  | M1 RAM                 | 0x005F40 | DCSM_Z2 (sec)         |
| 0x000CE0  | PIE_CTRL               | 0x005F80 | DCSM_COMMON           |
| 0x000D00  | PIE_VECT (192 vectors) | 0x006000 | EPWM1                 |
| 0x004000  | reserved/OTP-adj       | 0x006100 | EPWM2                 |
| 0x005000  | DEV_CFG (sysctl)       | 0x006200 | EPWM3                 |
| 0x005C00  | CLK_CFG                | 0x006300 | EPWM4                 |
| 0x005D00  | CPU_TIMER0             | 0x006400 | EPWM5                 |
| 0x005D40  | CPU_TIMER1             | 0x006500 | EPWM6                 |
| 0x005D80  | CPU_TIMER2             | 0x006600 | EPWM7                 |
| 0x005E00  | PIE_reserved           | 0x006700 | EPWM8                 |
| 0x006800  | EPWM9..12 (0x100 each) | 0x006C00 | ECAP1                 |
| 0x006C00  | ECAP1                  | 0x006C80 | ECAP2                 |
| 0x006D00  | ECAP3                  | 0x006E00 | EQEP1                 |
| 0x006F00  | EQEP2                  | 0x007000 | EQEP3                 |
| 0x007040  | EQEP (cont)            | 0x007100 | reserved              |
| 0x007400  | DMA                    | 0x007700 | reserved              |
| 0x007900  | I2CA                   | 0x007A00 | I2CB                  |
| 0x007B00  | reserved               | 0x007D00 | SCIA                  |
| 0x007D10  | SCIB                   | 0x007D20 | SCIC                  |
| 0x007D30  | SCID                   | 0x007E00 | reserved              |
| 0x006FC0  | reserved               | 0x00C000 | (D0/D1 RAM)           |
| 0x040000  | reserved               | 0x048000 | **CANA (D_CAN)**      |
| 0x04A000  | **CANB (D_CAN)**       | 0x050000 | ADCA result/ctrl      |
| 0x050200  | ADCB                   | 0x050400 | ADCC                  |
| 0x050600  | ADCD                   | 0x056000 | SPI A/B/C frames      |
| 0x0061C0  | GPIO_DATA              | 0x007C00 | GPIO_CTRL             |
| 0x0058E0  | XBAR / INPUTXBAR       | 0x006400 | (CMPSS via analog)    |

Notes:
- SCI = serial (UART), SPI = serial, I2C = serial, ECAP/EQEP/EPWM = motor-control PWM/capture.
- The CAN modules (CANA/CANB) are the focus; GPIO/PIE/SCI commonly appear alongside CAN setup.
- Exact bases vary slightly by TRM rev; these are the standard F2837xD CPU1 values.
