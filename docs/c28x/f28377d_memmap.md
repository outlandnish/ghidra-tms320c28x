# TMS320F28377D memory map (CPU1) — word addresses

The C28x has a unified address space (program + data overlap above the low RAM).
Key regions for loading firmware and separating code from data:

| Range (word addr)      | Size   | Type        | Notes |
|------------------------|--------|-------------|-------|
| 0x000000–0x0007FF      | 2K     | RAM (M0/M1) | low RAM; M1 holds boot stack (SP reset=0x400) |
| 0x000800–0x000CFF      | RAM    | data        | peripheral-frame-0-adjacent RAM |
| 0x000D00–0x000FFF      | CLA    | CLA msg RAM | (CLA — out of scope) |
| 0x001000–0x0013FF      | RAM    | data        | |
| 0x004000–0x0043FF      | flash  | OTP/eng     | |
| 0x008000–0x00BFFF      | 16K    | LS RAM      | LS0–LS5 local-shared RAM (code or data) |
| 0x00C000–0x00DFFF      | 8K     | D RAM       | D0/D1 RAM |
| 0x00E000–0x00FFFF      | GS RAM | data        | global-shared RAM |
| 0x010000–0x017FFF      | GS RAM | data        | GS0–GS15 global-shared (often DATA buffers) |
| **0x080000–0x0FFFFF**  | **512K**| **FLASH**  | **main app code+const (FlashSectorA..N)** |
| 0x3F8000–0x3F9FFF      | 8K     | boot ROM    | |
| 0x3FFFC0–0x3FFFFF      | 64     | vectors     | reset/interrupt vectors (BROM) |

## Peripheral frames (data space) — the ones that matter for CAN

| Base      | Peripheral |
|-----------|------------|
| 0x048000  | **CANA (D_CAN)** |
| 0x04A000  | **CANB (D_CAN)** |
| 0x007400  | DMA |
| 0x006700  | PIE vector table (interrupt dispatch) |
| 0x000CE0  | PIE control |

## Where DIR code lives

DIR loads at word **0x080800** (just past the flash sector-A header at 0x080000).
So the image bytes ARE flash code+const. The 54% of the image that's "data" by the
opcode sweep is the const pools / tables / padding INTERLEAVED with code in flash —
which is why a flat sweep over-reports "undecoded": it walks data as if it were code.

## Implication for Ghidra

Define these regions so Ghidra (a) knows flash is the code region, (b) labels the
CANA/CANB peripheral blocks, and (c) seeds disassembly from the reset vector at
0x3FFFC0 → follows real flow → decodes only reachable code, leaving const pools as
data. This is what makes a meaningful coverage number and clean decompilation.
