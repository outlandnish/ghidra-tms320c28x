#!/usr/bin/env bash
# Regression test for the C28x SLEIGH disassembler.
#
# Disassembles tests/addr_modes.bin with Ghidra (headless) and diffs the result
# against tests/addr_modes.expected.txt. Run after any .sinc/.slaspec change.
#
# Because Ghidra lives on the Windows side and cmd.exe can't run from a WSL UNC
# cwd, this driver is actually invoked from PowerShell (see docs/TESTING.md). This
# script documents the expected-vs-actual comparison; the harness lives in
# tests/run_disasm_test.ps1.
#
# Expected output (verified 2026-06-22, all 14 cases pass):
#   0x0000  0606      MOVL ACC,@0x6
#   0x0001  8006      MOVL ACC,*XAR0++
#   0x0002  8b06      MOVL ACC,*--XAR3
#   0x0003  9206      MOVL ACC,*+XAR2[AR0]
#   0x0004  9b06      MOVL ACC,*+XAR3[AR1]
#   0x0005  d506      MOVL ACC,*+XAR5[0x5]
#   0x0006  a106      MOVL ACC,@XAR1
#   0x0007  bd06      MOVL ACC,*SP++
#   0x0008  be06      MOVL ACC,*--SP
#   0x0009  0707      ADDL ACC,@0x7
#   0x000a  0420      MOV @0x4,IER
#   0x000b  04283412  MOV @0x4,#0x1234
#   0x000d  0100      ABORTI
#   0x000e  2176      IDLE
echo "See tests/run_disasm_test.ps1 (Ghidra is Windows-side)."
