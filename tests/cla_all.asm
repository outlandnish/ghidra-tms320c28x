;; Every CLA (Type-1) instruction form and addressing mode, assembled by TI's own
;; toolchain so dis2000 can be the oracle for the SLEIGH module.
_v32    .usect "CLAscratch", 2, 1
_v16    .usect "CLAscratch", 1, 1
        .sect "Cla1Prog"
        .global _Cla1Task1
_Cla1Task1:
;; ---- register-to-register float ----
        MABSF32   MR0, MR1
        MEINVF32  MR1, MR2
        MEISQRTF32 MR2, MR3
        MFRACF32  MR3, MR0
        MNEGF32   MR0, MR1
        MNEGF32   MR1, MR2, GEQ
        MMAXF32   MR2, MR3
        MMINF32   MR3, MR0
        MCMPF32   MR0, MR1
        MSWAPF    MR1, MR2
        MSWAPF    MR2, MR3, LT
        MMOV32    MR3, MR0
        MMOV32    MR0, MR1, EQ
;; ---- conversions ----
        MF32TOI16   MR0, MR1
        MF32TOI16R  MR1, MR2
        MF32TOI32   MR2, MR3
        MF32TOUI16  MR3, MR0
        MF32TOUI16R MR0, MR1
        MF32TOUI32  MR1, MR2
        MI16TOF32   MR2, MR3
        MI32TOF32   MR3, MR0
        MUI16TOF32  MR0, MR1
        MUI32TOF32  MR1, MR2
;; ---- three-operand float and integer ----
        MMPYF32   MR0, MR1, MR2
        MADDF32   MR1, MR2, MR3
        MSUBF32   MR2, MR3, MR0
        MAND32    MR3, MR0, MR1
        MOR32     MR0, MR1, MR2
        MXOR32    MR1, MR2, MR3
        MADD32    MR2, MR3, MR0
        MSUB32    MR3, MR0, MR1
        MCMP32    MR0, MR1
;; ---- shifts ----
        MASR32    MR0, #1
        MASR32    MR1, #32
        MLSR32    MR2, #16
        MLSL32    MR3, #8
;; ---- immediate float ----
        MMOVIZ    MR0, #1.5
        MMOVXI    MR0, #0x1234
        MMOVI16   MAR0, #0x55aa
        MMOVI16   MAR1, #0x1000
        MMPYF32   MR1, #2.0, MR2
        MMPYF32   MR2, MR3, #3.0
        MADDF32   MR3, #4.0, MR0
        MADDF32   MR0, MR1, #5.0
        MSUBF32   MR1, #6.0, MR2
        MCMPF32   MR2, #7.0
        MMAXF32   MR3, #8.0
        MMINF32   MR0, #9.0
;; ---- memory: direct ----
        MMOV32    MR0, @_v32
        MMOV32    MR1, @_v32, NEQ
        MMOV32    @_v32, MR2
        MMOVD32   MR3, @_v32
        MMOV32    MSTF, @_v32
        MMOV32    @_v32, MSTF
        MMOVZ16   MR0, @_v16
        MMOV16    @_v16, MR1
        MMOVZ16   MR2, @_v16
        MMOV16    MAR0, @_v16
        MMOV16    MAR1, @_v16
        MMOV16    @_v16, MAR0
        MMOV16    @_v16, MAR1
        MMOV16    MAR0, MR0, #4
        MMOV16    MAR1, MR1, #-4
        MI16TOF32 MR0, @_v16
        MUI16TOF32 MR1, @_v16
        MI32TOF32 MR2, @_v32
        MUI32TOF32 MR3, @_v32
;; ---- memory: indirect post-increment and offset ----
        MMOV32    MR0, *MAR0[2]++
        MMOV32    MR1, *MAR1[-2]++
        MMOV32    MR2, *MAR0+[4]
        MMOV32    MR3, *MAR1+[-4]
        MMOV32    *MAR0[2]++, MR0
        MMOV32    *MAR1+[6], MR1
        MMOVZ16   MR2, *MAR0[1]++
        MMOV16    *MAR1[1]++, MR3
;; ---- parallel ----
        MMPYF32   MR0, MR1, MR2
||      MADDF32   MR3, MR0, MR1
        MMPYF32   MR1, MR2, MR3
||      MSUBF32   MR0, MR1, MR2
        MMPYF32   MR2, MR3, MR0
||      MMOV32    MR1, @_v32
        MMPYF32   MR3, MR0, MR1
||      MMOV32    @_v32, MR2
        MADDF32   MR0, MR1, MR2
||      MMOV32    MR3, @_v32
        MADDF32   MR1, MR2, MR3
||      MMOV32    @_v32, MR0
        MSUBF32   MR2, MR3, MR0
||      MMOV32    MR1, *MAR0[2]++
        MSUBF32   MR3, MR0, MR1
||      MMOV32    *MAR1[2]++, MR2
        MMACF32   MR3, MR2, MR0, MR1, MR2
||      MMOV32    MR2, @_v32
;; ---- flags and control ----
        MSETFLG   RNDF32=1
        MTESTTF   GT
        MEALLOW
        MEDIS
        MNOP
        MDEBUGSTOP
        MCCNDD    _sub, NEQ
        MNOP
        MNOP
        MNOP
        MBCNDD    _Cla1Task1, LEQ
        MNOP
        MNOP
        MNOP
        MSTOP
_sub:
        MNOP
        MRCNDD    UNC
        MNOP
        MNOP
        MNOP
        .end
