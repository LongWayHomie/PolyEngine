/*
 * ==========================================================================
 *  Crypto.c – Compound Byte Cipher – implementation
 * ==========================================================================
 *
 *  Implements encryption and decryption of data using a chain
 *  of 4 operations on each byte. Detailed algorithm description -> Crypto.h.
 * ==========================================================================
 */

#include "Crypto.h"
#include <intrin.h> /* __rdtsc() – CPU cycle counter read */

/* ============================================================
 *  Custom simple PRNG (XORshift) replacing <stdlib.h> functions,
 *  to compile without CRT dependencies.
 * ============================================================ */
static unsigned int g_rand_state = 123456789;

static void custom_srand(unsigned int seed) {
    g_rand_state = seed ? seed : 123456789;
}

static int custom_rand() {
    g_rand_state ^= g_rand_state << 13;
    g_rand_state ^= g_rand_state >> 17;
    g_rand_state ^= g_rand_state << 5;
    return (int)(g_rand_state & 0x7FFFFFFF);
}

/*
 * _rotl8 / _rotr8 – byte bit rotation
 *
 * MSVC provides these functions as intrinsics (built into the compiler)
 * in the <intrin.h> header. We don't need to implement them manually.
 *
 * ROL (Rotate Left):  bits "exit" from the left side and enter from the right
 *   Example: 0b10110011 ROL 3 = 0b10011101
 *
 * ROR (Rotate Right): bits "exit" from the right side and enter from the left
 *   Example: 0b10110011 ROR 3 = 0b01110110
 */

/* ============================================================
 *  GenerateCompoundKey() – random key generation
 *
 *  Uses __rdtsc() as seed. __rdtsc() returns the CPU cycle counter,
 *  which changes at ~GHz frequency – gives a different seed at
 *  each run, even milliseconds apart.
 * ============================================================ */
void GenerateCompoundKey(PCOMPOUND_KEY pKey) {
  /* Seed based on CPU cycle count – unpredictable */
  unsigned __int64 tsc = __rdtsc();
  custom_srand((unsigned int)(tsc & 0xFFFFFFFF));

  pKey->key1       = (BYTE)(custom_rand() & 0xFF);      /* any value 0-255                             */
  pKey->rotBits    = (BYTE)(1 + (custom_rand() % 7));  /* 1-7 (0 = no rotation, 8 = full rotation = NOP) */
  pKey->key3       = (BYTE)(custom_rand() & 0xFF);      /* any value 0-255                             */
  pKey->key4       = (BYTE)(custom_rand() & 0xFF);      /* any value 0-255                             */
  pKey->xorSwapped = (custom_rand() & 1) ? TRUE : FALSE; /* random outer-XOR order per build           */
}

/* ============================================================
 *  CompoundEncrypt() – chain encryption
 *
 *  For each byte:
 *    1. XOR with key1     – mixes bits with the key
 *    2. ROL by rotBits  – shifts the bit pattern
 *    3. ADD key3       – adds value (mod 256, with carry)
 *    4. XOR with key4     – second XOR with another key
 * ============================================================ */
void CompoundEncrypt(PBYTE pData, SIZE_T dataLen, const COMPOUND_KEY *pKey) {
  for (SIZE_T i = 0; i < dataLen; i++) {
    BYTE b = pData[i];

    if (!pKey->xorSwapped) {
      /* Default order: XOR k1 → ROL → ADD k3 → XOR k4 */
      b ^= pKey->key1;
      b = _rotl8(b, pKey->rotBits);
      b += pKey->key3;
      b ^= pKey->key4;
    } else {
      /* Swapped order: XOR k4 → ROL → ADD k3 → XOR k1
       * Decryptor reverses this as: XOR k1 → SUB k3 → ROR → XOR k4 */
      b ^= pKey->key4;
      b = _rotl8(b, pKey->rotBits);
      b += pKey->key3;
      b ^= pKey->key1;
    }

    pData[i] = b;
  }
}

