/*
 * ==========================================================================
 *  Crypto.h – Compound Byte Cipher – declarations
 * ==========================================================================
 *
 *  PURPOSE:
 *  --------
 *  Defines the "Compound Byte Cipher" – a chain of 4 simple operations
 *  performed on EVERY byte of the payload. Each operation uses a separate
 *  sub-key, providing stronger encryption than a single XOR.
 *
 *  HOW ENCRYPTION WORKS (example: byte 0x41 = 'A'):
 *  ---------------------------------------------------------
 *    Keys: key1=0x37, rotBits=3, key3=0x1A, key4=0xBB
 *
 *    Step 1 (XOR):  0x41 ^ 0x37       = 0x76
 *    Step 2 (ROL):  0x76 ROL 3         = 0xB3   (left bit rotation)
 *    Step 3 (ADD):  0xB3 + 0x1A        = 0xCD   (addition with overflow mod 256)
 *    Step 4 (XOR):  0xCD ^ 0xBB        = 0x76   (encrypted byte)
 *
 *  DECRYPTION (inverse, from end):
 *  -------------------------------------
 *    Step 4' (XOR): 0x76 ^ 0xBB        = 0xCD
 *    Step 3' (SUB): 0xCD - 0x1A        = 0xB3
 *    Step 2' (ROR): 0xB3 ROR 3         = 0x76   (right bit rotation)
 *    Step 1' (XOR): 0x76 ^ 0x37        = 0x41   <- original byte!
 *
 *  WHY NOT SIMPLE XOR?
 *  ------------------------
 *  - XOR is linear: knowing 1 byte of plaintext, you recover the key.
 *  - ROL breaks bit patterns (same inputs -> different outputs).
 *  - ADD introduces carry – changing 1 bit affects neighbors.
 *  - 4 separate keys = 4x larger key space.
 *
 *  WHY GOOD FOR MUTATION?
 *  ---------------------------
 *  Each step is a separate ASM instruction in the decryptor stub.
 *  The mutation engine can replace each with an equivalent:
 *    XOR <-> NOT+AND+OR,  SUB <-> ADD complement,  ROR <-> SHR+SHL+OR
 *  This gives exponentially more unique code variants.
 * ==========================================================================
 */

#pragma once

#ifndef CRYPTO_H
#define CRYPTO_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 *  COMPOUND_KEY – structure holding 4 sub-keys
 *
 *  Generated randomly at each program startup,
 *  guaranteeing each "copy" has unique encryption.
 * ============================================================ */
typedef struct _COMPOUND_KEY {
  BYTE key1;       /* XOR sub-key (step 1) – any value 0x00-0xFF              */
  BYTE rotBits;    /* rotation bits (step 2) – range 1-7                      */
  BYTE key3;       /* ADD value (step 3) – any value 0x00-0xFF                */
  BYTE key4;       /* XOR sub-key (step 4) – any value 0x00-0xFF              */
  BOOL xorSwapped; /* TRUE  → encrypt: XOR k4 first, XOR k1 last             */
                   /* FALSE → encrypt: XOR k1 first, XOR k4 last  (default)  */
                   /* Decryptor stub emits keys in matching reversed order.   */
} COMPOUND_KEY, *PCOMPOUND_KEY;

/* ============================================================
 *  GenerateCompoundKey() – generates random 4-part key
 *
 *  Uses __rdtsc() (CPU cycle counter) as seed for rand(),
 *  providing unpredictability without needing crypto libraries.
 *
 *  Parameters:
 *    pKey – [out] pointer to COMPOUND_KEY structure to fill
 * ============================================================ */
void GenerateCompoundKey(PCOMPOUND_KEY pKey);

/* ============================================================
 *  CompoundEncrypt() – encrypts data in-place
 *
 *  Each byte undergoes the chain: XOR key1 -> ROL rotBits -> ADD key3 -> XOR
 * key4
 *
 *  Parameters:
 *    pData    – pointer to data to encrypt (modified in-place)
 *    dataLen  – length of data in bytes
 *    pKey     – encryption key
 * ============================================================ */
void CompoundEncrypt(PBYTE pData, SIZE_T dataLen, const COMPOUND_KEY *pKey);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
