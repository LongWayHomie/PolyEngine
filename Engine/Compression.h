#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ==========================================================================
 *  NT API Compression (LZNT1)
 * ==========================================================================
 *  Functions wrapping native Windows calls:
 *  RtlGetCompressionWorkSpaceSize
 *  RtlCompressBuffer
 *  RtlDecompressBuffer
 * ==========================================================================
 */

BOOL InitCompressionApi();

/* Returns TRUE if compression succeeded. outSize returns the size after compression. */
BOOL CompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG* outSize);

/* Returns TRUE if decompression succeeded. outSize returns the size after decompression. */
BOOL DecompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG outExpectedSize);

#ifdef __cplusplus
}
#endif

#endif /* COMPRESSION_H */
