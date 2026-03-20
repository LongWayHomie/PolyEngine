#include "Compression.h"
#include <stdio.h>

#ifndef COMPRESSION_FORMAT_LZNT1
#define COMPRESSION_FORMAT_LZNT1 (0x0002)
#endif
#ifndef COMPRESSION_ENGINE_STANDARD
#define COMPRESSION_ENGINE_STANDARD (0x0000)
#endif
#ifndef COMPRESSION_ENGINE_MAXIMUM
#define COMPRESSION_ENGINE_MAXIMUM (0x0100)
#endif

typedef NTSTATUS(NTAPI* RtlGetCompressionWorkSpaceSize_t)(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize);

typedef NTSTATUS(NTAPI* RtlCompressBuffer_t)(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID WorkSpace);

typedef NTSTATUS(NTAPI* RtlDecompressBuffer_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize);

/* Global pointers to NT functions */
static RtlGetCompressionWorkSpaceSize_t pRtlGetCompressionWorkSpaceSize = NULL;
static RtlCompressBuffer_t pRtlCompressBuffer = NULL;
static RtlDecompressBuffer_t pRtlDecompressBuffer = NULL;

BOOL InitCompressionApi() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pRtlGetCompressionWorkSpaceSize = (RtlGetCompressionWorkSpaceSize_t)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");
    pRtlCompressBuffer = (RtlCompressBuffer_t)GetProcAddress(hNtdll, "RtlCompressBuffer");
    pRtlDecompressBuffer = (RtlDecompressBuffer_t)GetProcAddress(hNtdll, "RtlDecompressBuffer");

    return (pRtlGetCompressionWorkSpaceSize && pRtlCompressBuffer && pRtlDecompressBuffer);
}

BOOL CompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG* outSize) {
    if (!pRtlGetCompressionWorkSpaceSize || !pRtlCompressBuffer) {
        if (!InitCompressionApi()) return FALSE;
    }

    ULONG compressWorkspaceSize = 0;
    ULONG fragmentWorkspaceSize = 0;
    USHORT compFormat = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;

    NTSTATUS status = pRtlGetCompressionWorkSpaceSize(compFormat, &compressWorkspaceSize, &fragmentWorkspaceSize);
    if (status != 0) { // !NT_SUCCESS
        return FALSE;
    }

    PVOID workspace = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, compressWorkspaceSize);
    if (!workspace) return FALSE;

    /* Output buffer may be slightly larger due to LZNT1 overhead in worst-case compression (e.g., padding)
       but in 99% of cases it will be much smaller. We assume worst-case scenario. */
    //ULONG maxOutSpace = inSize + 1024; 
    ULONG maxOutSpace = inSize + (inSize / 8) + 8192; //bugfix for potential overflow
    *outBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxOutSpace);
    if (!*outBuffer) {
        HeapFree(GetProcessHeap(), 0, workspace);
        return FALSE;
    }

    status = pRtlCompressBuffer(
        compFormat,
        (PUCHAR)inBuffer,
        inSize,
        (PUCHAR)*outBuffer,
        maxOutSpace,
        4096, // Default LZNT compression block size 
        outSize,
        workspace
    );

    HeapFree(GetProcessHeap(), 0, workspace);

    if (status != 0) {
        HeapFree(GetProcessHeap(), 0, *outBuffer);
        *outBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL DecompressPayload(const BYTE* inBuffer, ULONG inSize, BYTE** outBuffer, ULONG outExpectedSize) {
    if (!pRtlDecompressBuffer) {
        if (!InitCompressionApi()) return FALSE;
    }

    *outBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outExpectedSize);
    if (!*outBuffer) return FALSE;

    ULONG finalDecompressedSize = 0;
    USHORT compFormat = COMPRESSION_FORMAT_LZNT1;

    NTSTATUS status = pRtlDecompressBuffer(
        compFormat,
        (PUCHAR)*outBuffer,
        outExpectedSize,
        (PUCHAR)inBuffer,
        inSize,
        &finalDecompressedSize
    );

    if (status != 0 || finalDecompressedSize != outExpectedSize) {
        HeapFree(GetProcessHeap(), 0, *outBuffer);
        *outBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}
