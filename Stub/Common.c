#include "Common.h"

/* 
 * =========================================================================
 *  Custom CRT functions
 * =========================================================================
 */

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0) {
        *p++ = (unsigned char)value;
    }
    return pTarget;
}

#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* dest, const void* src, size_t count) {
    char* char_dest = (char*)dest;
    char* char_src = (char*)src;
    while (count--) {
        *char_dest++ = *char_src++;
    }
    return dest;
}

void* __cdecl custom_memset(void* pTarget, int value, size_t cbTarget) {
    return memset(pTarget, value, cbTarget);
}

void* __cdecl custom_memcpy(void* dest, const void* src, size_t count) {
    return memcpy(dest, src, count);
}

/* 
 * =========================================================================
 *  String functions
 * =========================================================================
 */

SIZE_T custom_strlen(const char* str) {
    SIZE_T len = 0;
    while (str[len]) len++;
    return len;
}

SIZE_T custom_wcslen(const wchar_t* str) {
    SIZE_T len = 0;
    while (str[len]) len++;
    return len;
}

int custom_wcsicmp(const wchar_t* s1, const wchar_t* s2) {
    wchar_t c1, c2;
    do {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 >= L'A' && c1 <= L'Z') c1 += L'a' - L'A';
        if (c2 >= L'A' && c2 <= L'Z') c2 += L'a' - L'A';
        if (c1 != c2) return (int)(c1 - c2);
    } while (c1);
    return 0;
}

int custom_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

/* 
 * =========================================================================
 *  Simple PRNG (XORshift) replacing functions from <stdlib.h>.
 * =========================================================================
 */

static unsigned int g_rand_state = 0;

void custom_srand(unsigned int seed) {
    g_rand_state = seed ? seed : 123456789;
}

int custom_rand(void) {
    if (g_rand_state == 0) {
        g_rand_state = (unsigned int)(__rdtsc() & 0xFFFFFFFF);
        if (g_rand_state == 0) g_rand_state = 123456789;
    }
    g_rand_state ^= g_rand_state << 13;
    g_rand_state ^= g_rand_state >> 17;
    g_rand_state ^= g_rand_state << 5;
    return (int)(g_rand_state & 0x7FFFFFFF);
}
