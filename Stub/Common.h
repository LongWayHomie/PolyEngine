#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * =========================================================================
 *  Common.h - Common definitions and custom CRT implementations
 * =========================================================================
 * 
 * Module replacing standard CRT (C Runtime Library) functions.
 * Required for compilation without /NODEFAULTLIB.
 */

/* Custom memory functions (marked as built-in) */
void* __cdecl custom_memset(void* pTarget, int value, size_t cbTarget);
void* __cdecl custom_memcpy(void* dest, const void* src, size_t count);

/* Custom string functions */
SIZE_T custom_strlen(const char* str);
SIZE_T custom_wcslen(const wchar_t* str);
int custom_wcsicmp(const wchar_t* s1, const wchar_t* s2);
int custom_strcmp(const char* s1, const char* s2);

/* Custom random number generator XORshift */
void custom_srand(unsigned int seed);
int custom_rand(void);

#ifdef __cplusplus
}
#endif
