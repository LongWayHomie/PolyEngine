#include "EntropyCodec.h"

/* 16 most frequent lowercase ASCII letters (English text frequency order).
 * A uniform nibble stream maps to a uniform 16-symbol distribution → exactly
 * 4.0 bits/byte, and every produced byte is a plausible text character. */
static const BYTE kEntropyAlphabet[16] = {
    'e','t','a','o','i','n','s','h','r','d','l','u','c','m','w','f'
};

void EntropyEncode(const BYTE* in, DWORD inLen, BYTE* out) {
    DWORD i;
    for (i = 0; i < inLen; i++) {
        out[i * 2]     = kEntropyAlphabet[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kEntropyAlphabet[in[i] & 0x0F];
    }
}

void EntropyDecode(BYTE* out, const BYTE* in, DWORD outLen) {
    BYTE rev[256];
    DWORD i;
    int   k;

    for (k = 0; k < 256; k++) rev[k] = 0;
    for (k = 0; k < 16;  k++) rev[kEntropyAlphabet[k]] = (BYTE)k;

    for (i = 0; i < outLen; i++) {
        out[i] = (BYTE)((rev[in[i * 2]] << 4) | rev[in[i * 2 + 1]]);
    }
}
