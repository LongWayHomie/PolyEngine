#include "EntropyCodec.h"

/* Candidate symbol pool: all 26 lowercase ASCII letters. Each build draws an
 * ordered 16-symbol subset from this pool — the alphabet is no longer a
 * cross-sample constant (a fixed set like "etaoinshrdlucmwf" would let one
 * charset regex retro-hunt match every sample ever built). */
static const BYTE kEntropyPool[26] = {
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z'
};

void EntropyDeriveAlphabet(const BYTE* key_salt, BYTE* outAlphabet) {
    BYTE   pool[26];
    UINT64 lo = 0, hi = 0, state;
    int    i;

    for (i = 0; i < 26; i++) pool[i] = kEntropyPool[i];

    /* Fold the 128-bit salt into a 64-bit PRNG state (LE loads — both Builder
     * and Stub run on x64 Windows, so this is deterministic across the two). */
    for (i = 0; i < 8; i++) {
        lo |= (UINT64)key_salt[i]     << (i * 8);
        hi |= (UINT64)key_salt[8 + i] << (i * 8);
    }
    state = lo ^ (hi * 0x9E3779B97F4A7C15ULL);
    if (state == 0) state = 0x9E3779B97F4A7C15ULL; /* xorshift sticks at zero */

    /* Partial Fisher-Yates: the first 16 draws of a shuffled 26-symbol pool. */
    for (i = 0; i < 16; i++) {
        DWORD j;
        BYTE  tmp;

        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        j = (DWORD)i + (DWORD)(state % (UINT64)(26 - i));
        tmp = pool[i]; pool[i] = pool[j]; pool[j] = tmp;
        outAlphabet[i] = pool[i];
    }
}

void EntropyEncode(const BYTE* in, DWORD inLen, BYTE* out, const BYTE* alphabet) {
    DWORD i;
    for (i = 0; i < inLen; i++) {
        out[i * 2]     = alphabet[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = alphabet[in[i] & 0x0F];
    }
}

void EntropyDecode(BYTE* out, const BYTE* in, DWORD outLen, const BYTE* alphabet) {
    BYTE rev[256];
    DWORD i;
    int   k;

    for (k = 0; k < 256; k++) rev[k] = 0;
    for (k = 0; k < 16;  k++) rev[alphabet[k]] = (BYTE)k;

    for (i = 0; i < outLen; i++) {
        out[i] = (BYTE)((rev[in[i * 2]] << 4) | rev[in[i * 2 + 1]]);
    }
}
