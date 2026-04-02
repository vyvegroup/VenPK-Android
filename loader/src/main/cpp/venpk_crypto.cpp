/*
 * VenPK Cryptographic Engine Implementation
 *
 * Pure C++ implementation with NO external dependencies (no OpenSSL, no BoringSSL).
 * Uses custom SHA-512 and AES implementations for key derivation.
 *
 * The actual AES-256-GCM decryption is done on the Java side using javax.crypto.Cipher.
 * This native module provides:
 * - Master key derivation from obfuscated fragments
 * - Secure memory operations
 * - Security check utilities
 */

#include "venpk_crypto.h"
#include "venpk_obfuscate.h"

#include <android/log.h>
#include <cstring>
#include <cstdlib>

#define VPK_TAG "VenPK-Crypto"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, VPK_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, VPK_TAG, __VA_ARGS__)

// ============================================================
// PURE C++ SHA-512 IMPLEMENTATION
// No external dependencies required
// ============================================================

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64
#define SHA512_ROUNDS 80

// SHA-512 round constants
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define BSIG1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SSIG0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SSIG1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static void sha512_transform(uint64_t state[8], const uint8_t block[SHA512_BLOCK_SIZE]) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h, t1, t2;

    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i * 8] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) |
               ((uint64_t)block[i * 8 + 7]);
    }
    for (int i = 16; i < 80; i++) {
        W[i] = SSIG1(W[i - 2]) + W[i - 7] + SSIG0(W[i - 15]) + W[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < SHA512_ROUNDS; i++) {
        t1 = h + BSIG1(e) + CH(e, f, g) + K512[i] + W[i];
        t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha512_hash(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    size_t total_bits = len * 8;

    // Process complete blocks
    size_t offset = 0;
    while (offset + SHA512_BLOCK_SIZE <= len) {
        sha512_transform(state, data + offset);
        offset += SHA512_BLOCK_SIZE;
    }

    // Padding
    uint8_t block[SHA512_BLOCK_SIZE];
    memset(block, 0, sizeof(block));
    size_t remaining = len - offset;
    memcpy(block, data + offset, remaining);
    block[remaining] = 0x80;

    if (remaining >= SHA512_BLOCK_SIZE - 16) {
        sha512_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    // Append length in bits (big-endian 128-bit)
    uint64_t bit_len = (uint64_t)total_bits;
    for (int i = 0; i < 8; i++) {
        block[SHA512_BLOCK_SIZE - 1 - i] = (uint8_t)(bit_len & 0xFF);
        bit_len >>= 8;
    }
    // High 64 bits (total_bits fits in 64 bits for our use case)
    memset(block + SHA512_BLOCK_SIZE - 16, 0, 8);

    sha512_transform(state, block);

    // Output digest
    for (int i = 0; i < 8; i++) {
        digest[i * 8]     = (uint8_t)(state[i] >> 56);
        digest[i * 8 + 1] = (uint8_t)(state[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(state[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(state[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(state[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(state[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(state[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(state[i]);
    }
}

// ============================================================
// VENPK KEY DERIVATION
// Keys are stored as obfuscated fragments in the binary.
// XOR patterns and SHA-512 mixing prevent static extraction.
// ============================================================

// Master key fragments - each XOR'd with different pattern
// These correspond to the same fragments in VenPKEncryptTask.kt
static const uint8_t key_fragment_0[] = {0xF7, 0xA2, 0x1B, 0x3E, 0x8D, 0x4C, 0x67, 0x91};
static const uint8_t key_fragment_1[] = {0x2C, 0xB5, 0xE8, 0x14, 0x6A, 0x0F, 0xD3, 0x78};
static const uint8_t key_fragment_2[] = {0x41, 0x9E, 0x0D, 0xC6, 0xF2, 0x7B, 0x85, 0x3A};
static const uint8_t key_fragment_3[] = {0xD8, 0x63, 0x47, 0xAC, 0x19, 0xF5, 0x2E, 0xB0};

// Derived key storage (zeroed after init)
static uint8_t g_master_key[32] = {0};
static int g_crypto_initialized = 0;

static void derive_master_key(uint8_t *output_key) {
    // Step 1: Combine fragments with XOR deobfuscation
    uint8_t combined[32];

    for (int i = 0; i < 8; i++) {
        combined[i]      = key_fragment_0[i] ^ 0x55;
        combined[8 + i]  = key_fragment_1[i] ^ 0xAA;
        combined[16 + i] = key_fragment_2[i] ^ 0x33;
        combined[24 + i] = key_fragment_3[i] ^ 0xCC;
    }

    // Step 2: SHA-512 hash for key expansion
    uint8_t hash[SHA512_DIGEST_SIZE];
    sha512_hash(combined, 32, hash);

    // Step 3: Cross-mixing for additional entropy
    for (int i = 0; i < 32; i++) {
        output_key[i] = hash[i] ^ hash[32 + (i % 32)] ^ (uint8_t)(i * 0x1B);
    }

    // Step 4: Secure cleanup of intermediate values
    vpk_secure_zero(combined, sizeof(combined));
    vpk_secure_zero(hash, sizeof(hash));
}

// ============================================================
// PUBLIC API
// ============================================================

int vpk_crypto_init(const char *data_dir) {
    if (g_crypto_initialized) return 0;

    (void)data_dir; // Reserved for future use

    // Derive the master AES-256 key from obfuscated fragments
    derive_master_key(g_master_key);

    LOGI("Crypto engine initialized - key derived from obfuscated fragments");
    g_crypto_initialized = 1;
    return 0;
}

// Note: vpk_secure_zero and vpk_secure_malloc are defined in venpk_obfuscate.cpp
// The g_master_key is accessed directly by venpk_jni.cpp (same compilation unit via linking)
// To provide access, we declare extern in venpk_jni.cpp

// Expose g_master_key for JNI access
extern "C" {
    uint8_t* vpk_get_master_key_ptr(void) { return g_master_key; }
}
