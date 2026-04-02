/*
 * VenPK Cryptographic Engine
 * Pure C++ implementation - NO external dependencies
 * Key derivation and security utilities for VenPK runtime
 */

#ifndef VENPK_CRYPTO_H
#define VENPK_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize crypto engine - derives master key from obfuscated fragments
// Returns 0 on success
int vpk_crypto_init(const char *data_dir);

// Securely zero memory (resists compiler optimization)
void vpk_secure_zero(void *ptr, size_t len);

// Secure memory allocation (zeroes memory on allocation)
void *vpk_secure_malloc(size_t size);

#ifdef __cplusplus
}
#endif

#endif // VENPK_CRYPTO_H
