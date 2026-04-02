/*
 * VenPK Code Obfuscation Utilities
 */

#ifndef VENPK_OBFUSCATE_H
#define VENPK_OBFUSCATE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Securely zero memory (optimized to not be stripped by compiler)
void vpk_secure_zero(void *ptr, size_t len);

// Secure memory allocation (zeros memory on alloc)
void *vpk_secure_malloc(size_t size);

// Initialize obfuscation engine
void vpk_obfuscate_init(void);

// Obfuscate/encrypt a string at compile time (runtime decryption)
// XOR-based string encryption
const char *vpk_deobfuscate_string(const uint8_t *data, size_t len, uint8_t key);

#ifdef __cplusplus
}
#endif

#endif // VENPK_OBFUSCATE_H
