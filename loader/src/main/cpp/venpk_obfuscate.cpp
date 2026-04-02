/*
 * VenPK Code Obfuscation Implementation
 *
 * Provides secure memory operations and string obfuscation.
 * Pure C++ - no external dependencies.
 */

#include "venpk_obfuscate.h"

#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <new>

#define VPK_TAG "VenPK-Obf"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, VPK_TAG, __VA_ARGS__)

// Compiler memory barrier to prevent optimization of secure_zero
// Using inline assembly to ensure the compiler cannot optimize away the zeroing
inline void memory_barrier() {
#if defined(__ARM_ARCH__)
    __asm__ __volatile__("dmb ish" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("mfence" ::: "memory");
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

void vpk_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    
    // Use volatile pointer to prevent compiler from optimizing away writes
    volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
    while (len--) {
        *p++ = 0;
    }
    
    // Ensure all writes are visible
    memory_barrier();
}

void *vpk_secure_malloc(size_t size) {
    if (size == 0) return nullptr;

    void *ptr = malloc(size);
    if (ptr) {
        // Zero the allocated memory for security
        vpk_secure_zero(ptr, size);
    }
    return ptr;
}

void vpk_obfuscate_init(void) {
    // Initialize runtime obfuscation state
    // Could be extended with:
    // - Encrypted function pointer tables
    // - Control flow obfuscation state
    // - Anti-dump memory protection
    LOGI("Obfuscation engine initialized");
}

const char *vpk_deobfuscate_string(const uint8_t *data, size_t len, uint8_t key) {
    if (!data || len == 0) return nullptr;

    // Allocate buffer + null terminator
    char *result = static_cast<char *>(vpk_secure_malloc(len + 1));
    if (!result) return nullptr;

    // XOR decrypt each byte
    for (size_t i = 0; i < len; i++) {
        result[i] = static_cast<char>(data[i] ^ key);
        // Rotate key for additional obfuscation
        key = static_cast<uint8_t>(key * 31 + 17);
    }
    result[len] = '\0';

    return result;
}
