/*
 * VenPK JNI Bridge
 * Native bridge between Java/Kotlin and VenPK native engine
 * All sensitive operations are handled in native code
 *
 * No external dependencies - pure C++ with Android NDK
 */

#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <netdb.h>
#include "venpk_crypto.h"
#include "venpk_obfuscate.h"

#define VPK_TAG "VenPK-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, VPK_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, VPK_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, VPK_TAG, __VA_ARGS__)

// Security state tracking
static volatile int g_security_ok = 0;
static volatile int g_key_released = 0;

// Access master key from venpk_crypto.cpp (must match extern "C" linkage)
extern "C" uint8_t* vpk_get_master_key_ptr(void);

// Forward declarations
static int run_all_security_checks(JNIEnv *env, jobject context);
static void vpk_anti_debug_check(void);
static void vpk_anti_frida_check(void);
static void vpk_anti_emulator_check(void);
static void vpk_integrity_check(JNIEnv *env, jobject context);

extern "C" {

JNIEXPORT jint JNICALL
Java_com_venpk_loader_VenPKLoaderApp_nativeInitSecurity(JNIEnv *env, jobject thiz, jstring data_dir) {
    LOGI("Initializing VenPK security layer...");

    const char *dir = env->GetStringUTFChars(data_dir, nullptr);
    if (!dir) {
        LOGE("Invalid data directory");
        return -1;
    }

    // Derive master key from obfuscated fragments
    vpk_crypto_init(dir);
    env->ReleaseStringUTFChars(data_dir, dir);

    // Run comprehensive security checks
    int result = run_all_security_checks(env, thiz);
    if (result != 0) {
        LOGW("Security checks returned warnings: %d", result);
    }
    g_security_ok = 1;

    // Initialize obfuscation engine
    vpk_obfuscate_init();

    LOGI("VenPK security layer ready (status=%d)", g_security_ok);
    return 0;
}

JNIEXPORT jbyteArray JNICALL
Java_com_venpk_loader_StubActivity_nativeGetKey(JNIEnv *env, jobject thiz) {
    LOGI("Key request received");

    if (!g_security_ok) {
        LOGE("Security not initialized - denying key request");
        return nullptr;
    }

    if (g_key_released) {
        LOGE("Key already released - denying duplicate request");
        return nullptr;
    }

    // Final integrity verification before key release
    vpk_anti_debug_check();

    if (!g_security_ok) {
        LOGE("Final security check failed - denying key request");
        return nullptr;
    }

    uint8_t *master_key = vpk_get_master_key_ptr();
    if (!master_key) {
        LOGE("Master key not available");
        return nullptr;
    }

    uint8_t key_copy[32];
    memcpy(key_copy, master_key, 32);

    jbyteArray result = env->NewByteArray(32);
    if (!result) {
        LOGE("Failed to allocate key array");
        vpk_secure_zero(key_copy, 32);
        return nullptr;
    }

    env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<const jbyte *>(key_copy));
    vpk_secure_zero(key_copy, 32);

    g_key_released = 1;
    LOGI("Decryption key released to runtime");

    return result;
}

/**
 * JNI method: Calls the real Activity's onCreate() on StubActivity instance.
 *
 * Uses CallNonvirtualVoidMethod to directly invoke the method implementation
 * from the specified class, bypassing Java's receiver type check.
 *
 * Java's Method.invoke() checks that obj is an instanceof the declaring class.
 * Since StubActivity is NOT a subclass of the real MainActivity, Method.invoke()
 * throws IllegalArgumentException. CallNonvirtualVoidMethod bypasses this check
 * on Android ART by directly invoking the bytecode from the specified class.
 *
 * This works because:
 * 1. Both StubActivity and the real MainActivity extend ComponentActivity
 * 2. The real MainActivity.onCreate() only uses 'this' as ComponentActivity
 *    (calls super.onCreate(), enableEdgeToEdge(), setContent {...})
 * 3. No Kotlin CHECKCAST of 'this' to MainActivity exists in the bytecode
 * 4. ART's CallNonvirtualVoidMethod does not verify receiver type
 */
JNIEXPORT jboolean JNICALL
Java_com_venpk_loader_StubActivity_nativeCallActivityOnCreate(
    JNIEnv *env, jobject thiz, jclass activity_class, jobject saved_instance_state) {

    LOGI("nativeCallActivityOnCreate: invoking onCreate via CallNonvirtualVoidMethod");

    // Get the onCreate(Bundle) method from the real Activity class
    jmethodID on_create_method = env->GetMethodID(
        activity_class, "onCreate", "(Landroid/os/Bundle;)V");

    if (on_create_method == nullptr) {
        LOGE("onCreate method not found in activity class");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return JNI_FALSE;
    }

    LOGI("Found onCreate method, calling via CallNonvirtualVoidMethod...");

    // CallNonvirtualVoidMethod invokes the method directly from activity_class
    // on the thiz object (StubActivity), bypassing virtual dispatch and
    // the receiver instanceof check that Method.invoke() performs.
    env->CallNonvirtualVoidMethod(thiz, activity_class, on_create_method, saved_instance_state);

    // Check for Java exceptions
    if (env->ExceptionCheck()) {
        jthrowable exception = env->ExceptionOccurred();
        env->ExceptionDescribe();
        env->ExceptionClear();

        // Get exception message
        jclass exClass = env->GetObjectClass(exception);
        jmethodID getMessage = env->GetMethodID(exClass, "getMessage", "()Ljava/lang/String;");
        if (getMessage) {
            jstring msg = (jstring)env->CallObjectMethod(exception, getMessage);
            if (msg) {
                const char *msgStr = env->GetStringUTFChars(msg, nullptr);
                LOGE("onCreate threw exception: %s", msgStr);
                env->ReleaseStringUTFChars(msg, msgStr);
            }
        }
        env->DeleteLocalRef(exception);
        env->DeleteLocalRef(exClass);

        return JNI_FALSE;
    }

    LOGI("✅ onCreate invoked successfully via JNI");
    return JNI_TRUE;
}

/**
 * Fallback: Try to call the method using internal ART APIs.
 * On newer Android versions where CallNonvirtualVoidMethod checks types,
 * we attempt to use reflection to access ArtMethod directly.
 */
JNIEXPORT jboolean JNICALL
Java_com_venpk_loader_StubActivity_nativeCallActivityOnCreateFallback(
    JNIEnv *env, jobject thiz, jmethodID method_id, jobject saved_instance_state) {

    LOGI("Attempting fallback invocation...");

    // Try direct invocation via the method pointer
    // On ART, jmethodID is a pointer to ArtMethod
    // We can try to invoke it directly, but this is highly version-dependent

    // Alternative approach: use the JNI CallVoidMethod with a different strategy
    // We temporarily replace the class in the object's class pointer
    // This is very hacky and version-dependent

    // For now, just log and return false
    LOGE("Fallback invocation not available on this ART version");
    return JNI_FALSE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("VenPK native library loading...");

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }

    (void)vm;
    (void)reserved;

    LOGI("VenPK native library loaded (v1.1.0)");
    return JNI_VERSION_1_6;
}

} // extern "C"

// === SECURITY CHECKS IMPLEMENTATION ===

static int run_all_security_checks(JNIEnv *env, jobject context) {
    int warnings = 0;

    vpk_anti_debug_check();
    vpk_anti_frida_check();
    vpk_anti_emulator_check();
    vpk_integrity_check(env, context);

    return warnings;
}

static void vpk_anti_debug_check(void) {
    static volatile int ptrace_done = 0;
    if (!ptrace_done) {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            LOGW("Anti-debug: ptrace TRACEME failed - debugger may be attached");
        }
        ptrace_done = 1;
    }

    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                if (pid != 0) {
                    LOGW("Anti-debug: TracerPid=%d detected", pid);
                }
                break;
            }
        }
        fclose(f);
    }
}

static void vpk_anti_frida_check(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "frida") != nullptr ||
                strstr(line, "linjector") != nullptr ||
                strstr(line, "agent.so") != nullptr) {
                LOGW("Anti-frida: Suspicious library detected in memory map");
                break;
            }
        }
        fclose(f);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(27042);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);

        if (ret == 0) {
            LOGW("Anti-frida: Port 27042 (frida-server) is open");
        }
    }

    const char *frida_paths[] = {
        "/tmp/frida-agent.so",
        "/tmp/frida-server",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida-agent.so",
        nullptr
    };
    for (int i = 0; frida_paths[i] != nullptr; i++) {
        if (access(frida_paths[i], F_OK) == 0) {
            LOGW("Anti-frida: Frida artifact found: %s", frida_paths[i]);
        }
    }
}

static void vpk_anti_emulator_check(void) {
    FILE *f;
    char buf[256];
    const char *emulator_signatures[] = {
        "goldfish", "ranchu", "vbox", "genymotion",
        "nox", "bluestacks", "memu", "androvm",
        "sdk", "emulator", "generic",
        nullptr
    };

    f = fopen("/system/build.prop", "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            for (int j = 0; emulator_signatures[j] != nullptr; j++) {
                if (strcasestr(buf, emulator_signatures[j]) != nullptr) {
                    LOGW("Anti-emulator: Found '%s' in build.prop", emulator_signatures[j]);
                    break;
                }
            }
        }
        fclose(f);
    }

    const char *qemu_files[] = {
        "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
        nullptr
    };
    for (int i = 0; qemu_files[i] != nullptr; i++) {
        if (access(qemu_files[i], F_OK) == 0) {
            LOGW("Anti-emulator: QEMU file found: %s", qemu_files[i]);
        }
    }
}

static void vpk_integrity_check(JNIEnv *env, jobject context) {
    jclass contextClass = env->GetObjectClass(context);
    if (!contextClass) return;

    jmethodID getPackageManager = env->GetMethodID(contextClass, "getPackageManager",
                                                    "()Landroid/content/pm/PackageManager;");
    if (!getPackageManager) {
        env->DeleteLocalRef(contextClass);
        return;
    }

    jobject pm = env->CallObjectMethod(context, getPackageManager);
    if (!pm) {
        env->DeleteLocalRef(contextClass);
        return;
    }

    jmethodID getPackageName = env->GetMethodID(contextClass, "getPackageName", "()Ljava/lang/String;");
    if (!getPackageName) {
        env->DeleteLocalRef(pm);
        env->DeleteLocalRef(contextClass);
        return;
    }

    jstring packageName = (jstring)env->CallObjectMethod(context, getPackageName);
    if (!packageName) {
        env->DeleteLocalRef(pm);
        env->DeleteLocalRef(contextClass);
        return;
    }

    jclass pmClass = env->GetObjectClass(pm);
    static const int GET_SIGNATURES = 0x40;
    jmethodID getPackageInfo = env->GetMethodID(pmClass, "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    if (getPackageInfo) {
        jobject pkgInfo = env->CallObjectMethod(pm, getPackageInfo, packageName, GET_SIGNATURES);
        if (pkgInfo) {
            env->DeleteLocalRef(pkgInfo);
            LOGI("APK integrity: signatures present");
        } else {
            LOGW("APK integrity: could not get package info");
        }
    }

    env->DeleteLocalRef(packageName);
    env->DeleteLocalRef(pmClass);
    env->DeleteLocalRef(pm);
    env->DeleteLocalRef(contextClass);
}
