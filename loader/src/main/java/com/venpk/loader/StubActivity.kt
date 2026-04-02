package com.venpk.loader

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import dalvik.system.InMemoryDexClassLoader
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * StubActivity - VenPK entry point.
 *
 * Decrypts the real app's DEX bytecode in memory, loads it via InMemoryDexClassLoader,
 * then uses JNI (CallNonvirtualVoidMethod) to call the real Activity's onCreate() on
 * this StubActivity instance, bypassing Java's receiver type check.
 */
class StubActivity : ComponentActivity() {

    companion object {
        private const val TAG = "VenPK"
        private const val PAYLOAD_ASSET = "venpk_payload.bin"
        private const val REAL_ACTIVITY_CLASS = "com.venpk.app.MainActivity"
        private const val REAL_APP_CLASS = "com.venpk.app.VenPKApp"
        private const val GCM_NONCE_LEN = 12
        private const val GCM_TAG_LEN = 128
    }

    @SuppressLint("DiscouragedPrivateApi")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d(TAG, "StubActivity created - initiating VenPK runtime")

        try {
            // Step 1: Load encrypted payload from assets
            val payloadData = loadEncryptedPayload()
            if (payloadData == null || payloadData.isEmpty()) {
                Log.e(TAG, "Payload not found or empty")
                showError("Application data not found")
                return
            }
            Log.d(TAG, "Payload loaded: ${payloadData.size} bytes")

            // Step 2: Validate payload header
            if (payloadData.size < 4 || String(payloadData, 0, 4, Charsets.UTF_8) != "VPK1") {
                Log.e(TAG, "Invalid payload header")
                showError("Application data corrupted")
                return
            }

            // Step 3: Get decryption key from native
            val keyBytes = obtainDecryptionKey()
            if (keyBytes == null || keyBytes.size != 32) {
                Log.e(TAG, "Failed to obtain decryption key")
                showError("Security verification failed")
                return
            }
            Log.d(TAG, "Decryption key obtained")

            // Step 4: Decrypt payload
            val encryptedData = payloadData.copyOfRange(4, payloadData.size)
            val decryptedDex = decryptAES256GCM(encryptedData, keyBytes)
            if (decryptedDex == null || decryptedDex.isEmpty()) {
                Log.e(TAG, "AES-256-GCM decryption failed")
                showError("Decryption failed")
                return
            }
            Log.d(TAG, "DEX decrypted: ${decryptedDex.size} bytes")

            // Step 5: Parse multi-dex
            val dexEntries = parseMultiDex(decryptedDex)
            Log.d(TAG, "Parsed ${dexEntries.size} DEX entries")

            // Step 6: Create in-memory class loader
            val classLoader = createMemoryClassLoader(dexEntries)
            if (classLoader == null) {
                showError("Class loading failed")
                return
            }

            // Step 7: Initialize real Application class (for VenPKApp.instance etc.)
            initRealApplication(classLoader)

            // Step 8: Inject Activity fields so framework works correctly
            injectActivityFields(classLoader)

            // Step 9: Call real Activity's onCreate via JNI (bypasses receiver type check)
            Log.d(TAG, "Launching real app via JNI...")
            val launched = nativeCallActivityOnCreate(
                classLoader.loadClass(REAL_ACTIVITY_CLASS),
                savedInstanceState
            )

            if (!launched) {
                Log.e(TAG, "JNI launch failed, trying fallback...")
                tryFallbackLaunch(classLoader, savedInstanceState)
            } else {
                Log.d(TAG, "✅ Real app launched successfully via JNI")
            }

            // Secure cleanup
            keyBytes.fill(0)
            decryptedDex.fill(0)

        } catch (e: Throwable) {
            Log.e(TAG, "VenPK runtime error", e)
            showError("Runtime error: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun loadEncryptedPayload(): ByteArray? {
        return try {
            assets.open(PAYLOAD_ASSET).use { stream ->
                val buffer = ByteArray(stream.available())
                var totalRead = 0
                while (totalRead < buffer.size) {
                    val read = stream.read(buffer, totalRead, buffer.size - totalRead)
                    if (read == -1) break
                    totalRead += read
                }
                if (totalRead != buffer.size) buffer.copyOf(totalRead) else buffer
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error loading payload", e)
            null
        }
    }

    private fun obtainDecryptionKey(): ByteArray? {
        return try { nativeGetKey() } catch (e: Throwable) {
            Log.e(TAG, "Native key retrieval failed", e)
            null
        }
    }

    private fun decryptAES256GCM(encrypted: ByteArray, key: ByteArray): ByteArray? {
        return try {
            if (encrypted.size < GCM_NONCE_LEN + GCM_TAG_LEN) return null
            val nonce = encrypted.copyOfRange(0, GCM_NONCE_LEN)
            val ct = encrypted.copyOfRange(GCM_NONCE_LEN, encrypted.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_LEN, nonce))
            cipher.doFinal(ct)
        } catch (e: Throwable) {
            Log.e(TAG, "Decryption error: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    private fun parseMultiDex(data: ByteArray): List<ByteArray> {
        val entries = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < data.size - 4) {
            val size = ((data[offset].toInt() and 0xFF) shl 24) or
                    ((data[offset + 1].toInt() and 0xFF) shl 16) or
                    ((data[offset + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + 3].toInt() and 0xFF)
            offset += 4
            if (size <= 0 || offset + size > data.size) break
            entries.add(data.copyOfRange(offset, offset + size))
            offset += size
        }
        if (entries.isEmpty()) entries.add(data)
        return entries
    }

    private fun createMemoryClassLoader(dexEntries: List<ByteArray>): ClassLoader? {
        return try {
            InMemoryDexClassLoader(
                dexEntries.map { ByteBuffer.wrap(it) }.toTypedArray(),
                classLoader
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Error creating InMemoryDexClassLoader", e)
            null
        }
    }

    /**
     * Initialize the real app's Application class.
     * The real app might reference VenPKApp.instance, so we initialize it.
     */
    @SuppressLint("DiscouragedPrivateApi", "PrivateApi")
    private fun initRealApplication(classLoader: ClassLoader) {
        try {
            val realAppClass = classLoader.loadClass(REAL_APP_CLASS)
            val realApp = realAppClass.getDeclaredConstructor().newInstance()

            // Inject the base context into the real Application
            try {
                val attachBase = android.app.Application::class.java.getDeclaredMethod(
                    "attachBaseContext", Context::class.java
                )
                attachBase.isAccessible = true
                attachBase.invoke(realApp, baseContext)
            } catch (e: Throwable) {
                Log.d(TAG, "attachBaseContext on real app skipped: ${e.message}")
            }

            // Call onCreate
            try {
                val onCreate = android.app.Application::class.java.getDeclaredMethod("onCreate")
                onCreate.isAccessible = true
                onCreate.invoke(realApp)
                Log.d(TAG, "Real Application class initialized: ${realAppClass.name}")
            } catch (e: Throwable) {
                Log.d(TAG, "Real app onCreate skipped: ${e.message}")
            }
        } catch (e: Throwable) {
            Log.d(TAG, "Real app init skipped: ${e.message}")
        }
    }

    /**
     * Inject critical Activity fields so the framework treats this
     * StubActivity as if it were the real Activity.
     */
    @SuppressLint("DiscouragedPrivateApi", "PrivateApi")
    private fun injectActivityFields(classLoader: ClassLoader) {
        try {
            // Set mComponent to point to the real Activity class
            val mComponent = ComponentName(packageName, REAL_ACTIVITY_CLASS)
            setField(Activity::class.java, this, "mComponent", mComponent)

            // Set mIntent with the correct component
            val newIntent = Intent(intent).apply {
                component = mComponent
            }
            setField(Activity::class.java, this, "mIntent", newIntent)
        } catch (e: Throwable) {
            Log.d(TAG, "Field injection skipped: ${e.message}")
        }
    }

    /**
     * Fallback: If JNI launch fails, try using the internal ART reflection
     * mechanism to bypass the type check.
     */
    @SuppressLint("DiscouragedPrivateApi", "BlockedPrivateApi", "PrivateApi")
    private fun tryFallbackLaunch(classLoader: ClassLoader, savedInstanceState: Bundle?) {
        try {
            val realActivityClass = classLoader.loadClass(REAL_ACTIVITY_CLASS)
            val method = realActivityClass.getDeclaredMethod("onCreate", Bundle::class.java)
            method.isAccessible = true

            // Try using sun.misc.Unsafe equivalent on Android
            // Access the internal ArtMethod and invoke directly
            try {
                val artMethod = method.getDeclaredField("artMethod")
                artMethod.isAccessible = true
                Log.d(TAG, "ArtMethod field accessible, but direct invocation not implemented")
            } catch (e: NoSuchFieldException) {
                // Expected on most Android versions
            }

            // Final fallback: use setAccessible and invoke with MethodProxy
            // On some ART versions, we can bypass by modifying the method's declaring class
            Log.e(TAG, "All launch methods failed. Showing error.")
            showError("Launch failed - incompatible Android version")

        } catch (e: Throwable) {
            Log.e(TAG, "Fallback launch error", e)
            showError("Launch failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun setField(clazz: Class<*>, target: Any, fieldName: String, value: Any?) {
        try {
            val field = clazz.getDeclaredField(fieldName)
            field.isAccessible = true
            field.set(target, value)
        } catch (e: NoSuchFieldException) {
            try {
                val field = clazz.superclass.getDeclaredField(fieldName)
                field.isAccessible = true
                field.set(target, value)
            } catch (e2: Throwable) {
                Log.d(TAG, "Field $fieldName not found")
            }
        } catch (e: Throwable) {
            Log.d(TAG, "Failed to set field $fieldName: ${e.message}")
        }
    }

    private fun showError(message: String) {
        Log.e(TAG, "VenPK Error: $message")
        try {
            val rootView = android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                gravity = android.view.Gravity.CENTER
                setPadding(48, 48, 48, 48)
                setBackgroundColor(0xFF1B1B1B.toInt())
            }
            val icon = android.widget.TextView(this).apply {
                text = "\u26A0"
                textSize = 48f
                gravity = android.view.Gravity.CENTER
                setTextColor(0xFFFF6B6B.toInt())
            }
            val title = android.widget.TextView(this).apply {
                text = "VenPK Engine"
                textSize = 24f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(0xFFFFFFFF.toInt())
                gravity = android.view.Gravity.CENTER
            }
            val msg = android.widget.TextView(this).apply {
                text = message
                textSize = 14f
                setTextColor(0xFFAAAAAA.toInt())
                gravity = android.view.Gravity.CENTER
                setPadding(0, 24, 0, 0)
            }
            rootView.addView(icon)
            rootView.addView(title)
            rootView.addView(msg)
            setContentView(rootView)
        } catch (e: Throwable) {
            Log.e(TAG, "Cannot show error UI", e)
        }
    }

    /**
     * JNI method: Calls the real Activity's onCreate() on this StubActivity
     * using CallNonvirtualVoidMethod, which bypasses Java's receiver type check.
     * On Android ART, CallNonvirtualVoidMethod directly invokes the method
     * from the specified class without checking if the receiver is an instance.
     */
    private external fun nativeCallActivityOnCreate(activityClass: Class<*>, savedInstanceState: Bundle?): Boolean

    private external fun nativeGetKey(): ByteArray?
}
