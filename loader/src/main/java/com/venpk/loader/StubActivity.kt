package com.venpk.loader

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dalvik.system.InMemoryDexClassLoader
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * StubActivity - The entry point of the VenPK-protected APK.
 *
 * This activity decrypts the real app's DEX bytecode, loads it into memory,
 * and uses reflection method hijacking to run the real Activity's onCreate()
 * on itself. The real Activity's Compose UI renders within this StubActivity's
 * window - no separate Activity launch is needed.
 */
class StubActivity : ComponentActivity() {

    companion object {
        private const val TAG = "VenPK"
        private const val PAYLOAD_ASSET = "venpk_payload.bin"
        private const val REAL_ACTIVITY_CLASS = "com.venpk.app.MainActivity"
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
                Log.e(TAG, "Invalid payload header - corrupted or tampered")
                showError("Application data corrupted")
                return
            }

            // Step 3: Get decryption key from native (runs security checks first)
            val keyBytes = obtainDecryptionKey()
            if (keyBytes == null || keyBytes.size != 32) {
                Log.e(TAG, "Failed to obtain decryption key - security check may have failed")
                showError("Security verification failed")
                return
            }
            Log.d(TAG, "Decryption key obtained from native engine")

            // Step 4: Decrypt payload using Java Cipher (AES-256-GCM)
            val encryptedData = payloadData.copyOfRange(4, payloadData.size)
            val decryptedDex = decryptAES256GCM(encryptedData, keyBytes)
            if (decryptedDex == null || decryptedDex.isEmpty()) {
                Log.e(TAG, "AES-256-GCM decryption failed - authentication tag mismatch")
                showError("Decryption failed")
                return
            }
            Log.d(TAG, "Dex decrypted: ${decryptedDex.size} bytes")

            // Step 5: Parse multi-dex from payload (4-byte size header per dex)
            val dexEntries = parseMultiDex(decryptedDex)
            Log.d(TAG, "Parsed ${dexEntries.size} DEX entries")

            // Step 6: Load classes from decrypted DEX into memory
            val classLoader = createMemoryClassLoader(dexEntries)
            if (classLoader == null) {
                Log.e(TAG, "Failed to create in-memory class loader")
                showError("Class loading failed")
                return
            }

            // Step 7: Load the real Activity and hijack its onCreate to run on THIS activity
            Log.d(TAG, "Launching real app via reflection method hijacking...")
            launchRealApp(classLoader, savedInstanceState)

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
        return try {
            nativeGetKey()
        } catch (e: Throwable) {
            Log.e(TAG, "Native key retrieval failed", e)
            null
        }
    }

    private fun decryptAES256GCM(encrypted: ByteArray, key: ByteArray): ByteArray? {
        return try {
            if (encrypted.size < GCM_NONCE_LEN + GCM_TAG_LEN) {
                Log.e(TAG, "Encrypted data too short: ${encrypted.size}")
                return null
            }

            val nonce = encrypted.copyOfRange(0, GCM_NONCE_LEN)
            val ciphertextWithTag = encrypted.copyOfRange(GCM_NONCE_LEN, encrypted.size)

            val secretKey: SecretKey = SecretKeySpec(key, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LEN, nonce)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            cipher.doFinal(ciphertextWithTag)
        } catch (e: javax.crypto.AEADBadTagException) {
            Log.e(TAG, "GCM authentication FAILED - data integrity compromised!")
            null
        } catch (e: Throwable) {
            Log.e(TAG, "AES decryption error: ${e.javaClass.simpleName}: ${e.message}")
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

        if (entries.isEmpty()) {
            entries.add(data)
        }

        return entries
    }

    private fun createMemoryClassLoader(dexEntries: List<ByteArray>): ClassLoader? {
        return try {
            val buffers = dexEntries.map { dex ->
                ByteBuffer.wrap(dex)
            }
            InMemoryDexClassLoader(
                buffers.toTypedArray(),
                classLoader
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Error creating InMemoryDexClassLoader", e)
            null
        }
    }

    /**
     * Launch the real app using REFLECTION METHOD HIJACKING.
     *
     * Instead of creating a new Activity instance (which requires fragile Activity.attach()),
     * we call the real MainActivity's onCreate() method directly on THIS StubActivity instance.
     *
     * This works because:
     * 1. StubActivity extends ComponentActivity (same as real MainActivity)
     * 2. The real onCreate() uses `this` only as a ComponentActivity
     * 3. Compose's setContent {} works on any ComponentActivity
     * 4. Class references in the real DEX bytecode are resolved via InMemoryDexClassLoader
     */
    @SuppressLint("DiscouragedPrivateApi")
    private fun launchRealApp(classLoader: ClassLoader, savedInstanceState: Bundle?) {
        try {
            // Load the real Activity class from the decrypted DEX
            val realActivityClass = classLoader.loadClass(REAL_ACTIVITY_CLASS)
            Log.d(TAG, "Loaded real activity class: ${realActivityClass.name}")

            // Method hijacking: call the real Activity's onCreate on THIS instance.
            // The method will execute as if `this` is a MainActivity, but it's actually
            // the StubActivity. Since both extend ComponentActivity, all super calls,
            // enableEdgeToEdge(), and setContent {} work correctly.
            val onCreateMethod = realActivityClass.getDeclaredMethod("onCreate", Bundle::class.java)
            onCreateMethod.isAccessible = true

            Log.d(TAG, "Invoking real onCreate via method hijacking...")
            onCreateMethod.invoke(this, savedInstanceState)

            Log.d(TAG, "✅ Real app launched successfully via method hijacking")

        } catch (e: ClassNotFoundException) {
            Log.e(TAG, "Real activity class not found in decrypted DEX: $REAL_ACTIVITY_CLASS", e)
            showError("Application class not found in payload")
        } catch (e: NoSuchMethodException) {
            Log.e(TAG, "onCreate method not found on real activity", e)
            showError("Application method not found")
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val cause = e.targetException
            Log.e(TAG, "Real activity onCreate threw exception: ${cause?.javaClass?.simpleName}: ${cause?.message}", cause)
            showError("App error: ${cause?.javaClass?.simpleName}: ${cause?.message}")
        } catch (e: NoClassDefFoundError) {
            Log.e(TAG, "Class not found during execution - missing dependency: ${e.message}", e)
            showError("Missing dependency: ${e.message}")
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to launch real activity", e)
            showError("Launch failed: ${e.javaClass.simpleName}: ${e.message}")
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

    private external fun nativeGetKey(): ByteArray?
}
