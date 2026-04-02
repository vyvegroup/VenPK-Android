package com.venpk.loader

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import dalvik.system.InMemoryDexClassLoader
import java.io.ByteArrayInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class StubActivity : Activity() {

    companion object {
        private const val TAG = "VenPK"
        private const val PAYLOAD_ASSET = "venpk_payload.bin"
        private const val REAL_APP_CLASS = "com.venpk.app.VenPKApp"
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

            // Step 7: Launch the real application activity
            Log.d(TAG, "Launching real activity...")
            launchRealActivity(classLoader)

            // Secure cleanup - zero key from memory
            keyBytes.fill(0)
            decryptedDex.fill(0)

        } catch (e: Throwable) {
            Log.e(TAG, "VenPK runtime error", e)
            showError("Runtime error: ${e.javaClass.simpleName}")
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

    /**
     * Get decryption key from native engine.
     * Native code performs all security checks (anti-debug, anti-frida, integrity)
     * before releasing the key. If any check fails, returns null.
     */
    private fun obtainDecryptionKey(): ByteArray? {
        return try {
            nativeGetKey()
        } catch (e: Throwable) {
            Log.e(TAG, "Native key retrieval failed", e)
            null
        }
    }

    /**
     * AES-256-GCM decryption using Java Cipher API.
     * The payload format is: nonce(12) + ciphertext + GCM tag(16)
     * GCM tag is appended by the Cipher API automatically.
     */
    private fun decryptAES256GCM(encrypted: ByteArray, key: ByteArray): ByteArray? {
        return try {
            if (encrypted.size < GCM_NONCE_LEN + GCM_TAG_LEN) {
                Log.e(TAG, "Encrypted data too short: ${encrypted.size}")
                return null
            }

            // Extract nonce (first 12 bytes)
            val nonce = encrypted.copyOfRange(0, GCM_NONCE_LEN)
            // Extract ciphertext + tag (remaining bytes)
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

    /**
     * Parse multi-dex payload.
     * Format: [4-byte size][dex data][4-byte size][dex data]...
     * Returns list of individual DEX byte arrays.
     */
    private fun parseMultiDex(data: ByteArray): List<ByteArray> {
        val entries = mutableListOf<ByteArray>()
        var offset = 0

        while (offset < data.size - 4) {
            // Read 4-byte big-endian size
            val size = ((data[offset].toInt() and 0xFF) shl 24) or
                    ((data[offset + 1].toInt() and 0xFF) shl 16) or
                    ((data[offset + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + 3].toInt() and 0xFF)
            offset += 4

            if (size <= 0 || offset + size > data.size) break

            entries.add(data.copyOfRange(offset, offset + size))
            offset += size
        }

        // If no valid header found, treat entire data as single dex
        if (entries.isEmpty()) {
            entries.add(data)
        }

        return entries
    }

    /**
     * Create InMemoryDexClassLoader - loads DEX directly into memory
     * without writing any files to disk. This is the core of VenPK's
     * zero-disk protection.
     */
    private fun createMemoryClassLoader(dexEntries: List<ByteArray>): ClassLoader? {
        return try {
            // Use the first DEX as primary, with parent classloader for framework classes
            val primaryDex = dexEntries.first()
            InMemoryDexClassLoader(
                ByteArrayInputStream(primaryDex),
                classLoader
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Error creating InMemoryDexClassLoader", e)
            null
        }
    }

    private fun launchRealActivity(classLoader: ClassLoader) {
        try {
            // Load the real Activity class from the decrypted DEX
            val activityClass = classLoader.loadClass(REAL_ACTIVITY_CLASS)

            // Create intent targeting the loaded activity
            val intent = Intent(this, activityClass).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
                // Pass original intent data if any
                putExtras(getIntent().extras ?: android.os.Bundle())
            }

            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
            Log.d(TAG, "Real activity launched successfully")
        } catch (e: ClassNotFoundException) {
            Log.e(TAG, "Real activity class not found in decrypted DEX: $REAL_ACTIVITY_CLASS", e)
            showError("Application class not found")
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to launch real activity", e)
            showError("Launch failed")
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
     * Native method: returns 32-byte AES-256 key after security verification.
     * Returns null if any security check fails (anti-debug, anti-frida, integrity, etc.)
     */
    private external fun nativeGetKey(): ByteArray?
}
