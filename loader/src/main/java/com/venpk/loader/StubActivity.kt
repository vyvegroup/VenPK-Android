package com.venpk.loader

import android.annotation.SuppressLint
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
 * StubActivity - VenPK protected APK entry point.
 *
 * Decrypts real app DEX → InMemoryDexClassLoader → calls AppEntry.launch(this)
 *
 * AppEntry.launch() is a STATIC method taking ComponentActivity as parameter.
 * Since StubActivity extends ComponentActivity, the parameter type always matches.
 * Static method calls have NO receiver type check — works on ALL Android 8+.
 */
class StubActivity : ComponentActivity() {

    companion object {
        private const val TAG = "VenPK"
        private const val PAYLOAD_ASSET = "venpk_payload.bin"
        private const val REAL_ENTRY_CLASS = "com.venpk.app.AppEntry"
        private const val REAL_ENTRY_METHOD = "launch"
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
                showError("Application data not found")
                return
            }
            Log.d(TAG, "Payload loaded: ${payloadData.size} bytes")

            // Step 2: Validate VPK1 header
            if (payloadData.size < 4 || String(payloadData, 0, 4, Charsets.UTF_8) != "VPK1") {
                showError("Application data corrupted")
                return
            }

            // Step 3: Get decryption key from native
            val keyBytes = obtainDecryptionKey()
            if (keyBytes == null || keyBytes.size != 32) {
                showError("Security verification failed")
                return
            }

            // Step 4: Decrypt payload (AES-256-GCM)
            val decryptedDex = decryptAES256GCM(
                payloadData.copyOfRange(4, payloadData.size),
                keyBytes
            )
            if (decryptedDex == null || decryptedDex.isEmpty()) {
                showError("Decryption failed")
                return
            }
            Log.d(TAG, "DEX decrypted: ${decryptedDex.size} bytes")

            // Step 5: Parse multi-dex entries
            val dexEntries = parseMultiDex(decryptedDex)
            Log.d(TAG, "Parsed ${dexEntries.size} DEX entries")

            // Step 6: Create InMemoryDexClassLoader
            val classLoader = createMemoryClassLoader(dexEntries)
                ?: run { showError("Class loading failed"); return }

            // Step 7: Launch real app via static method call (works on ALL Android 8+)
            launchRealApp(classLoader, savedInstanceState)

            // Secure cleanup
            keyBytes.fill(0)
            decryptedDex.fill(0)

        } catch (e: Throwable) {
            Log.e(TAG, "VenPK runtime error", e)
            showError("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Launch the real app by calling AppEntry.launch(this) via reflection.
     *
     * This works because:
     * 1. AppEntry.launch is a STATIC method → no receiver type check
     * 2. Parameter is ComponentActivity → StubActivity IS-A ComponentActivity
     * 3. Method calls enableEdgeToEdge() + setContent {} on the activity
     * 4. All Compose classes resolve via InMemoryDexClassLoader (parent has Compose deps)
     */
    private fun launchRealApp(classLoader: ClassLoader, savedInstanceState: Bundle?) {
        try {
            // Load AppEntry class from decrypted DEX
            val entryClass = classLoader.loadClass(REAL_ENTRY_CLASS)
            Log.d(TAG, "Loaded entry class: ${entryClass.name}")

            // Get the static launch(ComponentActivity, Bundle) method
            // This is the key: STATIC method call → no receiver type check
            val launchMethod = entryClass.getDeclaredMethod(
                REAL_ENTRY_METHOD,
                ComponentActivity::class.java,
                Bundle::class.java
            )
            launchMethod.isAccessible = true

            // Call static method: AppEntry.launch(this, savedInstanceState)
            // 'this' is StubActivity which IS a ComponentActivity → type check passes!
            launchMethod.invoke(null, this, savedInstanceState)

            Log.d(TAG, "✅ Real app launched successfully")

        } catch (e: ClassNotFoundException) {
            Log.e(TAG, "Entry class not found: $REAL_ENTRY_CLASS", e)
            showError("Application class not found")
        } catch (e: NoSuchMethodException) {
            Log.e(TAG, "Launch method not found", e)
            showError("Launch method not found")
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val cause = e.targetException
            Log.e(TAG, "Launch failed: ${cause?.javaClass?.simpleName}: ${cause?.message}", cause)
            showError("${cause?.javaClass?.simpleName}: ${cause?.message}")
        } catch (e: Throwable) {
            Log.e(TAG, "Launch failed", e)
            showError("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    // ─── Utility methods ────────────────────────────────────────────

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
            Log.e(TAG, "Native key retrieval failed", e); null
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
            Log.e(TAG, "Decrypt error: ${e.javaClass.simpleName}: ${e.message}")
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
            Log.e(TAG, "InMemoryDexClassLoader failed", e); null
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
                text = "\u26A0"; textSize = 48f
                gravity = android.view.Gravity.CENTER
                setTextColor(0xFFFF6B6B.toInt())
            }
            val title = android.widget.TextView(this).apply {
                text = "VenPK Engine"; textSize = 24f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(0xFFFFFFFF.toInt())
                gravity = android.view.Gravity.CENTER
            }
            val msg = android.widget.TextView(this).apply {
                text = message; textSize = 14f
                setTextColor(0xFFAAAAAA.toInt())
                gravity = android.view.Gravity.CENTER
                setPadding(0, 24, 0, 0)
            }
            rootView.addView(icon); rootView.addView(title); rootView.addView(msg)
            setContentView(rootView)
        } catch (e: Throwable) { Log.e(TAG, "Cannot show error UI", e) }
    }

    private external fun nativeGetKey(): ByteArray?
}
