package com.venpk.loader

import android.content.Context
import android.util.Log
import java.security.MessageDigest

object VenPKEngine {

    private const val TAG = "VenPK-Engine"
    private var initialized = false
    private lateinit var appContext: Context

    @JvmStatic
    fun initialize(context: Context) {
        if (initialized) return

        appContext = context.applicationContext

        try {
            runIntegrityChecks()
            Log.d(TAG, "VenPK Engine initialized successfully")
            initialized = true
        } catch (e: Throwable) {
            Log.e(TAG, "VenPK Engine initialization failed", e)
        }
    }

    private fun runIntegrityChecks() {
        checkSignature()
        checkDebugging()
        checkEmulator()
        checkFrida()
        checkRoot()
    }

    private fun checkSignature() {
        try {
            val packageInfo = appContext.packageManager.getPackageInfo(
                appContext.packageName,
                android.content.pm.PackageManager.GET_SIGNATURES
            )
            val signatures = packageInfo.signatures ?: return
            for (sig in signatures) {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(sig.toByteArray())
                Log.d(TAG, "APK signature hash: ${digest.toHexString()}")
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Signature check failed", e)
        }
    }

    private fun checkDebugging() {
        val isDebuggable = (appContext.applicationInfo.flags and
            android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

        if (isDebuggable) {
            Log.w(TAG, "Debuggable flag detected")
        }

        if (android.os.Debug.isDebuggerConnected()) {
            Log.w(TAG, "Debugger detected")
        }

        if (android.os.Debug.waitingForDebugger()) {
            Log.w(TAG, "Waiting for debugger")
        }
    }

    private fun checkEmulator() {
        val emulatorIndicators = listOf(
            "goldfish", "ranchu", "vbox", "genymotion",
            "nox", "bluestacks", "memu"
        )

        val buildProps = System.getProperty("ro.hardware", "") +
            System.getProperty("ro.product.model", "") +
            System.getProperty("ro.product.board", "")

        for (indicator in emulatorIndicators) {
            if (buildProps.contains(indicator, ignoreCase = true)) {
                Log.w(TAG, "Emulator indicator detected: $indicator")
                break
            }
        }
    }

    private fun checkFrida() {
        try {
            val maps = java.io.File("/proc/self/maps")
            if (maps.exists()) {
                maps.bufferedReader().use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        if (line.contains("frida", ignoreCase = true) ||
                            line.contains("agent", ignoreCase = true)) {
                            Log.w(TAG, "Suspicious library in memory maps")
                            break
                        }
                        line = reader.readLine()
                    }
                }
            }
        } catch (e: Throwable) {
            // Not accessible, ignore
        }

        try {
            val proc = Runtime.getRuntime().exec("which frida-server")
            proc.inputStream.read()
            if (proc.waitFor() == 0) {
                Log.w(TAG, "Frida server found")
            }
        } catch (e: Throwable) {
            // frida-server not found, good
        }
    }

    private fun checkRoot() {
        val rootPaths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/su/bin/su"
        )

        for (path in rootPaths) {
            if (java.io.File(path).exists()) {
                Log.w(TAG, "Root indicator found: $path")
                break
            }
        }
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
