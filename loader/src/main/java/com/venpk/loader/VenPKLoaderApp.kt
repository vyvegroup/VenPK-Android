package com.venpk.loader

import android.app.Application
import android.content.Context
import android.util.Log

class VenPKLoaderApp : Application() {

    companion object {
        private const val TAG = "VenPK"
        init {
            try {
                System.loadLibrary("venpk")
                Log.d(TAG, "VenPK native library loaded")
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to load native library", e)
            }
        }
    }

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        runSecurityChecks(base)
    }

    override fun onCreate() {
        super.onCreate()
        VenPKEngine.initialize(this)
    }

    private fun runSecurityChecks(context: Context) {
        try {
            val nativeInit = nativeInitSecurity(context.filesDir.absolutePath)
            Log.d(TAG, "Security init result: $nativeInit")
        } catch (e: Throwable) {
            Log.e(TAG, "Security check error", e)
        }
    }

    private external fun nativeInitSecurity(dataDir: String): Int
}
