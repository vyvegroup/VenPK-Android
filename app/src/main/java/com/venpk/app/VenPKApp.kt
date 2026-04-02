package com.venpk.app

import android.app.Application
import android.util.Log

class VenPKApp : Application() {

    override fun onCreate() {
        super.onCreate()
        Log.d("VenPKApp", "Application initialized")
        instance = this
    }

    companion object {
        lateinit var instance: VenPKApp
            private set
    }
}
