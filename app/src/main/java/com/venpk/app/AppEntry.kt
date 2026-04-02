package com.venpk.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.venpk.app.ui.navigation.AppNavHost
import com.venpk.app.ui.theme.VenPKTheme

/**
 * VenPK App Entry Point.
 *
 * This is the entry point that StubActivity calls via reflection after
 * decrypting the DEX payload. The method takes a ComponentActivity parameter,
 * and since StubActivity extends ComponentActivity, the type check always passes.
 *
 * This approach works on ALL Android 8+ versions because:
 * - It's a static method call (no receiver type check)
 * - StubActivity IS a ComponentActivity (satisfies parameter type)
 * - Compose setContent {} works on any ComponentActivity
 */
object AppEntry {

    @JvmStatic
    fun launch(activity: ComponentActivity, savedInstanceState: Bundle? = null) {
        activity.enableEdgeToEdge()
        activity.setContent {
            VenPKTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppNavHost()
                }
            }
        }
    }

    @Composable
    @JvmStatic
    fun AppContent() {
        VenPKTheme {
            Surface(
                modifier = Modifier.fillMaxSize(),
                color = MaterialTheme.colorScheme.background
            ) {
                AppNavHost()
            }
        }
    }
}
