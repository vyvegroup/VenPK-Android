package com.venpk.app.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val LightColorScheme = lightColorScheme(
    primary = VenPKPrimary,
    onPrimary = VenPKOnPrimary,
    primaryContainer = VenPKPrimaryContainer,
    onPrimaryContainer = VenPKOnPrimaryContainer,
    secondary = VenPKSecondary,
    onSecondary = VenPKOnSecondary,
    secondaryContainer = VenPKSecondaryContainer,
    onSecondaryContainer = VenPKOnSecondaryContainer,
    tertiary = VenPKTertiary,
    onTertiary = VenPKOnTertiary,
    tertiaryContainer = VenPKTertiaryContainer,
    onTertiaryContainer = VenPKOnTertiaryContainer,
    background = VenPKBackground,
    onBackground = VenPKOnBackground,
    surface = VenPKSurface,
    onSurface = VenPKOnSurface
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF88D8A9),
    onPrimary = Color(0xFF003821),
    primaryContainer = Color(0xFF005236),
    onPrimaryContainer = Color(0xFFA4F4C5),
    secondary = Color(0xFFB4CCBA),
    onSecondary = Color(0xFF203528),
    secondaryContainer = Color(0xFF374B3E),
    onSecondaryContainer = Color(0xFFD0E8D6),
    tertiary = Color(0xFFA4CDDE),
    onTertiary = Color(0xFF033642),
    tertiaryContainer = Color(0xFF214C5B),
    onTertiaryContainer = Color(0xFFC0E9FB),
    background = Color(0xFF191C19),
    onBackground = Color(0xFFE1E3DE),
    surface = Color(0xFF191C19),
    onSurface = Color(0xFFE1E3DE)
)

@Composable
fun VenPKTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = VenPKTypography,
        content = content
    )
}
