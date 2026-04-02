# VenPK Loader ProGuard Rules

# Keep VenPK loader classes
-keep class com.venpk.loader.** { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Compose runtime classes (needed by the decrypted DEX)
-keep class androidx.compose.** { *; }
-keep class androidx.navigation.** { *; }
-keep class kotlinx.coroutines.** { *; }

# Keep Compose compiler-generated classes
-keepclassmembers class * {
    *** *Composable();
}

# Don't warn about crypto
-dontwarn javax.crypto.**

# Strip debug logs in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
