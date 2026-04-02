-keep class com.venpk.loader.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
-dontwarn javax.crypto.**
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
