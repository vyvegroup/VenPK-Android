-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

-dontwarn javax.annotation.**
-dontwarn kotlin.Unit
-dontwarn retrofit2.**
-dontwarn okhttp3.**

-keep class com.venpk.app.** { *; }
