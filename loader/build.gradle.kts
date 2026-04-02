plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.venpk.plugin")
}

android {
    namespace = "com.venpk.loader"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.venpk.loader"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17 -fvisibility=hidden -ffunction-sections -fdata-sections"
                arguments += "-DANDROID_STL=c++_static"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "26.1.10909125"
        }
    }
}

venpk {
    sourceModule = "app"
    enabled = true
}
