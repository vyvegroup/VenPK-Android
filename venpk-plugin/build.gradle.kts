plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    kotlin("jvm") version "1.9.22"
    id("maven-publish")
}

group = "com.venpk"
version = "1.0.0"

repositories {
    mavenCentral()
    google()
}

dependencies {
    compileOnly("com.android.tools.build:gradle:8.2.2")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78")
}

gradlePlugin {
    plugins {
        create("venpk") {
            id = "com.venpk.plugin"
            implementationClass = "com.venpk.plugin.VenPKPlugin"
        }
    }
}

kotlin {
    jvmToolchain(17)
}
