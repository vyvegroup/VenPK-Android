package com.venpk.plugin

import com.android.build.gradle.AppExtension
import org.gradle.api.Plugin
import org.gradle.api.Project

class VenPKPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val extension = project.extensions.create("venpk", VenPKExtension::class.java)

        project.afterEvaluate {
            if (!extension.enabled) {
                project.logger.lifecycle("[VenPK] Plugin disabled")
                return@afterEvaluate
            }

            val appExtension = project.extensions.findByType(AppExtension::class.java)
            if (appExtension == null) {
                project.logger.lifecycle("[VenPK] Not an Android Application module, skipping")
                return@afterEvaluate
            }

            project.logger.lifecycle("[VenPK] Registering VenPK encrypt tasks for ${project.name}")

            // Register encrypt task (release) - use configure with receiver lambda
            val encryptRelease = project.tasks.register(
                "venpkEncryptDex",
                VenPKEncryptTask::class.java
            )
            encryptRelease.configure {
                sourceModule.set(extension.sourceModule)
                assetName.set(extension.assetName)
                variantName.set("release")
                outputDir.set(project.layout.buildDirectory.dir("venpk/release"))
                description = "Encrypts DEX files for VenPK protection (release)"
                group = "venpk"
            }

            // Register encrypt task (debug)
            val encryptDebug = project.tasks.register(
                "venpkEncryptDexDebug",
                VenPKEncryptTask::class.java
            )
            encryptDebug.configure {
                sourceModule.set(extension.sourceModule)
                assetName.set(extension.assetName)
                variantName.set("debug")
                outputDir.set(project.layout.buildDirectory.dir("venpk/debug"))
                description = "Encrypts DEX files for VenPK protection (debug)"
                group = "venpk"
            }

            // Register helper task: copy encrypted payload to assets
            val prepareAssets = project.tasks.register("venpkPrepareAssets")
            prepareAssets.configure {
                dependsOn(encryptRelease.get())
                description = "Copies encrypted DEX to loader assets directory"
                group = "venpk"
                doLast {
                    val buildDir = project.layout.buildDirectory.get().asFile
                    val payloadFile = buildDir.resolve("venpk/release/${extension.assetName}")
                    val assetsDir = project.projectDir.resolve("src/main/assets")
                    assetsDir.mkdirs()

                    if (payloadFile.exists()) {
                        payloadFile.copyTo(assetsDir.resolve(extension.assetName), overwrite = true)
                        project.logger.lifecycle("[VenPK] Prepared assets: ${payloadFile.length()} bytes")
                    } else {
                        project.logger.warn("[VenPK] Encrypted payload not found at ${payloadFile.absolutePath}")
                        project.logger.warn("[VenPK] Build the source module first: ./gradlew :${extension.sourceModule}:assembleRelease")
                    }
                }
            }
        }
    }
}
