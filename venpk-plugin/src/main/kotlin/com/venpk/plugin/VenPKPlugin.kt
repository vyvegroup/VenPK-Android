package com.venpk.plugin

import com.android.build.gradle.AppExtension
import org.gradle.api.GradleException
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

            // Register encrypt task (release)
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
                        project.logger.lifecycle("[VenPK] ✅ Prepared assets: ${payloadFile.length()} bytes → ${assetsDir.resolve(extension.assetName).absolutePath}")
                    } else {
                        // HARD FAIL - do not silently continue
                        throw GradleException("""
                            [VenPK] FATAL: Encrypted payload not found at ${payloadFile.absolutePath}
                            [VenPK] The venpkEncryptDex task did not produce output.
                            [VenPK] Make sure the '${extension.sourceModule}' module builds successfully first.
                            [VenPK] Run: ./gradlew :${extension.sourceModule}:assembleRelease
                        """.trimIndent())
                    }
                }
            }

            // Wire venpkPrepareAssets into the loader's build lifecycle
            // This ensures the payload is always prepared before the APK is built
            project.tasks.matching {
                it.name == "mergeReleaseAssets" || it.name == "processReleaseManifest"
            }.configureEach {
                dependsOn(prepareAssets)
            }

            project.tasks.matching {
                it.name == "mergeDebugAssets" || it.name == "processDebugManifest"
            }.configureEach {
                dependsOn(project.tasks.named("venpkEncryptDexDebug"))
            }
        }
    }
}
