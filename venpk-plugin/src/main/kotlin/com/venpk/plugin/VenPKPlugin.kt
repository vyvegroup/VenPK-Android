package com.venpk.plugin

import com.android.build.gradle.AppExtension
import org.gradle.api.DefaultTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.TaskProvider

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
            encryptRelease.configure { task ->
                task.sourceModule.set(extension.sourceModule)
                task.assetName.set(extension.assetName)
                task.variantName.set("release")
                task.outputDir.set(project.layout.buildDirectory.dir("venpk/release"))
                task.description = "Encrypts DEX files for VenPK protection (release)"
                task.group = "venpk"
            }

            // Register encrypt task (debug)
            val encryptDebug = project.tasks.register(
                "venpkEncryptDexDebug",
                VenPKEncryptTask::class.java
            )
            encryptDebug.configure { task ->
                task.sourceModule.set(extension.sourceModule)
                task.assetName.set(extension.assetName)
                task.variantName.set("debug")
                task.outputDir.set(project.layout.buildDirectory.dir("venpk/debug"))
                task.description = "Encrypts DEX files for VenPK protection (debug)"
                task.group = "venpk"
            }

            // Register helper task to copy encrypted payload to assets
            val prepareAssets = project.tasks.register("venpkPrepareAssets")
            prepareAssets.configure { task ->
                task.dependsOn(encryptRelease)
                task.description = "Copies encrypted DEX to loader assets directory"
                task.group = "venpk"
                task.doLast {
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
