package com.venpk.plugin

import com.android.build.gradle.AppExtension
import org.gradle.api.Plugin
import org.gradle.api.Project

open class VenPKPlugin : Plugin<Project> {

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

            project.logger.lifecycle("[VenPK] Registering VenPK encrypt task for ${project.name}")

            // Always register the standalone encryption task
            val encryptTask = project.tasks.register("venpkEncryptDex", VenPKEncryptTask::class.java) { task ->
                task.sourceModule.set(extension.sourceModule)
                task.assetName.set(extension.assetName)
                task.variantName.set("release")
                task.outputDir.set(project.layout.buildDirectory.dir("venpk/release"))
                task.description = "Encrypts the source module DEX files for VenPK protection"
                task.group = "venpk"
            }

            // Also register debug variant
            project.tasks.register("venpkEncryptDexDebug", VenPKEncryptTask::class.java) { task ->
                task.sourceModule.set(extension.sourceModule)
                task.assetName.set(extension.assetName)
                task.variantName.set("debug")
                task.outputDir.set(project.layout.buildDirectory.dir("venpk/debug"))
                task.description = "Encrypts the source module DEX files (debug) for VenPK protection"
                task.group = "venpk"
            }

            // Register helper task to copy encrypted payload to assets
            project.tasks.register("venpkPrepareAssets") {
                it.dependsOn(encryptTask)
                it.group = "venpk"
                it.description = "Copies encrypted DEX to loader assets directory"

                it.doLast {
                    val payloadFile = project.layout.buildDirectory.get().asFile.resolve("venpk/release/${extension.assetName}")
                    val assetsDir = project.projectDir.resolve("src/main/assets")
                    assetsDir.mkdirs()

                    if (payloadFile.exists()) {
                        payloadFile.copyTo(assetsDir.resolve(extension.assetName), overwrite = true)
                        project.logger.lifecycle("[VenPK] Prepared assets: ${payloadFile.length()} bytes")
                    } else {
                        project.logger.warn("[VenPK] Encrypted payload not found at ${payloadFile.absolutePath}")
                        project.logger.warn("[VenPK] Make sure to build the source module first: ./gradlew :${extension.sourceModule}:assembleRelease")
                    }
                }
            }
        }
    }
}
