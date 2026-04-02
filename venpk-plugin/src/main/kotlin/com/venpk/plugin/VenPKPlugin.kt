package com.venpk.plugin

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.gradle.AppExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.TaskProvider
import java.io.File

abstract class VenPKPlugin : Plugin<Project> {

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

            project.logger.lifecycle("[VenPK] Configuring VenPK protection for ${project.name}")

            // Apply to all variants
            try {
                val componentExtension = project.extensions.getByType(
                    ApplicationAndroidComponentsExtension::class.java
                )
                configureWithComponentExtension(project, componentExtension, extension)
            } catch (e: Exception) {
                project.logger.warn("[VenPK] Component extension not available, using legacy: ${e.message}")
                configureLegacy(project, extension)
            }
        }
    }

    private fun configureWithComponentExtension(
        project: Project,
        extension: ApplicationAndroidComponentsExtension,
        venpkExt: VenPKExtension
    ) {
        extension.onVariants { variant ->
            if (variant.name.lowercase().contains("release") || variant.name.lowercase().contains("debug")) {
                val taskName = "venpkEncrypt${variant.name.replaceFirstChar { it.uppercase() }}Dex"
                val task = project.tasks.register(taskName, VenPKEncryptTask::class.java) { task ->
                    task.sourceModule.set(venpkExt.sourceModule)
                    task.assetName.set(venpkExt.assetName)
                    task.variantName.set(variant.name)
                    task.outputDir.set(project.layout.buildDirectory.dir("venpk/${variant.name}"))
                }

                // Hook into the merge task
                try {
                    variant.artifacts.use(task)
                        .wiredWithFiles(
                            VenPKEncryptTask::mergedDexDir,
                            VenPKEncryptTask::outputAssetsDir
                        )
                        .toTransform(SingleArtifact.MERGED_DEX)
                } catch (e: Exception) {
                    project.logger.warn("[VenPK] Could not wire artifacts: ${e.message}")
                }
            }
        }
    }

    private fun configureLegacy(project: Project, venpkExt: VenPKExtension) {
        // Fallback: register a standalone encryption task
        project.tasks.register("venpkEncryptDex", VenPKEncryptTask::class.java) { task ->
            task.sourceModule.set(venpkExt.sourceModule)
            task.assetName.set(venpkExt.assetName)
            task.variantName.set("release")
            task.outputDir.set(project.layout.buildDirectory.dir("venpk/release"))
        }
    }
}
