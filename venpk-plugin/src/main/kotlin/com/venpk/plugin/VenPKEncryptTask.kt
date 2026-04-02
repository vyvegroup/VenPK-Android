package com.venpk.plugin

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class VenPKEncryptTask : DefaultTask() {

    @get:Input
    abstract val sourceModule: Property<String>

    @get:Input
    abstract val assetName: Property<String>

    @get:Input
    abstract val variantName: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun execute() {
        logger.lifecycle("[VenPK] ═══════════════════════════════════════════")
        logger.lifecycle("[VenPK] Starting DEX encryption for variant: ${variantName.get()}")
        logger.lifecycle("[VenPK] Source module: ${sourceModule.get()}")

        val sourceDir = findSourceDexDir()
        if (sourceDir == null) {
            logger.lifecycle("[VenPK] ─── Scanning app/build for ANY .dex files ───")
            // Deep scan: walk the entire app/build directory
            val appBuildDir = File(project.rootDir, "${sourceModule.get()}/build")
            if (appBuildDir.exists()) {
                val allDexFiles = mutableListOf<File>()
                appBuildDir.walkTopDown()
                    .filter { it.isFile && it.name.endsWith(".dex") && it.name.startsWith("classes") }
                    .forEach { allDexFiles.add(it) }

                if (allDexFiles.isNotEmpty()) {
                    logger.lifecycle("[VenPK] Deep scan found ${allDexFiles.size} DEX file(s):")
                    allDexFiles.forEach { f ->
                        logger.lifecycle("[VenPK]   → ${f.absolutePath} (${f.length()} bytes)")
                    }

                    // Use the directory containing the first DEX file
                    val parentDir = allDexFiles.first().parentFile
                    logger.lifecycle("[VenPK] Using DEX directory: ${parentDir?.absolutePath}")
                    encryptFromDir(parentDir!!)
                    return
                }
            }

            // List what actually exists for debugging
            logger.lifecycle("[VenPK] ─── Debug: app/build contents ───")
            val appBuildDir2 = File(project.rootDir, "${sourceModule.get()}/build")
            if (appBuildDir2.exists()) {
                appBuildDir2.walkTopDown().maxDepth(3)
                    .filter { it.isDirectory }
                    .forEach { dir ->
                        val dexCount = dir.listFiles { f -> f.name.endsWith(".dex") }?.size ?: 0
                        if (dexCount > 0 || dir.name == "dex" || dir.name == "intermediates") {
                            logger.lifecycle("[VenPK]   ${dir.absolutePath} (dex files: $dexCount)")
                        }
                    }
            } else {
                logger.lifecycle("[VenPK]   ERROR: ${appBuildDir2.absolutePath} DOES NOT EXIST")
                logger.lifecycle("[VenPK]   Did you run :${sourceModule.get()}:assemble${variantName.get().replaceFirstChar { it.uppercase() }} first?")
            }

            throw GradleException("""
                [VenPK] FATAL: Source DEX directory not found!
                [VenPK] Make sure the '${sourceModule.get()}' module has been built first.
                [VenPK] Run: ./gradlew :${sourceModule.get()}:assemble${variantName.get().replaceFirstChar { it.uppercase() }}
            """.trimIndent())
        }

        encryptFromDir(sourceDir)
    }

    private fun encryptFromDir(sourceDir: File) {
        val dexFiles = sourceDir.listFiles { file ->
            file.name.endsWith(".dex") && file.isFile && file.name.startsWith("classes")
        }

        if (dexFiles.isNullOrEmpty()) {
            throw GradleException("""
                [VenPK] FATAL: No DEX files found in ${sourceDir.absolutePath}
                [VenPK] Directory contents: ${sourceDir.listFiles()?.map { "${it.name} (${it.length()})" }?.joinToString(", ")}
            """.trimIndent())
        }

        logger.lifecycle("[VenPK] Found ${dexFiles.size} DEX file(s) to encrypt:")
        dexFiles.sortedBy { it.name }.forEach { f ->
            logger.lifecycle("[VenPK]   → ${f.name} (${f.length()} bytes)")
        }

        // Concatenate all dex files with size headers
        val allDex = ByteArrayOutputStream()
        for (dexFile in dexFiles.sortedBy { it.name }) {
            FileInputStream(dexFile).use { input ->
                val size = dexFile.length()
                // Write 4-byte big-endian size header
                allDex.write((size ushr 24).toInt() and 0xFF)
                allDex.write((size ushr 16).toInt() and 0xFF)
                allDex.write((size ushr 8).toInt() and 0xFF)
                allDex.write(size.toInt() and 0xFF)
                // Write dex data
                input.copyTo(allDex)
            }
        }

        val plainDex = allDex.toByteArray()
        logger.lifecycle("[VenPK] Combined DEX size: ${plainDex.size} bytes")

        // Derive key and encrypt
        val key = deriveMasterKey()
        val encrypted = encryptAES256GCM(plainDex, key)
        logger.lifecycle("[VenPK] Encrypted payload size: ${encrypted.size} bytes")

        // Write encrypted payload with VPK1 header
        val outputDirectory = outputDir.get().asFile
        outputDirectory.mkdirs()
        val outputFile = File(outputDirectory, assetName.get())
        FileOutputStream(outputFile).use { out ->
            out.write("VPK1".toByteArray(Charsets.UTF_8))
            out.write(encrypted)
        }

        logger.lifecycle("[VenPK] ✅ Encrypted payload written: ${outputFile.absolutePath} (${outputFile.length()} bytes)")
        logger.lifecycle("[VenPK] ═══════════════════════════════════════════")

        // Secure cleanup
        plainDex.fill(0)
        encrypted.fill(0)
        key.fill(0)
    }

    private fun findSourceDexDir(): File? {
        val moduleName = sourceModule.get()
        val variant = variantName.get()
        val buildDir = File(project.rootDir, "$moduleName/build")
        val capitalizedVariant = variant.replaceFirstChar { it.uppercase() }

        // Known paths where merged DEX files are output by AGP (comprehensive list)
        val possiblePaths = listOf(
            // AGP 8.x primary paths
            "$buildDir/intermediates/dex/$variant/mergeDex$capitalizedVariant/out",
            "$buildDir/intermediates/dex/$variant/mergeProjectDex/$variant/out",
            "$buildDir/intermediates/dex/$variant/mergeDex/out",
            "$buildDir/intermediates/dex/$variant/mergeExtDex$capitalizedVariant/out",
            "$buildDir/intermediates/dex/$variant/mergeLibDex$capitalizedVariant/out",
            // AGP 7.x fallback paths
            "$buildDir/intermediates/transforms/dex_builder/$variant/0",
            "$buildDir/intermediates/transforms/dex_merger/$variant/0",
            // Legacy paths
            "$buildDir/outputs/dex/$variant/mergeDex$capitalizedVariant/out",
            "$buildDir/intermediates/dex/$variant/out",
            // Direct path without variant subfolder
            "$buildDir/intermediates/dex/$variant/mergeDex$capitalizedVariant"
        )

        for (path in possiblePaths) {
            val dir = File(path)
            if (dir.exists() && dir.isDirectory) {
                val dexFiles = dir.listFiles { f -> f.name.endsWith(".dex") && f.name.startsWith("classes") }
                if (!dexFiles.isNullOrEmpty()) {
                    logger.lifecycle("[VenPK] Found DEX files at: $dir")
                    return dir
                }
            }
        }

        // Fallback: walk intermediates looking for any directory containing dex files
        val intermediatesDir = File(buildDir, "intermediates")
        if (intermediatesDir.exists()) {
            logger.lifecycle("[VenPK] Primary paths not found, scanning intermediates...")
            val found = intermediatesDir.walkTopDown()
                .filter { it.isDirectory }
                .firstOrNull { dir ->
                    val dexFiles = dir.listFiles { f -> f.name.endsWith(".dex") && f.name.startsWith("classes") }
                    !dexFiles.isNullOrEmpty()
                }
            if (found != null) {
                logger.lifecycle("[VenPK] Found DEX files (fallback) at: $found")
                return found
            }
        }

        return null
    }

    /**
     * Derives the AES-256 master key from obfuscated fragments.
     * This must match exactly with the native code in venpk_crypto.cpp.
     */
    private fun deriveMasterKey(): ByteArray {
        val frag0 = byteArrayOf(0xF7.toByte(), 0xA2.toByte(), 0x1B.toByte(), 0x3E.toByte(),
            0x8D.toByte(), 0x4C.toByte(), 0x67.toByte(), 0x91.toByte())
        val frag1 = byteArrayOf(0x2C.toByte(), 0xB5.toByte(), 0xE8.toByte(), 0x14.toByte(),
            0x6A.toByte(), 0x0F.toByte(), 0xD3.toByte(), 0x78.toByte())
        val frag2 = byteArrayOf(0x41.toByte(), 0x9E.toByte(), 0x0D.toByte(), 0xC6.toByte(),
            0xF2.toByte(), 0x7B.toByte(), 0x85.toByte(), 0x3A.toByte())
        val frag3 = byteArrayOf(0xD8.toByte(), 0x63.toByte(), 0x47.toByte(), 0xAC.toByte(),
            0x19.toByte(), 0xF5.toByte(), 0x2E.toByte(), 0xB0.toByte())

        // XOR deobfuscation
        val combined = ByteArray(32)
        for (i in 0 until 8) {
            combined[i]      = (frag0[i].toInt() xor 0x55).toByte()
            combined[8 + i]  = (frag1[i].toInt() xor 0xAA).toByte()
            combined[16 + i] = (frag2[i].toInt() xor 0x33).toByte()
            combined[24 + i] = (frag3[i].toInt() xor 0xCC).toByte()
        }

        // SHA-512 derivation
        val md = java.security.MessageDigest.getInstance("SHA-512")
        val hash = md.digest(combined)

        // Cross-mixing
        val key = ByteArray(32)
        for (i in 0 until 32) {
            key[i] = (hash[i].toInt() xor hash[32 + (i % 32)].toInt() xor (i * 0x1B)).toByte()
        }
        return key
    }

    /**
     * AES-256-GCM encryption using Java Cipher API.
     * Output format: nonce(12) + ciphertext + GCM tag(16)
     */
    private fun encryptAES256GCM(plaintext: ByteArray, key: ByteArray): ByteArray {
        val random = SecureRandom()
        val nonce = ByteArray(12)
        random.nextBytes(nonce)

        val secretKey: SecretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))

        val cipherText = cipher.doFinal(plaintext)

        // Combine: nonce (12) + ciphertext+tag
        val result = ByteArray(12 + cipherText.size)
        System.arraycopy(nonce, 0, result, 0, 12)
        System.arraycopy(cipherText, 0, result, 12, cipherText.size)

        return result
    }
}
