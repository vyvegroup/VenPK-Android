package com.venpk.plugin

import org.gradle.api.DefaultTask
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
        logger.lifecycle("[VenPK] Starting DEX encryption for variant: ${variantName.get()}")

        val sourceDir = findSourceDexDir()
        if (sourceDir == null) {
            logger.warn("[VenPK] Source DEX directory not found. Skipping encryption.")
            logger.warn("[VenPK] Build the '${sourceModule.get()}' module first.")
            return
        }

        val dexFiles = sourceDir.listFiles { file ->
            file.name.endsWith(".dex") && file.isFile
        }

        if (dexFiles.isNullOrEmpty()) {
            logger.warn("[VenPK] No DEX files found in $sourceDir")
            return
        }

        logger.lifecycle("[VenPK] Found ${dexFiles.size} DEX file(s) to encrypt")

        // Concatenate all dex files with size headers
        val allDex = ByteArrayOutputStream()
        for (dexFile in dexFiles.sortedBy { it.name }) {
            logger.lifecycle("[VenPK] Adding: ${dexFile.name} (${dexFile.length()} bytes)")
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

        logger.lifecycle("[VenPK] Encrypted payload written to: ${outputFile.absolutePath} (${outputFile.length()} bytes)")

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

        // Known paths where merged DEX files are output by AGP
        val possiblePaths = listOf(
            "$buildDir/intermediates/dex/$variant/mergeDex$capitalizedVariant/out",
            "$buildDir/intermediates/dex/$variant/mergeProjectDex/$variant/out",
            "$buildDir/intermediates/dex/$variant/mergeDex/out",
            "$buildDir/outputs/dex/$variant/mergeDex$capitalizedVariant/out"
        )

        for (path in possiblePaths) {
            val dir = File(path)
            if (dir.exists() && dir.isDirectory) {
                val dexFiles = dir.listFiles { f -> f.name.endsWith(".dex") }
                if (!dexFiles.isNullOrEmpty()) {
                    logger.lifecycle("[VenPK] Found DEX files at: $dir")
                    return dir
                }
            }
        }

        // Fallback: walk intermediates looking for dex directories
        val intermediatesDir = File(buildDir, "intermediates")
        if (intermediatesDir.exists()) {
            val found = intermediatesDir.walkTopDown()
                .filter { it.isDirectory && it.name == "out" }
                .firstOrNull { dir ->
                    dir.listFiles { f -> f.name.endsWith(".dex") }?.isNotEmpty() == true
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
