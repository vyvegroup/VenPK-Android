package com.venpk.plugin

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
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

    @get:InputDirectory
    @get:Optional
    abstract val mergedDexDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:OutputDirectory
    @get:Optional
    abstract val outputAssetsDir: DirectoryProperty

    /**
     * The master encryption key - same as in native code (venpk_crypto.cpp)
     * In production, this should be fetched from a secure source
     */
    private val masterKey: ByteArray
        get() {
            // Key fragments matching the native code
            val frag0 = byteArrayOf(0xF7.toByte(), 0xA2.toByte(), 0x1B.toByte(), 0x3E.toByte(),
                0x8D.toByte(), 0x4C.toByte(), 0x67.toByte(), 0x91.toByte())
            val frag1 = byteArrayOf(0x2C.toByte(), 0xB5.toByte(), 0xE8.toByte(), 0x14.toByte(),
                0x6A.toByte(), 0x0F.toByte(), 0xD3.toByte(), 0x78.toByte())
            val frag2 = byteArrayOf(0x41.toByte(), 0x9E.toByte(), 0x0D.toByte(), 0xC6.toByte(),
                0xF2.toByte(), 0x7B.toByte(), 0x85.toByte(), 0x3A.toByte())
            val frag3 = byteArrayOf(0xD8.toByte(), 0x63.toByte(), 0x47.toByte(), 0xAC.toByte(),
                0x19.toByte(), 0xF5.toByte(), 0x2E.toByte(), 0xB0.toByte())

            val combined = ByteArray(32)
            for (i in 0 until 8) {
                combined[i] = (frag0[i].toInt() xor 0x55).toByte()
                combined[8 + i] = (frag1[i].toInt() xor 0xAA).toByte()
                combined[16 + i] = (frag2[i].toInt() xor 0x33).toByte()
                combined[24 + i] = (frag3[i].toInt() xor 0xCC).toByte()
            }

            // SHA-512 derivation matching native code
            val md = java.security.MessageDigest.getInstance("SHA-512")
            val hash = md.digest(combined)

            val key = ByteArray(32)
            for (i in 0 until 32) {
                key[i] = (hash[i].toInt() xor hash[32 + (i % 32)].toInt() xor (i * 0x1B)).toByte()
            }
            return key
        }

    @TaskAction
    fun execute() {
        logger.lifecycle("[VenPK] Starting DEX encryption for variant: ${variantName.get()}")

        val sourceDir = findSourceDexDir()
        if (sourceDir == null) {
            logger.warn("[VenPK] Source DEX directory not found. Skipping encryption.")
            logger.warn("[VenPK] Make sure to build the '${sourceModule.get()}' module first.")
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

        // Concatenate all dex files
        val outputStream = ByteArrayOutputStream()
        for (dexFile in dexFiles.sortedBy { it.name }) {
            logger.lifecycle("[VenPK] Adding: ${dexFile.name} (${dexFile.length()} bytes)")
            FileInputStream(dexFile).use { input ->
                // Write dex size as 4-byte header
                val size = dexFile.length()
                outputStream.write((size ushr 24).toInt() and 0xFF)
                outputStream.write((size ushr 16).toInt() and 0xFF)
                outputStream.write((size ushr 8).toInt() and 0xFF)
                outputStream.write(size.toInt() and 0xFF)
                // Write dex data
                input.copyTo(outputStream)
            }
        }

        val plainDex = outputStream.toByteArray()
        logger.lifecycle("[VenPK] Combined DEX size: ${plainDex.size} bytes")

        // Encrypt
        val encrypted = encryptAES256GCM(plainDex, masterKey)
        logger.lifecycle("[VenPK] Encrypted payload size: ${encrypted.size} bytes")

        // Write encrypted payload
        val outputDirectory = outputDir.get().asFile
        outputDirectory.mkdirs()

        val outputFile = File(outputDirectory, assetName.get())
        FileOutputStream(outputFile).use { out ->
            // Write header: magic + version
            out.write("VPK1".toByteArray(Charsets.UTF_8))
            // Write encrypted data
            out.write(encrypted)
        }

        logger.lifecycle("[VenPK] Encrypted payload written to: ${outputFile.absolutePath}")

        // Also copy to assets directory if available
        if (outputAssetsDir.isPresent) {
            val assetsDir = outputAssetsDir.get().asFile
            assetsDir.mkdirs()
            val assetFile = File(assetsDir, assetName.get())
            outputFile.copyTo(assetFile, overwrite = true)
            logger.lifecycle("[VenPK] Also copied to assets: ${assetFile.absolutePath}")
        }

        // Secure cleanup
        plainDex.fill(0)
        encrypted.fill(0)
    }

    private fun findSourceDexDir(): File? {
        val sourceModuleName = sourceModule.get()
        val rootDir = project.rootDir
        val buildDir = File(rootDir, "$sourceModuleName/build")

        // Look for merged dex files in common locations
        val possiblePaths = listOf(
            "$buildDir/intermediates/dex/${variantName.get()}/mergeDex${variantName.get().replaceFirstChar { it.uppercase() }}/out",
            "$buildDir/intermediates/dex/${variantName.get()}/mergeProjectDex/${variantName.get()}/out",
            "$buildDir/intermediates/merged_native_libs/${variantName.get()}/mergeDex${variantName.get().replaceFirstChar { it.uppercase() }}/out",
            "$buildDir/outputs/dex/${variantName.get()}/mergeDex${variantName.get().replaceFirstChar { it.uppercase() }}/out"
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

        // Try merged dex in all intermediates
        val intermediatesDir = File(buildDir, "intermediates")
        if (intermediatesDir.exists()) {
            intermediatesDir.walkTopDown()
                .filter { it.isDirectory && it.name == "out" }
                .firstOrNull { dir ->
                    dir.listFiles { f -> f.name.endsWith(".dex") }?.isNotEmpty() == true
                }
                ?.let { return it }
        }

        return null
    }

    private fun encryptAES256GCM(plaintext: ByteArray, key: ByteArray): ByteArray {
        val random = SecureRandom()
        val nonce = ByteArray(12)
        random.nextBytes(nonce)

        val secretKey: SecretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))

        val encrypted = cipher.doFinal(plaintext)

        // Combine: nonce (12) + encrypted (includes 16-byte tag)
        val result = ByteArray(12 + encrypted.size)
        System.arraycopy(nonce, 0, result, 0, 12)
        System.arraycopy(encrypted, 0, result, 12, encrypted.size)

        return result
    }

    // Simple ByteArrayOutputStream for internal use
    private class ByteArrayOutputStream {
        private val buffer = mutableListOf<Byte>()

        fun write(b: Int) {
            buffer.add(b.toByte())
        }

        fun write(data: ByteArray) {
            buffer.addAll(data.toList())
        }

        fun toByteArray(): ByteArray {
            return buffer.toByteArray()
        }
    }
}
