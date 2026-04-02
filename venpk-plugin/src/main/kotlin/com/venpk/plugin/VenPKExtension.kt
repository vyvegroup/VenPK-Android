package com.venpk.plugin

open class VenPKExtension {
    var sourceModule: String = "app"
    var enabled: Boolean = true
    var encryptAssets: Boolean = true
    var assetName: String = "venpk_payload.bin"
    var obfuscateNativeLibs: Boolean = true
}
