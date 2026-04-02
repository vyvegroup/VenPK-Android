package com.venpk.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(itemId: Int, onBack: () -> Unit) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    val detailData = mapOf(
        1 to DetailInfo("VenPK Runtime", "Runtime Protection Engine", listOf(
            "AES-256-GCM encryption cho toàn bộ DEX code",
            "Multi-layer key derivation với device-specific salt",
            "In-memory DEX loading qua InMemoryDexClassLoader",
            "Zero disk write: decrypted code chỉ tồn tại trong RAM",
            "Tự động dọn dẹp memory khi app进入 background",
            "Hỗ trợ multi-dex với lazy loading strategy"
        ), 0.95f),
        2 to DetailInfo("Native Crypto Engine", "C++ Cryptographic Engine", listOf(
            "AES-256-GCM authenticated encryption",
            "PBKDF2-SHA512 key derivation (100,000 iterations)",
            "HMAC-SHA256 integrity verification",
            "Constant-time comparison chống timing attack",
            "Obfuscated control flow trong native code",
            "Anti-disassembly techniques"
        ), 0.92f),
        3 to DetailInfo("In-Memory Loading", "Memory-Only Class Loading", listOf(
            "InMemoryDexClassLoader (API 26+)",
            "Không tạo temporary files trên disk",
            "Secure memory cleanup khi unload",
            "Lazy class resolution cho performance",
            "Compatible với R8 optimization",
            "Support cho cả primary và secondary DEX"
        ), 0.98f),
        4 to DetailInfo("Anti-Analysis", "Reverse Engineering Protection", listOf(
            "Debugger detection (JDWP, ptrace)",
            "Frida/Xposed framework detection",
            "Emulator detection (QEMU, BlueStacks, Nox)",
            "APK signature integrity verification",
            "Certificate pinning validation",
            "Root detection với fallback policy"
        ), 0.88f)
    )

    val info = detailData[itemId] ?: detailData[1]!!
    var switchEnabled by remember { mutableStateOf(true) }

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text(info.title, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                scrollBehavior = scrollBehavior
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
        ) {
            Text(
                info.subtitle,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            )

            Divider(modifier = Modifier.padding(horizontal = 16.dp))

            ListItem(
                headlineContent = { Text("Bảo vệ mức độ") },
                supportingContent = { Text("${(info.protectionLevel * 100).toInt()}%") },
                trailingContent = {
                    Switch(checked = switchEnabled, onCheckedChange = { switchEnabled = it })
                }
            )

            LinearProgressIndicator(
                progress = { info.protectionLevel },
                modifier = Modifier.padding(horizontal = 16.dp),
                color = MaterialTheme.colorScheme.primary,
                trackColor = MaterialTheme.colorScheme.surfaceVariant
            )

            Divider(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))

            info.features.forEachIndexed { index, feature ->
                ListItem(
                    headlineContent = { Text("Tính năng ${index + 1}") },
                    supportingContent = { Text(feature) }
                )
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

data class DetailInfo(
    val title: String,
    val subtitle: String,
    val features: List<String>,
    val protectionLevel: Float
)
