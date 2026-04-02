package com.venpk.app.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun AboutScreen(onBack: () -> Unit) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text("Giới thiệu", fontWeight = FontWeight.Bold) },
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
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            Icon(
                Icons.Filled.Shield,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                "VenPK Engine",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                "Phiên bản 1.0.0",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(24.dp))

            HorizontalDivider(modifier = Modifier.fillMaxWidth())

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                "VenPK Engine là hệ thống bảo vệ ứng dụng Android thế hệ mới, " +
                "được thiết kế với mục tiêu cung cấp mức độ bảo mật cao nhất cho mã nguồn ứng dụng. " +
                "Thay vì phụ thuộc vào các thư viện bảo vệ bên ngoài, VenPK sử dụng engine riêng " +
                "được viết hoàn toàn bằng C++ native code với AES-256-GCM encryption.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Justify,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            HorizontalDivider(modifier = Modifier.fillMaxWidth())

            Spacer(modifier = Modifier.height(16.dp))

            ListItem(
                headlineContent = { Text("Engine") },
                supportingContent = { Text("VenPK Native Crypto Engine") }
            )

            ListItem(
                headlineContent = { Text("Encryption") },
                supportingContent = { Text("AES-256-GCM + PBKDF2-SHA512") }
            )

            ListItem(
                headlineContent = { Text("Loading") },
                supportingContent = { Text("InMemoryDexClassLoader (Zero-disk)") }
            )

            ListItem(
                headlineContent = { Text("Min Android") },
                supportingContent = { Text("Android 8.0 (API 26)") }
            )

            ListItem(
                headlineContent = { Text("Target Android") },
                supportingContent = { Text("Android 14 (API 34)") }
            )

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}
