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
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
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
fun SettingsScreen(onBack: () -> Unit) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    var encryptionEnabled by remember { mutableStateOf(true) }
    var antiDebug by remember { mutableStateOf(true) }
    var selectedTheme by remember { mutableStateOf(0) }

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text("Cài đặt", fontWeight = FontWeight.Bold) },
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
                "Bảo mật",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            )

            ListItem(
                headlineContent = { Text("Mã hóa DEX") },
                supportingContent = { Text("Bật mã hóa AES-256-GCM cho DEX bytecode") },
                trailingContent = { Switch(checked = encryptionEnabled, onCheckedChange = { encryptionEnabled = it }) }
            )

            Divider(modifier = Modifier.padding(horizontal = 16.dp))

            ListItem(
                headlineContent = { Text("Chống Debug") },
                supportingContent = { Text("Phát hiện và chặn debugger, frida") },
                trailingContent = { Switch(checked = antiDebug, onCheckedChange = { antiDebug = it }) }
            )

            Divider(modifier = Modifier.padding(horizontal = 16.dp))

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                "Giao diện",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            )

            listOf("Theo hệ thống", "Sáng", "Tối").forEachIndexed { index, label ->
                ListItem(
                    headlineContent = { Text(label) },
                    leadingContent = { RadioButton(selected = selectedTheme == index, onClick = { selectedTheme = index }) }
                )
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}
