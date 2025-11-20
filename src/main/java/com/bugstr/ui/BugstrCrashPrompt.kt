/**
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.bugstr.ui

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Done
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.bugstr.BugstrCrashReportCache
import com.bugstr.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Composable dialog that surfaces any cached crash report and lets the user decide what to do.
 */
@Composable
fun BugstrCrashPrompt(
    cache: BugstrCrashReportCache,
    developerName: String,
    onSendReport: (String) -> Unit,
    modifier: Modifier = Modifier,
    titleText: String? = null,
    descriptionText: String? = null,
    sendButtonText: String? = null,
    dismissButtonText: String? = null,
) {
    val stackTrace = remember { mutableStateOf<String?>(null) }

    LaunchedEffect(cache) {
        stackTrace.value =
            withContext(Dispatchers.IO) {
                cache.loadAndDelete()
            }
    }

    stackTrace.value?.let { stack ->
        AlertDialog(
            modifier = modifier,
            onDismissRequest = {
                stackTrace.value = null
            },
            title = {
                Text(titleText ?: stringResource(id = R.string.bugstr_crash_report_found))
            },
            text = {
                SelectionContainer {
                    Text(descriptionText ?: stringResource(id = R.string.bugstr_crash_report_message, developerName))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        stackTrace.value = null
                    },
                ) {
                    Text(dismissButtonText ?: stringResource(id = R.string.bugstr_crash_report_dismiss))
                }
            },
            confirmButton = {
                Button(
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    onClick = {
                        onSendReport(stack)
                        stackTrace.value = null
                    },
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Outlined.Done, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(sendButtonText ?: stringResource(id = R.string.bugstr_crash_report_send))
                    }
                }
            },
        )
    }
}
