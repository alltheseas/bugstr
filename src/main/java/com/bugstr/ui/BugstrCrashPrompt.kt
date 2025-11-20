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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.bugstr.BugstrCrashReportCache
import com.bugstr.R
import kotlinx.coroutines.launch

// Keeps UI decisions explicit instead of juggling nullable strings.
private sealed interface CrashUiState {
    data object Loading : CrashUiState

    data object Empty : CrashUiState

    data class Ready(
        val report: String,
    ) : CrashUiState

    data class Error(
        val throwable: Throwable?,
        val pendingReport: String?,
    ) : CrashUiState
}

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
    retryButtonText: String? = null,
    loadingText: String? = null,
) {
    var state by remember { mutableStateOf<CrashUiState>(CrashUiState.Loading) }
    var loadSequence by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    fun refreshFromDisk() {
        state = CrashUiState.Loading
        loadSequence++
    }

    LaunchedEffect(cache, loadSequence) {
        val result = cache.loadAndDelete()
        state =
            result.fold(
                onSuccess = { report -> report?.let { CrashUiState.Ready(it) } ?: CrashUiState.Empty },
                onFailure = { CrashUiState.Error(it, null) },
            )
    }

    when (val current = state) {
        CrashUiState.Empty -> Unit
        CrashUiState.Loading ->
            AlertDialog(
                modifier = modifier,
                onDismissRequest = { state = CrashUiState.Empty },
                title = { Text(titleText ?: stringResource(id = R.string.bugstr_crash_report_found)) },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(loadingText ?: stringResource(id = R.string.bugstr_crash_report_loading))
                    }
                },
                confirmButton = {},
            )
        is CrashUiState.Error ->
            AlertDialog(
                modifier = modifier,
                onDismissRequest = { state = CrashUiState.Empty },
                title = { Text(stringResource(id = R.string.bugstr_crash_report_error_title)) },
                text = {
                    Text(
                        stringResource(id = R.string.bugstr_crash_report_error, current.throwable?.localizedMessage.orEmpty()),
                    )
                },
                dismissButton = {
                    TextButton(onClick = { state = CrashUiState.Empty }) {
                        Text(dismissButtonText ?: stringResource(id = R.string.bugstr_crash_report_dismiss))
                    }
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            if (current.pendingReport != null) {
                                state = CrashUiState.Ready(current.pendingReport)
                            } else {
                                refreshFromDisk()
                            }
                        },
                    ) {
                        Text(retryButtonText ?: stringResource(id = R.string.bugstr_crash_report_retry))
                    }
                },
            )
        is CrashUiState.Ready -> {
            val report = current.report
            AlertDialog(
                modifier = modifier,
                onDismissRequest = {},
                title = { Text(titleText ?: stringResource(id = R.string.bugstr_crash_report_found)) },
                text = {
                    SelectionContainer {
                        Text(descriptionText ?: stringResource(id = R.string.bugstr_crash_report_message, developerName))
                    }
                },
                dismissButton = {
                    TextButton(
                        onClick = {
                            scope.launch {
                                cache
                                    .writeReport(report)
                                    .onSuccess { state = CrashUiState.Empty }
                                    .onFailure { state = CrashUiState.Error(it, report) }
                            }
                        },
                    ) {
                        Text(dismissButtonText ?: stringResource(id = R.string.bugstr_crash_report_keep))
                    }
                },
                confirmButton = {
                    Button(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        onClick = {
                            runCatching { onSendReport(report) }
                                .onSuccess { state = CrashUiState.Empty }
                                .onFailure { throwable -> state = CrashUiState.Error(throwable, report) }
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
}
