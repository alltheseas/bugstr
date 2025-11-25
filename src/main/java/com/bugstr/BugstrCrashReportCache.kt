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
package com.bugstr

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.InputStreamReader

private const val STACK_TRACE_FILENAME = "bugstr.stack.trace"

/**
 * Simple helper that keeps the most recent crash report in private app storage.
 * Consumers may customize the backing file via [fileName] if they want a queue of reports.
 * The data is removed as soon as UI code reads it to keep state tidy across launches.
 */
class BugstrCrashReportCache(
    private val appContext: Context,
    private val fileName: String = STACK_TRACE_FILENAME,
) {
    private fun outputStream() = appContext.openFileOutput(fileName, Context.MODE_PRIVATE)

    private fun deleteReport() = appContext.deleteFile(fileName)

    private fun inputStreamOrNull(): FileInputStream? =
        try {
            appContext.openFileInput(fileName)
        } catch (_: FileNotFoundException) {
            null
        }

    /**
     * Persists the formatted stack trace for later retrieval.
     * Suspends on Dispatchers.IO to guarantee the write happens off the main thread.
     * Returns a [Result] so callers can log/propagate failures without crashing the app again.
     */
    suspend fun writeReport(report: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                outputStream().use { stream ->
                    stream.write(report.toByteArray(Charsets.UTF_8))
                }
            }
        }

    /**
     * Returns the persisted report once and wipes it to avoid stale duplicates.
     * The file is only deleted if the read succeeds to avoid losing unreadable data.
     */
    suspend fun loadAndDelete(): Result<String?> =
        withContext(Dispatchers.IO) {
            runCatching {
                val stack =
                    inputStreamOrNull()?.use { inStream ->
                        InputStreamReader(inStream, Charsets.UTF_8).use { reader ->
                            reader.readText()
                        }
                    }
                if (stack != null) {
                    runCatching { deleteReport() }
                }
                stack
            }
        }
}
