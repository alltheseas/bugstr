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
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicInteger

private const val STACK_TRACE_FILENAME = "bugstr.stack.trace"
private const val PREFS_NAME = "bugstr.cache.prefs"
private const val PREF_NEXT_SLOT = "next_slot"

/**
 * Simple helper that keeps crash reports in private app storage.
 * Defaults to one-slot storage; set [maxReports] > 1 to rotate a small queue.
 * Data is removed as soon as UI code reads it to keep state tidy across launches.
 */
class BugstrCrashReportCache(
    private val appContext: Context,
    private val fileName: String = STACK_TRACE_FILENAME,
    private val maxReports: Int = 1,
) {
    init {
        require(maxReports >= 1) { "maxReports must be at least 1" }
    }

    private val prefs by lazy {
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private val nextSlot = AtomicInteger(prefs.getInt(PREF_NEXT_SLOT, 0))

    private fun outputStream(target: String): FileOutputStream =
        appContext.openFileOutput(target, Context.MODE_PRIVATE)

    private fun deleteReport(target: String) {
        appContext.deleteFile(target)
    }

    private fun inputStreamOrNull(target: String): FileInputStream? =
        try {
            appContext.openFileInput(target)
        } catch (_: FileNotFoundException) {
            null
        }

    private fun rotateSlot(): String {
        if (maxReports == 1) return fileName
        val slot = nextSlot.getAndUpdate { (it + 1) % maxReports }
        prefs.edit().putInt(PREF_NEXT_SLOT, (slot + 1) % maxReports).apply()
        return "$fileName.$slot"
    }

    private fun resolveFile(slotKey: String?): String {
        if (slotKey != null) return "$fileName.$slotKey"
        return rotateSlot()
    }

    private fun reportFiles(): List<java.io.File> {
        val dir = appContext.filesDir ?: return emptyList()
        val matches = dir.listFiles { _, name -> name.startsWith(fileName) } ?: return emptyList()
        if (matches.isEmpty()) return emptyList()
        return matches.sortedByDescending { it.lastModified() }
    }

    /**
     * Persists the formatted stack trace for later retrieval.
     * Suspends on Dispatchers.IO to guarantee the write happens off the main thread.
     * Returns a [Result] so callers can log/propagate failures without crashing the app again.
     */
    suspend fun writeReport(report: String, slotKey: String? = null): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val target = resolveFile(slotKey)
                outputStream(target).use { stream ->
                    stream.write(report.toByteArray(Charsets.UTF_8))
                }
            }
        }

    /**
     * Returns the persisted report once and wipes it to avoid stale duplicates.
     * The file is only deleted if the read succeeds to avoid losing unreadable data.
     */
    suspend fun loadAndDelete(): Result<String?> =
        loadAllAndDelete().map { it.firstOrNull() }

    /**
     * Returns all persisted reports (newest first) and wipes them after a successful read.
     * If any read fails, nothing is deleted to avoid losing data.
     */
    suspend fun loadAllAndDelete(): Result<List<String>> =
        withContext(Dispatchers.IO) {
            runCatching {
                val files = reportFiles()
                if (files.isEmpty()) return@runCatching emptyList<String>()

                val reports =
                    files.map { file ->
                        inputStreamOrNull(file.name)?.use { inStream ->
                            InputStreamReader(inStream, Charsets.UTF_8).use { reader ->
                                reader.readText()
                            }
                        }
                    }

                if (reports.any { it == null }) error("Failed to read one or more Bugstr reports")

                files.forEach { deleteReport(it.name) }
                reports.filterNotNull()
            }
        }
}
