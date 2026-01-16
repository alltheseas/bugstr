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

import android.util.Log
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Installs as the process-wide crash handler and serializes interesting crashes via Bugstr.
 */
class BugstrCrashHandler(
    private val cache: BugstrCrashReportCache,
    private val assembler: BugstrReportAssembler,
    private val delegate: Thread.UncaughtExceptionHandler? = Thread.getDefaultUncaughtExceptionHandler(),
    private val shouldStore: (Throwable) -> Boolean = { it !is OutOfMemoryError },
    private val writeTimeoutMs: Long = 1_000,
    private val attachmentsProvider: () -> Map<String, String> = { emptyMap() },
) : Thread.UncaughtExceptionHandler {
    companion object {
        private const val TAG = "BugstrCrashHandler"
    }

    override fun uncaughtException(
        t: Thread,
        e: Throwable,
    ) {
        if (!shouldStore(e)) {
            delegate?.uncaughtException(t, e)
            return
        }

        val report =
            runCatching { assembler.buildReport(e, attachmentsProvider()) }
                .getOrElse { assembler.buildReport(e) }

        val result =
            // Blocks the crashing thread just long enough to flush the stack trace to disk.
            runBlocking {
                withTimeoutOrNull(writeTimeoutMs) {
                    cache.writeReport(report).onFailure { Log.w(TAG, "Failed to persist Bugstr report", it) }
                } ?: runCatching { error("Bugstr write timed out after ${writeTimeoutMs}ms") }
            }

        result?.onFailure { Log.w(TAG, "Bugstr did not complete write before crash propagation", it) }

        delegate?.uncaughtException(t, e)
    }

    /**
     * Convenience method to register this handler as the default one.
     */
    fun installAsDefault() {
        Thread.setDefaultUncaughtExceptionHandler(this)
    }
}
